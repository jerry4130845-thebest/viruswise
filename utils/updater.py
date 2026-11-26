"""Verify and replace the managed VirusWise Windows bundle; never start a process.

The caller supplies a trusted installation root and a private work directory,
verifies the downloaded package before extraction, and holds the exclusive
installation lock throughout apply/rollback. Only it decides when to discard
backups. Path checks are not a substitute for restricting write access to
those directories during the transaction.
"""
from contextlib import contextmanager
from functools import lru_cache
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile
import zlib


REPOSITORY = "jerry4130845-thebest/viruswise"
MAX_PACKAGE_BYTES = 512 * 1024**2
APP_EXE = "VirusWise.exe"
HELPER_EXE = "VirusWiseUpdater.exe"
RUNTIME_DIR = "_internal"
UPDATE_PROTOCOL = 2

_LOCK_NAME = ".viruswise-update.lock"
_DEFENSE_SERVICE = "VirusWiseActiveDefense"
_ITEMS = ((RUNTIME_DIR, "dir"), (APP_EXE, "file"))
_APP_MANIFEST = (RUNTIME_DIR, "viruswise-release.json")
_HELPER_MANIFEST = (RUNTIME_DIR, "updater-release.json")
_BASE_LIBRARY = (RUNTIME_DIR, "base_library.zip")
_REPARSE = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
_CHUNK = 256 * 1024
_SOCKET_TIMEOUT = 15
_DOWNLOAD_TIMEOUT = 600
_MAX_ENTRIES = 20_000
_MAX_CENTRAL_BYTES = 16 * 1024**2
_MAX_EXTRACTED_BYTES = 2 * 1024**3
_MAX_MANIFEST_BYTES = 4096
_RELEASE_PATH = re.compile(
    rf"/{re.escape(REPOSITORY)}/releases/download/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
)
_CDN_PATHS = {
    "release-assets.githubusercontent.com": "/github-production-release-asset/",
    "objects.githubusercontent.com": "/github-production-release-asset-2e65be/",
}
_INVALID_WIN_CHARS = frozenset('<>:"/\|?*')
_RESERVED_WIN_NAME = re.compile(r"CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³]")
_PE_MAGICS = {0x014C: 0x10B, 0x8664: 0x20B, 0xAA64: 0x20B}


class UpdateError(RuntimeError):
    """The requested update cannot safely proceed."""


def _valid_win_component(name):
    return (bool(name) and not name.endswith((".", " "))
            and not any(c in _INVALID_WIN_CHARS or ord(c) < 32 for c in name)
            and not _RESERVED_WIN_NAME.fullmatch(name.split(".", 1)[0].rstrip(" ").upper()))


def _absolute(path):
    path = Path(path)
    if path.anchor and not path.is_absolute():
        raise UpdateError(f"不允许使用不明确的更新路径：{path}")
    path = path.absolute()
    if (".." in path.parts or "\0" in str(path)
            or (os.name == "nt" and (path.anchor.startswith("\\\\")
                or any(not _valid_win_component(part) for part in path.parts[1:])))):
        raise UpdateError(f"不安全的更新路径：{path}")
    return path


def _win_function(dll, name, restype, *argtypes):
    func = getattr(dll, name)
    func.restype = restype
    func.argtypes = argtypes
    return func


@lru_cache(maxsize=1)
def _win_get_attributes():
    import ctypes as c
    from ctypes import wintypes as w
    return _win_function(c.WinDLL("kernel32", use_last_error=True),
                         "GetFileAttributesW", w.DWORD, w.LPCWSTR)


def _checked_lstat(path, kind=None):
    if os.name == "nt":
        # Some non-name-surrogate reparse tags are followed by Python's lstat.
        # Check the raw attributes first without opening the reparse target.
        import ctypes
        attrs = _win_get_attributes()(str(path))
        if attrs == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        if attrs & _REPARSE:
            raise UpdateError(f"更新路径含链接、联接点或重解析点：{path}")
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE:
        raise UpdateError(f"更新路径含链接、联接点或重解析点：{path}")
    if (kind == "file" and not stat.S_ISREG(info.st_mode)
            or kind == "dir" and not stat.S_ISDIR(info.st_mode)):
        raise UpdateError(f"更新路径类型不正确：{path}")
    return info


def safe_path(path, *, kind=None):
    """Return an absolute Path after checking every component without resolving links.

    A missing component raises FileNotFoundError. Only the leaf can have an
    optional file/dir kind; all ancestors must be ordinary directories.
    """
    if kind not in (None, "file", "dir"):
        raise ValueError("kind must be None, 'file', or 'dir'")
    path = _absolute(path)
    for ancestor in reversed(path.parents):
        _checked_lstat(ancestor, "dir")
    _checked_lstat(path, kind)
    return path


def _single_file(path):
    path = safe_path(path, kind="file")
    if _checked_lstat(path, "file").st_nlink != 1:
        raise UpdateError(f"更新文件含硬链接：{path}")
    return path


def validate_plain_tree(path):
    """Refuse reparse points, hard-linked files and special entries before moving or deleting."""
    path = safe_path(path)
    pending = [path]
    while pending:
        current = pending.pop()
        info = _checked_lstat(current)
        if stat.S_ISDIR(info.st_mode):
            pending.extend(current.iterdir())
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise UpdateError(f"更新目录含硬链接或特殊文件：{current}")
    return path


def _check_absent(path):
    safe_path(path.parent, kind="dir")
    try:
        _checked_lstat(path)
    except FileNotFoundError:
        return
    raise UpdateError(f"更新目标已存在：{path}")


def _query_defense_service():
    import ctypes as c
    from ctypes import wintypes as w

    if os.name != "nt":
        raise UpdateError("仅支持在 Windows 查询主动防御服务。")
    dll = c.WinDLL("advapi32", use_last_error=True)
    manager_open = _win_function(dll, "OpenSCManagerW", w.HANDLE, w.LPCWSTR, w.LPCWSTR, w.DWORD)
    service_open = _win_function(dll, "OpenServiceW", w.HANDLE, w.HANDLE, w.LPCWSTR, w.DWORD)
    close = _win_function(dll, "CloseServiceHandle", w.BOOL, w.HANDLE)

    class ServiceStatus(c.Structure):
        _fields_ = [(name, w.DWORD) for name in (
            "service_type", "current_state", "controls_accepted", "win32_exit_code",
            "service_exit_code", "checkpoint", "wait_hint",
        )]

    query = _win_function(dll, "QueryServiceStatus", w.BOOL, w.HANDLE, c.POINTER(ServiceStatus))
    scm = manager_open(None, None, 0x0001)  # SC_MANAGER_CONNECT only
    if not scm:
        raise c.WinError(c.get_last_error())
    try:
        service = service_open(scm, _DEFENSE_SERVICE, 0x0004)  # SERVICE_QUERY_STATUS only
        if not service:
            error = c.get_last_error()
            if error == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return None
            raise c.WinError(error)
        try:
            status = ServiceStatus()
            if not query(service, c.byref(status)):
                raise c.WinError(c.get_last_error())
            return status.current_state
        finally:
            close(service)
    finally:
        close(scm)


def ensure_service_stopped():
    """Allow updates only when the project's defense service is stopped or absent."""
    try:
        state = _query_defense_service()
    except (OSError, AttributeError) as exc:
        raise UpdateError("无法确认主动防御服务状态，更新已中止。") from exc
    if state is None or state == 1:  # SERVICE_STOPPED
        return
    if state in (2, 3, 4, 5, 6, 7):
        raise UpdateError("主动防御服务尚未完全停止，请停止该服务后重试更新。")
    raise UpdateError("主动防御服务处于未知状态，更新已中止。")


@contextmanager
def installation_lock(root, *, exclusive=False):
    """Hold a Windows share-mode lock for this installation until context exit."""
    import ctypes as c
    from ctypes import wintypes as w

    if os.name != "nt":
        raise UpdateError("安装锁仅支持 Windows。")
    lock = safe_path(root, kind="dir") / _LOCK_NAME
    kernel = c.WinDLL("kernel32", use_last_error=True)
    advapi = c.WinDLL("advapi32", use_last_error=True)

    class SecurityAttributes(c.Structure):
        _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]

    class FileInformation(c.Structure):
        _fields_ = [("attributes", w.DWORD), ("creation", w.FILETIME), ("access", w.FILETIME),
                    ("write", w.FILETIME)] + [(name, w.DWORD) for name in (
            "volume", "size_high", "size_low", "links", "index_high", "index_low",
        )]

    convert = _win_function(advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
                            w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p)
    free = _win_function(kernel, "LocalFree", c.c_void_p, c.c_void_p)
    create = _win_function(kernel, "CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD,
                           c.POINTER(SecurityAttributes), w.DWORD, w.DWORD, w.HANDLE)
    close = _win_function(kernel, "CloseHandle", w.BOOL, w.HANDLE)
    info_by_handle = _win_function(kernel, "GetFileInformationByHandle", w.BOOL,
                                   w.HANDLE, c.POINTER(FileInformation))

    descriptor = c.c_void_p()
    # Let admins, SYSTEM and the file owner lock for writes. Other
    # authenticated users can take a shared read lock but cannot write to the
    # file. OPEN_ALWAYS does not change an existing ACL.
    if not convert("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;AU)", 1, c.byref(descriptor), None):
        raise UpdateError("无法初始化安装锁权限。") from c.WinError(c.get_last_error())
    try:
        attrs = SecurityAttributes(c.sizeof(SecurityAttributes), descriptor.value, False)
        handle = create(str(lock), 0x40000000 if exclusive else 0x80000000,
                        0 if exclusive else 1, c.byref(attrs), 4,
                        0x00200000, None)  # OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT
        error = c.get_last_error()
    finally:
        free(descriptor)
    if handle == c.c_void_p(-1).value:
        if error in (32, 33):  # ERROR_SHARING_VIOLATION or ERROR_LOCK_VIOLATION
            raise UpdateError("安装目录正在使用或更新，请退出其他 VirusWise 实例后重试。")
        raise UpdateError("无法获取安装锁，请检查安装目录的访问权限。") from c.WinError(error)
    try:
        info = FileInformation()
        if not info_by_handle(handle, c.byref(info)):
            raise UpdateError("无法验证安装锁文件。") from c.WinError(c.get_last_error())
        if info.attributes & (_REPARSE | stat.FILE_ATTRIBUTE_DIRECTORY) or info.links != 1:
            raise UpdateError("安装锁文件不是单一普通文件。")
        yield
    finally:
        close(handle)


def _check_url(url, *, redirect=False):
    valid = False
    if (isinstance(url, str) and url.isascii() and not any(c.isspace() for c in url)
            and not any(c in url for c in ("\\", "#")) and not any(ord(c) < 32 for c in url)):
        try:
            parsed = urlsplit(url)
        except ValueError:
            parsed = None
        if parsed and parsed.scheme == "https":
            host = parsed.netloc.lower()  # Reject ports, userinfo and trailing dots.
            if host == "github.com":
                valid = (not parsed.query and bool(_RELEASE_PATH.fullmatch(parsed.path))
                         and not any(part in (".", "..") for part in parsed.path.split("/")))
            elif redirect and host in _CDN_PATHS:
                valid = parsed.path.startswith(_CDN_PATHS[host])
    if not valid:
        raise UpdateError("更新下载地址不属于允许的 GitHub 仓库或资产 CDN。")


class _AssetRedirect(HTTPRedirectHandler):
    max_redirections = 4
    max_repeats = 1

    def http_error_302(self, req, fp, code, msg, headers):
        # urllib normally drains the entire redirect body before following it.
        # The body is irrelevant; close this connection without reading it.
        fp.close()
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl, redirect=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _expected_package(size, sha256):
    if type(size) is not int or not 0 < size <= MAX_PACKAGE_BYTES:
        raise UpdateError("更新包大小声明无效或超过上限。")
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise UpdateError("更新包 SHA-256 声明无效。")
    return sha256.lower()


def _check_digest(received, digest, size, expected):
    if received != size:
        raise UpdateError("更新包大小与声明不符。")
    if digest.hexdigest() != expected:
        raise UpdateError("更新包 SHA-256 校验失败。")


def download_package(url, size, sha256, dest, *, cancel, progress):
    """Stream to a new sibling .part; publish only after verifying byte count and SHA-256."""
    expected = _expected_package(size, sha256)
    _check_url(url)
    dest = _absolute(dest)
    part = dest.with_name(dest.name + ".part")
    _check_absent(dest)
    created = False
    deadline = time.monotonic() + _DOWNLOAD_TIMEOUT

    def check_running():
        if cancel.is_set():
            raise UpdateError("更新下载已取消。")
        if time.monotonic() >= deadline:
            raise UpdateError("更新包下载超时，请稍后重试。")

    try:
        check_running()
        with part.open("xb") as output:
            created = True
            req = Request(url, headers={"User-Agent": "VirusWiseUpdater", "Accept-Encoding": "identity"})
            with build_opener(_AssetRedirect()).open(req, timeout=_SOCKET_TIMEOUT) as response:
                _check_url(response.geturl(), redirect=True)
                if response.getcode() != 200:
                    raise UpdateError("GitHub 未返回完整更新包。")
                length = response.headers.get("Content-Length")
                if (length is not None and (not re.fullmatch(r"[0-9]{1,12}", length)
                                             or int(length) != size)):
                    raise UpdateError("更新包 HTTP 长度与声明不符。")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise UpdateError("更新包 HTTP 内容编码不受支持。")
                digest = hashlib.sha256()
                received = 0
                progress(received, size)
                read = getattr(response, "read1", response.read)
                while True:
                    check_running()
                    data = read(min(_CHUNK, size - received + 1))
                    if not data:
                        break
                    received += len(data)
                    if received > size:
                        raise UpdateError("更新包下载超过声明大小。")
                    output.write(data)
                    digest.update(data)
                    progress(received, size)
                _check_digest(received, digest, size, expected)
        check_running()
        _rename_new(part, dest)
        created = False
    except TimeoutError as exc:
        raise UpdateError("更新包下载超时，请稍后重试。") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise UpdateError("无法下载或保存更新包，请检查网络和目录权限。") from exc
    finally:
        if created:
            try:
                _single_file(part).unlink()
            except FileNotFoundError:
                pass


def _verify_package_stream(package, size, expected):
    if os.fstat(package.fileno()).st_size != size:
        raise UpdateError("更新包大小与声明不符。")
    received = 0
    digest = hashlib.sha256()
    while data := package.read(min(_CHUNK, size - received + 1)):
        received += len(data)
        if received > size:
            raise UpdateError("更新包超过声明大小。")
        digest.update(data)
    _check_digest(received, digest, size, expected)


def verify_package(path, size, sha256):
    """Verify a local package using the expected byte count and SHA-256."""
    expected = _expected_package(size, sha256)
    with _single_file(path).open("rb") as package:
        _verify_package_stream(package, size, expected)


def _bounded_zip_directory(package):
    # Cap the central directory before ZipFile allocates and parses it. This
    # protocol needs neither ZIP64 end records nor split/self-extracting ZIPs.
    size = os.fstat(package.fileno()).st_size
    if not 22 <= size <= MAX_PACKAGE_BYTES:
        raise UpdateError("更新包 ZIP 大小无效或超过上限。")
    start = max(0, size - (65535 + 22 + 20))
    package.seek(start)
    tail = package.read()
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise UpdateError("更新包缺少有效的 ZIP 中央目录。")
    disk, central_disk, on_disk, count, length, position, comment = struct.unpack_from("<4H2IH", tail, offset + 4)
    if (disk or central_disk or count != on_disk or not 0 < count <= _MAX_ENTRIES
            or not 0 < length <= _MAX_CENTRAL_BYTES or position + length != start + offset
            or comment != len(tail) - offset - 22
            or (offset >= 20 and tail[offset - 20:offset - 16] == b"PK\x06\x07")):
        raise UpdateError("更新包 ZIP 中央目录不受支持或超过限制。")
    package.seek(position)
    end = position + length
    for _ in range(count):
        if package.tell() + 46 > end:
            raise UpdateError("更新包 ZIP 中央目录长度无效。")
        header = package.read(46)
        if header[:4] != b"PK\x01\x02":
            raise UpdateError("更新包 ZIP 中央目录条目无效。")
        name, extra, comment, disk = struct.unpack_from("<4H", header, 28)
        if not name or disk or package.tell() + name + extra + comment > end:
            raise UpdateError("更新包 ZIP 中央目录条目长度无效。")
        package.seek(name + extra + comment, os.SEEK_CUR)
    if package.tell() != end:
        raise UpdateError("更新包 ZIP 中央目录条目数量无效。")
    return count


def _zip_member(info, executable):
    name = info.orig_filename  # filename alone may silently truncate at NUL.
    directory = name.endswith("/")
    parts = tuple((name[:-1] if directory else name).split("/"))
    if (len(parts) > 32 or len(name.encode("utf-16-le")) > 480
            or any(not _valid_win_component(part) for part in parts)):
        raise UpdateError(f"更新包内含不安全的 Windows 路径：{name!r}")
    root = parts[0]
    if root != RUNTIME_DIR and not (root == executable and len(parts) == 1 and not directory):
        raise UpdateError(f"更新包内含非托管路径：{name!r}")
    if root == RUNTIME_DIR and len(parts) == 1 and not directory:
        raise UpdateError("更新包运行时必须是目录。")
    if (executable == APP_EXE and root == RUNTIME_DIR and len(parts) > 1
            and parts[1].upper().casefold() == "updater-runtime"):
        raise UpdateError(f"主程序更新包禁止包含更新器运行时：{name!r}")
    mode = stat.S_IFMT(info.external_attr >> 16)
    if (mode not in (0, stat.S_IFDIR if directory else stat.S_IFREG)
            or info.external_attr & (_REPARSE | (0 if directory else stat.FILE_ATTRIBUTE_DIRECTORY))):
        raise UpdateError(f"更新包内含链接或特殊条目：{name!r}")
    extra = info.extra
    while extra:
        if len(extra) < 4:
            raise UpdateError("更新包 ZIP 扩展字段格式无效。")
        tag, length = struct.unpack_from("<HH", extra)
        if len(extra) < 4 + length or tag in (0x000D, 0x756E):  # Unix metadata can encode links.
            raise UpdateError("更新包 ZIP 扩展字段不受支持。")
        extra = extra[4 + length:]
    if (info.flag_bits & ~0x80E or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            or (directory and info.file_size != 0)
            or not 0 <= info.file_size <= MAX_PACKAGE_BYTES
            or not 0 <= info.compress_size <= MAX_PACKAGE_BYTES
            or info.file_size > max(1024**2, 250 * info.compress_size)):
        raise UpdateError(f"更新包条目大小或压缩方式不受支持：{name!r}")
    return parts, directory


def _plan_zip(archive, count, executable, manifest):
    infos = archive.infolist()
    if len(infos) != count:
        raise UpdateError("更新包 ZIP 条目计数无效。")
    paths = {}  # Case-insensitive Windows names, including implicit ancestors.
    files = {}
    seen = set()
    total = 0
    for info in infos:
        parts, directory = _zip_member(info, executable)
        key = tuple(part.upper().casefold() for part in parts)
        if key in seen:
            raise UpdateError(f"更新包内含重复路径：{info.orig_filename!r}")
        seen.add(key)
        for depth in range(1, len(parts) + 1):
            entry = (parts[:depth], depth < len(parts) or directory)
            if paths.setdefault(key[:depth], entry) != entry:
                raise UpdateError(f"更新包内含冲突路径：{info.orig_filename!r}")
        total += info.file_size
        if total > _MAX_EXTRACTED_BYTES:
            raise UpdateError("更新包解压后超过大小上限。")
        if not directory:
            files[parts] = info
    for required in ((executable,), _BASE_LIBRARY, manifest):
        if required not in files or files[required].file_size == 0:
            raise UpdateError(f"更新包缺少必要文件：{'/'.join(required)}")
    return sorted((parts for parts, is_dir in paths.values() if is_dir), key=len), files


def _manifest_pairs(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise UpdateError("更新包清单包含重复字段。")
    return result


def _verify_manifest(archive, info, expected):
    if info.file_size > _MAX_MANIFEST_BYTES:
        raise UpdateError("更新包清单大小无效。")
    data = json.loads(archive.read(info).decode("utf-8-sig"), object_pairs_hook=_manifest_pairs)
    if (not isinstance(data, dict) or data != expected
            or type(data["protocol"]) is not int):
        raise UpdateError("更新包清单版本或安装协议不匹配。")


def _pe_machine(path):
    with path.open("rb") as file:
        dos = file.read(64)
        if len(dos) == 64 and dos[:2] == b"MZ":
            offset = struct.unpack_from("<I", dos, 60)[0]
            size = os.fstat(file.fileno()).st_size
            if 64 <= offset <= size - 26:
                file.seek(offset)
                header = file.read(26)
                machine = struct.unpack_from("<H", header, 4)[0]
                options_size, flags, magic = struct.unpack_from("<HHH", header, 20)
                if (header[:4] == b"PE\0\0" and 2 <= options_size <= size - offset - 24
                        and flags & 0x0002 and not flags & 0x2000 and _PE_MAGICS.get(machine) == magic):
                    return machine
    raise UpdateError(f"更新文件不是受支持的 Windows PE 可执行文件：{path.name}")


def _app_manifest(version):
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise UpdateError("更新包版本格式无效。")
    return {"version": version, "protocol": UPDATE_PROTOCOL}


@contextmanager
def _checked_zip(package, executable, manifest, expected):
    try:
        count = _bounded_zip_directory(package)
        with zipfile.ZipFile(package) as archive:
            directories, files = _plan_zip(archive, count, executable, manifest)
            _verify_manifest(archive, files[manifest], expected)
            yield archive, directories, files
    except (zipfile.BadZipFile, ValueError, EOFError, NotImplementedError,
            struct.error, zlib.error, RecursionError) as exc:
        raise UpdateError("更新包 ZIP 或清单格式无效。") from exc


def validate_package(path, *, version):
    """Check the app ZIP metadata and manifest without extracting payloads or verifying SHA-256."""
    expected = _app_manifest(version)
    with _single_file(path).open("rb") as package:
        with _checked_zip(package, APP_EXE, _APP_MANIFEST, expected):
            pass


def _extract_zip(package, stage, executable, manifest, expected):
    stage = _absolute(stage)
    _check_absent(stage)
    created = finished = False
    try:
        with _checked_zip(package, executable, manifest, expected) as (archive, directories, files):
            stage.mkdir()
            created = True
            # Each destination is created exactly once, without exist_ok.
            # Windows 8.3 aliases cannot silently satisfy a second mkdir.
            for parts in directories:
                stage.joinpath(*parts).mkdir()
            for parts, info in files.items():
                with archive.open(info) as src, stage.joinpath(*parts).open("xb") as dst:
                    remaining = info.file_size
                    while data := src.read(min(_CHUNK, remaining + 1)):
                        remaining -= len(data)
                        if remaining < 0:
                            raise UpdateError("更新包解压超过声明大小。")
                        dst.write(data)
                    if remaining != 0:
                        raise UpdateError("更新包解压大小与声明不符。")
            machine = _pe_machine(stage / executable)
            if os.name == "nt" and _pe_machine(Path(sys.executable)) != machine:
                raise UpdateError(f"{executable} 的架构与当前程序不匹配。")
        finished = True
    finally:
        if created and not finished:
            shutil.rmtree(validate_plain_tree(stage))


def extract_package(path, stage, *, version):
    """Extract a previously hash-verified app ZIP to a new private stage."""
    expected = _app_manifest(version)
    with _single_file(path).open("rb") as package:
        _extract_zip(package, stage, APP_EXE, _APP_MANIFEST, expected)


def extract_helper_package(path, stage, *, size, sha256):
    """Hash-verify the standalone updater ZIP and extract it without reopening the source path."""
    expected = _expected_package(size, sha256)
    with _single_file(path).open("rb") as package:
        _verify_package_stream(package, size, expected)
        _extract_zip(package, stage, HELPER_EXE, _HELPER_MANIFEST, {"protocol": UPDATE_PROTOCOL})


def _transaction_paths(root, stage, backup):
    # Resolve only after the no-reparse walk, so short names cannot alias a
    # protected component or disguise overlapping transaction directories.
    root, stage, backup = (safe_path(p, kind="dir").resolve(strict=True) for p in (root, stage, backup))
    runtime = root / RUNTIME_DIR
    if (root.is_relative_to(stage) or root.is_relative_to(backup)
            or stage.is_relative_to(backup) or backup.is_relative_to(stage)
            or stage.is_relative_to(runtime) or backup.is_relative_to(runtime)):
        raise UpdateError("安装目录、暂存和备份目录相互重叠。")
    if len({_checked_lstat(p, "dir").st_dev for p in (root, stage, backup)}) != 1:
        raise UpdateError("安装、暂存和备份目录必须在同一卷。")
    return root, stage, backup


def _managed_item(parent, name, kind, *, optional=False):
    path = parent / name
    try:
        safe_path(path, kind=kind)
    except FileNotFoundError:
        if optional:
            return None
        raise
    return validate_plain_tree(path) if kind == "dir" else _single_file(path)


def _rename_new(source, target):
    _check_absent(target)
    # os.rename is no-overwrite on Windows, and never falls back to copying
    # across volumes. The parent directories are trusted and locked by caller.
    source.rename(target)


def apply_package(root, stage, backup):
    """Move originals to a pre-created empty backup, then publish the staged bundle."""
    root, stage, backup = _transaction_paths(root, stage, backup)
    if any(backup.iterdir()):
        raise UpdateError("更新备份目录必须为空。")
    for name, kind in _ITEMS:
        _managed_item(root, name, kind)
        _managed_item(stage, name, kind)
    # Unpublish the launcher first. Windows refuses this rename while the old
    # image is in use (including by a startup yet to acquire its shared lock).
    _rename_new(root / APP_EXE, backup / APP_EXE)
    _rename_new(root / RUNTIME_DIR, backup / RUNTIME_DIR)
    _rename_new(stage / RUNTIME_DIR, root / RUNTIME_DIR)
    _rename_new(stage / APP_EXE, root / APP_EXE)


def rollback_package(root, stage, backup):
    """Restore each backed up item under the lock, without deleting any directory."""
    root, stage, backup = _transaction_paths(root, stage, backup)
    saved = {}
    active = {}
    for name, kind in _ITEMS:
        old = _managed_item(backup, name, kind, optional=True)
        if old is None:
            continue  # This item was untouched or already restored.
        current = _managed_item(root, name, kind, optional=True)
        staged = _managed_item(stage, name, kind, optional=True)
        if current is not None and staged is not None:
            raise UpdateError(f"更新回滚发现不一致的暂存状态：{name}")
        saved[name], active[name] = old, current
    if RUNTIME_DIR in saved and APP_EXE not in saved:
        raise UpdateError("更新回滚缺少原启动程序备份。")
    if active.get(APP_EXE) is not None:
        _rename_new(active[APP_EXE], stage / APP_EXE)
    if RUNTIME_DIR in saved:
        if active[RUNTIME_DIR] is not None:
            _rename_new(active[RUNTIME_DIR], stage / RUNTIME_DIR)
        _rename_new(saved[RUNTIME_DIR], root / RUNTIME_DIR)
    if APP_EXE in saved:
        _rename_new(saved[APP_EXE], root / APP_EXE)
