"""Loss-averse quarantine: publish a verified copy before removing a source."""

import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
import stat
import tempfile
import uuid
import zipfile

from utils.paths import QUARANTINE_DIR


_CHUNK_SIZE = 1024 * 1024
_PAYLOAD = "payload"
_METADATA = "metadata.json"


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _require_regular(info):
    if (not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise ValueError("Only regular, non-reparse files can be quarantined")


def _open_source(path):
    """Return (file, may_delete). Windows denies concurrent write/delete opens."""
    if os.name != "nt":
        # There is no portable unlink-by-open-handle. Preserve the source here.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            return os.fdopen(fd, "rb"), False
        except BaseException:
            os.close(fd)
            raise

    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                       wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    # GENERIC_READ | DELETE, FILE_SHARE_READ, OPEN_EXISTING,
    # FILE_FLAG_OPEN_REPARSE_POINT. Never follow a final-component reparse point.
    may_delete = True
    handle = create(path, 0x80000000 | 0x10000, 1, None, 3, 0x00200000, None)
    if handle == invalid:
        # Read permission alone can still preserve a verified recovery copy.
        may_delete = False
        handle = create(path, 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == invalid:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        close(handle)
        raise
    try:
        return os.fdopen(fd, "rb"), may_delete
    except BaseException:
        os.close(fd)
        raise


def _delete_open_source(source, may_delete):
    """Mark the exact locked Windows handle for deletion, never a pathname."""
    if os.name != "nt" or not may_delete:
        raise OSError("Safe handle-based deletion unavailable; source retained")
    import msvcrt
    from ctypes import wintypes

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    dispose = kernel.SetFileInformationByHandle
    dispose.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                        wintypes.DWORD)
    dispose.restype = wintypes.BOOL
    info = FileDispositionInfo(1)
    # FileDispositionInfo (3) applies to this file object, even if a parent moves.
    if not dispose(msvcrt.get_osfhandle(source.fileno()), 3,
                   ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())


def _verify_archive(path, metadata):
    with zipfile.ZipFile(path, "r") as archive:
        if archive.namelist() != [_PAYLOAD, _METADATA]:
            raise ValueError("Unexpected quarantine archive members")
        if archive.testzip() is not None:
            raise ValueError("Quarantine archive CRC validation failed")
        if json.loads(archive.read(_METADATA)) != metadata:
            raise ValueError("Quarantine metadata validation failed")
        digest = hashlib.sha256()
        size = 0
        with archive.open(_PAYLOAD) as payload:
            for chunk in iter(lambda: payload.read(_CHUNK_SIZE), b""):
                digest.update(chunk)
                size += len(chunk)
        if size != metadata["size"] or digest.hexdigest() != metadata["sha256"]:
            raise ValueError("Quarantine payload validation failed")


def quarantine(path, expected_sha256=None):
    """Return status/id/source_path/archive_path/error, not a boolean.

    An optional expected SHA-256 binds the scanned content to the locked copy.
    Existing ZIPs are never overwritten. A failed operation never deletes the
    source; once published, its archive is retained even if removal fails.
    Non-Windows platforms deliberately return copied_not_removed. On Windows,
    isolated means delete disposition was accepted and our source handle closed;
    other already-open read handles may delay final filesystem reclamation.
    """
    result = {"status": "failed", "id": uuid.uuid4().hex,
              "source_path": None, "archive_path": None, "error": None}
    temporary = None
    published = False
    try:
        if expected_sha256 is not None:
            if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
                    or any(c not in "0123456789abcdefABCDEF" for c in expected_sha256)):
                raise ValueError("expected_sha256 must be exactly 64 hexadecimal characters")
            expected_sha256 = expected_sha256.lower()
        source_path = os.path.abspath(os.fsdecode(os.fspath(path)))
        result["source_path"] = source_path
        quarantine_dir = os.path.abspath(QUARANTINE_DIR)
        # Do not consume existing recovery archives, including legacy ZIPs.
        real_source = os.path.normcase(os.path.realpath(source_path))
        real_quarantine = os.path.normcase(os.path.realpath(quarantine_dir))
        try:
            already_quarantined = os.path.commonpath([real_source, real_quarantine]) == real_quarantine
        except ValueError:  # Different Windows drives cannot contain each other.
            already_quarantined = False
        if already_quarantined:
            raise ValueError("Source is already inside the quarantine directory")
        before = os.lstat(source_path)
        _require_regular(before)
        source, may_delete = _open_source(source_path)
        with source:
            opened = os.fstat(source.fileno())
            _require_regular(opened)
            if _identity(before) != _identity(opened):
                raise OSError("Source identity changed while opening")
            os.makedirs(quarantine_dir, exist_ok=True)
            archive_path = os.path.join(quarantine_dir, result["id"] + ".zip")
            fd, temporary = tempfile.mkstemp(prefix=".quarantine-", suffix=".tmp",
                                             dir=quarantine_dir)
            try:
                output = os.fdopen(fd, "w+b")
            except BaseException:
                os.close(fd)
                raise
            digest = hashlib.sha256()
            size = 0
            with output:
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    with archive.open(_PAYLOAD, "w", force_zip64=True) as payload:
                        for chunk in iter(lambda: source.read(_CHUNK_SIZE), b""):
                            payload.write(chunk)
                            digest.update(chunk)
                            size += len(chunk)
                    if _identity(os.fstat(source.fileno())) != _identity(opened) or size != opened.st_size:
                        raise OSError("Source changed during archival")
                    if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
                        raise ValueError("Source SHA-256 no longer matches scanned content; source retained")
                    metadata = {
                        "schema_version": 1, "id": result["id"],
                        "source_path": source_path, "original_name": os.path.basename(source_path),
                        "archived_at": datetime.now(timezone.utc).isoformat(),
                        "payload": _PAYLOAD, "size": size, "sha256": digest.hexdigest(),
                        "source_identity": dict(zip(
                            ("device", "inode", "size", "mtime_ns", "ctime_ns"), _identity(opened))),
                    }
                    archive.writestr(_METADATA, json.dumps(metadata, ensure_ascii=True))
                output.flush()
                os.fsync(output.fileno())
            _verify_archive(temporary, metadata)
            # Hard-link publication is atomic and fails if the destination exists.
            # Unsupported filesystems fail closed: never fall back to overwrite.
            os.link(temporary, archive_path)
            published = True
            result["archive_path"] = archive_path
            result["status"] = "copied_not_removed"
            _verify_archive(archive_path, metadata)
            current = os.lstat(source_path)
            _require_regular(current)
            if (_identity(current) != _identity(opened)
                    or _identity(os.fstat(source.fileno())) != _identity(opened)):
                raise OSError("Source identity changed before removal; source retained")
            _delete_open_source(source, may_delete)
        result["status"] = "isolated"
    except Exception as exc:
        result["status"] = "copied_not_removed" if published else "failed"
        result["error"] = str(exc) or type(exc).__name__
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError as exc:
                # A leftover temp is preferable to losing a recovery archive.
                warning = "Temporary archive cleanup failed: " + str(exc)
                result["error"] = (result["error"] + "; " + warning
                                   if result["error"] else warning)
    return result
