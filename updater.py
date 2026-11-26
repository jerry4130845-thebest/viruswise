"""VirusWise update handoff. The onedir application imports this without I/O."""
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from uuid import uuid4

from utils.updater import (
    APP_EXE, HELPER_EXE, RUNTIME_DIR, MAX_PACKAGE_BYTES, REPOSITORY, UPDATE_PROTOCOL, UpdateError,
    apply_package, download_package, ensure_service_stopped, extract_helper_package, extract_package,
    installation_lock, rollback_package, safe_path, validate_package, validate_plain_tree, verify_package,
)

PREFIX = "VirusWise-update-"
PENDING = ".viruswise-update.pending"
HELPER_DIR = "runner"
HELPER_ZIP = "updater.zip"
HELPER_URL = f"https://github.com/{REPOSITORY}/releases/download/updater/{HELPER_ZIP}"
HELPER_PIN = "viruswise-updater-pin.json"
TOKEN = re.compile(r"[0-9a-f]{32}")
VERSION = re.compile(r"[0-9]{1,12}(?:\.[0-9]{1,12}){2}")
ACK_TIMEOUT = 60


def _base():
    from win32com.shell import shell, shellcon
    location = shell.SHGetFolderPath(0, shellcon.CSIDL_PROGRAM_FILES, None, 0)
    return safe_path(Path(location), kind="dir")


def _admin():
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def _work_path(token):
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise UpdateError("更新事务编号无效。")
    return _base() / (PREFIX + token)


def _stage_root(root, token):
    return root / (".viruswise-update-" + token)


def _private_mkdir(path, *, runtime=False):
    import pywintypes
    import win32file
    import win32security

    # Admin and SYSTEM own the transaction. Only the installed runtime needs
    # read/execute permissions for unprivileged CLI users after its rename.
    sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    if runtime:
        sddl += "(A;OICI;GRGX;;;AU)"
    attrs = pywintypes.SECURITY_ATTRIBUTES()
    attrs.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    win32file.CreateDirectory(str(path), attrs)


def _trusted_work(work):
    import win32security as security

    work = safe_path(work, kind="dir")
    descriptor = security.GetFileSecurity(
        str(work), security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
    admin = security.ConvertStringSidToSid("S-1-5-32-544")
    system = security.ConvertStringSidToSid("S-1-5-18")
    acl = descriptor.GetSecurityDescriptorDacl()
    if (descriptor.GetSecurityDescriptorOwner() not in (admin, system)
            or acl is None or acl.GetAceCount() != 2):
        raise UpdateError("更新事务目录权限不可信。")
    trustees = set()
    for index in range(acl.GetAceCount()):
        (kind, flags), mask, sid = acl.GetAce(index)
        if kind != 0 or flags != 3 or mask != 0x1F01FF or sid not in (admin, system):
            raise UpdateError("更新事务目录权限不可信。")
        trustees.add(security.ConvertSidToStringSid(sid))
    if len(trustees) != 2 or not descriptor.GetSecurityDescriptorControl()[0] & 0x1000:
        raise UpdateError("更新事务目录权限不可信。")
    return work


def _read(path):
    try:
        with safe_path(path, kind="file").open("rb") as stream:
            data = stream.read(8193)
    except FileNotFoundError:
        return None
    if len(data) > 8192:
        raise UpdateError("更新事务数据过长。")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise UpdateError("更新事务数据无效。")
    return value


def _write(path, value, *, replace=False):
    tmp = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        with tmp.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        (os.replace if replace else os.rename)(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _remove_tree(path):
    try:
        validate_plain_tree(path)
    except FileNotFoundError:
        return
    shutil.rmtree(path)


def _same_path(a, b):
    return os.path.normcase(os.fspath(a)) == os.path.normcase(os.fspath(b))


def _install_root():
    if os.name != "nt" or not getattr(sys, "frozen", False):
        raise UpdateError("自动更新仅支持 Windows 打包版。")
    exe = safe_path(Path(sys.executable), kind="file")
    if exe.name.casefold() != APP_EXE.casefold():
        raise UpdateError("当前 EXE 名称不符合自动更新要求。")
    return exe.parent


def _helper_pin(root):
    meta = _read(root / RUNTIME_DIR / HELPER_PIN)
    if (not meta or meta.keys() != {"size", "sha256"}
            or type(meta["size"]) is not int or not 0 < meta["size"] <= MAX_PACKAGE_BYTES
            or not isinstance(meta["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", meta["sha256"])):
        raise UpdateError("当前安装缺少可信的更新器校验信息。")
    return meta["size"], meta["sha256"]


def can_auto_update():
    try:
        root = _install_root()
        _helper_pin(root)
        return _same_path(safe_path(root / RUNTIME_DIR, kind="dir"), Path(sys._MEIPASS))
    except (OSError, AttributeError, ValueError, UpdateError):
        return False


def _clean_launch_env():
    env = os.environ.copy()
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def _launch(exe, args, *, cwd, hidden=False):
    env = _clean_launch_env()
    set_dir = ctypes.windll.kernel32.SetDllDirectoryW
    if not set_dir(None):
        raise ctypes.WinError()
    try:
        flags = subprocess.CREATE_NO_WINDOW if hidden else subprocess.CREATE_NEW_PROCESS_GROUP
        return subprocess.Popen([str(exe), *args], cwd=str(cwd), env=env, creationflags=flags)
    finally:
        set_dir(getattr(sys, "_MEIPASS", None))


@contextmanager
def _open_process(pid, *, expected_image=None, expected_started=None):
    import win32api
    import win32con
    import win32process

    if type(pid) is not int or pid <= 0:
        raise UpdateError("更新进程身份无效。")
    # QueryFullProcessImageName permits a limited query handle and yields the
    # executable path even when the job working directory differs.
    handle = win32api.OpenProcess(win32con.SYNCHRONIZE | 0x1000, False, pid)
    try:
        if expected_image is not None:
            buf = ctypes.create_unicode_buffer(32768)
            length = ctypes.c_ulong(len(buf))
            query = ctypes.windll.kernel32.QueryFullProcessImageNameW
            query.argtypes = (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p,
                              ctypes.POINTER(ctypes.c_ulong))
            if not query(int(handle), 0, buf, ctypes.byref(length)):
                raise ctypes.WinError()
            if not _same_path(safe_path(Path(buf.value), kind="file"), expected_image):
                raise UpdateError("更新父进程不是该安装目录的 VirusWise。")
        if expected_started is not None and _started(handle) != expected_started:
            raise UpdateError("更新父进程已更换，取消更新。")
        yield handle
    finally:
        handle.Close()


def _started(handle):
    # Use the raw FILETIME, not a rounded timestamp or a recyclable PID alone.
    import ctypes.wintypes as wt
    times = [wt.FILETIME() for _ in range(4)]
    fn = ctypes.windll.kernel32.GetProcessTimes
    fn.argtypes = (ctypes.c_void_p,) + (ctypes.POINTER(wt.FILETIME),) * 4
    if not fn(int(handle), *(ctypes.byref(t) for t in times)):
        raise ctypes.WinError()
    return times[0].dwHighDateTime << 32 | times[0].dwLowDateTime


def _exited(handle, milliseconds=0):
    import win32event
    result = win32event.WaitForSingleObject(handle, milliseconds)
    if result == win32event.WAIT_OBJECT_0:
        return True
    if result == win32event.WAIT_TIMEOUT:
        return False
    raise UpdateError("无法确认旧程序已退出。")


class _Session:
    def __init__(self, work, process, cancelled):
        self.work = work
        self.process = process
        self.cancelled = cancelled

    def commit(self):
        if self.cancelled.is_set() or self.process.poll() is not None:
            raise UpdateError("更新已取消或安装程序已经退出。")
        _write(self.work / "decision.json", {"install": True})

    def cancel(self):
        self.cancelled.set()
        try:
            _write(self.work / "decision.json", {"install": False})
        except OSError:
            pass  # Another decision already exists or helper already left.


def prepare_update(*, version, url, size, sha256, cancel, progress):
    if not can_auto_update() or not _admin():
        raise UpdateError("当前安装不支持自动更新，请手动获取新版。")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise UpdateError("待安装版本无效。")
    root = _install_root()
    ensure_service_stopped()
    if _read(root / PENDING) is not None:
        raise UpdateError("有未完成的更新，请先处理该事务。")
    token = uuid4().hex
    work = _work_path(token)
    if work.is_relative_to(root) or root.is_relative_to(work):
        raise UpdateError("不能在安装目录内运行独立更新程序。")
    _private_mkdir(work)
    session = None
    process = None
    try:
        helper_size, helper_sha256 = _helper_pin(root)
        total = size + helper_size
        package = work / "package.zip"
        download_package(url, size, sha256, package, cancel=cancel,
                         progress=lambda received, _: progress(received, total))
        validate_package(package, version=version)
        helper_zip = work / HELPER_ZIP
        runner = work / HELPER_DIR
        try:
            download_package(HELPER_URL, helper_size, helper_sha256, helper_zip, cancel=cancel,
                             progress=lambda received, _: progress(size + received, total))
            extract_helper_package(helper_zip, runner, size=helper_size, sha256=helper_sha256)
            helper_zip.unlink()
        except (OSError, UpdateError) as exc:
            raise UpdateError(f"无法准备 GitHub 更新器：{exc}") from exc
        if cancel.is_set():
            raise UpdateError("更新已取消。")
        helper = safe_path(runner / HELPER_EXE, kind="file")
        with _open_process(os.getpid()) as parent:
            _write(work / "request.json", {"root": str(root), "version": version, "size": size,
                                          "sha256": sha256, "parent": os.getpid(),
                                          "parent_started": _started(parent), "protocol": UPDATE_PROTOCOL})
        process = _launch(helper, ["--apply", token], cwd=runner, hidden=True)
        session = _Session(work, process, cancel)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not cancel.is_set():
            failed = _read(work / "error.json")
            if failed:
                raise UpdateError(failed.get("message", "安装程序无法准备更新。"))
            if process.poll() is not None:
                break
            if _read(work / "ready.json") == {"ready": True}:
                return session
            cancel.wait(0.1)
        failed = _read(work / "error.json")
        if failed:
            raise UpdateError(failed.get("message", "安装程序无法准备更新。"))
        raise UpdateError("更新已取消。" if cancel.is_set() else "安装程序未能就绪，旧版未关闭。")
    except Exception:
        if session is not None:
            session.cancel()
        if process is not None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass  # helper is still alive; leave the transaction intact
        if process is None or process.poll() is not None:
            try:
                _remove_tree(work)
            except (OSError, UpdateError):
                pass
        raise


def _request(work):
    work = _trusted_work(work)
    req = _read(work / "request.json")
    if (not req or type(req.get("protocol")) is not int or req["protocol"] != UPDATE_PROTOCOL
            or not isinstance(req.get("root"), str) or not Path(req["root"]).is_absolute()
            or not isinstance(req.get("version"), str) or not VERSION.fullmatch(req["version"])
            or type(req.get("size")) is not int or not 0 < req["size"] <= MAX_PACKAGE_BYTES
            or not isinstance(req.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", req["sha256"])):
        raise UpdateError("安装请求无效。")
    root = safe_path(Path(req["root"]), kind="dir")
    if work.is_relative_to(root) or root.is_relative_to(work):
        raise UpdateError("安装目录和更新器目录不得重叠。")
    return req, root


def _set_phase(work, phase):
    _write(work / "phase.json", {"phase": phase}, replace=True)


def _phase(work):
    return (_read(work / "phase.json") or {}).get("phase")


def _record_error(work, exc, rollback_error=None):
    details = {"message": str(exc)}
    if rollback_error is not None:
        details["rollback"] = str(rollback_error)
    try:
        _write(work / "error.json", details, replace=True)
    except OSError:
        pass  # An unavailable log must not prevent rollback.


def _release_gate(root, token):
    if _read(root / PENDING) != {"token": token}:
        raise UpdateError("安装保护标记已改变，拒绝清理。")
    (root / PENDING).unlink()


def _cleanup_files(work, stage_root):
    try:
        _remove_tree(stage_root)
        (work / "package.zip").unlink(missing_ok=True)
    except (OSError, UpdateError):
        return  # eligible for a subsequent startup cleanup retry


def _notice(message):
    ctypes.windll.user32.MessageBoxW(None, str(message), "VirusWise 更新", 0x10)


def _accept_ack(work, candidate, version):
    return _read(work / "ack.json") == {"pid": candidate.pid, "version": version}


def _apply_after_exit(work, root, token, req):
    stage_root = _stage_root(root, token)
    stage, backup = stage_root / "stage", stage_root / "backup"
    exe = root / APP_EXE
    candidate = None
    phase = None
    own_stage = False
    try:
        with installation_lock(root, exclusive=True):
            ensure_service_stopped()
            if _read(root / PENDING) is not None:
                raise UpdateError("另一个更新正在运行或等待恢复。")
            _private_mkdir(stage_root, runtime=True)
            own_stage = True
            extract_package(work / "package.zip", stage, version=req["version"])
            _private_mkdir(backup)
            ensure_service_stopped()
            # The journal is durable before the gate/first program file rename.
            _set_phase(work, "applying")
            _write(root / PENDING, {"token": token})
            phase = "applying"
            apply_package(root, stage, backup)
        candidate = _launch(safe_path(exe, kind="file"), ["--post-update", token], cwd=root)
        _write(work / "candidate.json", {"pid": candidate.pid})
        deadline = time.monotonic() + ACK_TIMEOUT
        while time.monotonic() < deadline and candidate.poll() is None:
            if _accept_ack(work, candidate, req["version"]):
                break
            time.sleep(0.1)
        if candidate.poll() is not None or not _accept_ack(work, candidate, req["version"]):
            raise UpdateError("新版未在限时内确认启动。")
        # Never rollback after the durable success record, even if the cleanup
        # or gate release fails. Recovery only removes the gate in that case.
        _set_phase(work, "confirmed")
        phase = "confirmed"
        _release_gate(root, token)
    except Exception as exc:
        _record_error(work, exc)
        if phase == "confirmed":
            _notice(f"新版已启动，但更新收尾未完成。请保留事务目录：\n{work}")
            return 1
        try:
            if candidate is not None and candidate.poll() is None:
                # This is exactly the unconfirmed child we created, not an
                # unrelated app instance or the SCM service.
                candidate.terminate()
                candidate.wait(timeout=10)
            if phase == "applying":
                with installation_lock(root, exclusive=True):
                    ensure_service_stopped()
                    if _read(root / PENDING) != {"token": token}:
                        raise UpdateError("事务不再拥有安装门禁。")
                    rollback_package(root, stage, backup)
                    _set_phase(work, "rolled_back")
                    _release_gate(root, token)
        except Exception as rollback_error:
            _record_error(work, exc, rollback_error)
            _notice(f"更新未完成，无法确认回滚。请保留备份和日志：\n{work}\n{stage_root}\n\n{rollback_error}")
            return 1
        if own_stage:
            _cleanup_files(work, stage_root)
        else:
            (work / "package.zip").unlink(missing_ok=True)
        _notice(f"更新未完成，原程序未改变或已恢复。\n{exc}\n\n日志：{work / 'error.json'}")
        try:
            if _read(root / PENDING) is None:
                _launch(safe_path(exe, kind="file"), [], cwd=root)
        except (OSError, UpdateError) as launch_error:
            _notice(f"请手动打开 VirusWise：{launch_error}")
        return 1
    _cleanup_files(work, stage_root)
    return 0


def _apply(work, root, token, req):
    with _open_process(req["parent"], expected_image=root / APP_EXE,
                       expected_started=req.get("parent_started")) as parent:
        ensure_service_stopped()
        verify_package(work / "package.zip", req["size"], req["sha256"])
        validate_package(work / "package.zip", version=req["version"])
        _write(work / "ready.json", {"ready": True})
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            decision = _read(work / "decision.json")
            if decision is not None or _exited(parent, 100):
                break
        # Check once more after exit to avoid losing a decision written just
        # before the waited process became signalled.
        if _read(work / "decision.json") != {"install": True}:
            _set_phase(work, "cancelled")
            (work / "package.zip").unlink(missing_ok=True)
            return 1
        if not _exited(parent, 120000):
            _notice("旧程序没有退出，未覆盖任何文件。")
            _set_phase(work, "cancelled")
            (work / "package.zip").unlink(missing_ok=True)
            return 1
    return _apply_after_exit(work, root, token, req)


def _recover(work, root, token):
    # Manual, elevated recovery via the surviving external copy.
    # No just-created candidate or other instance may be running.
    stage_root = _stage_root(root, token)
    with installation_lock(root, exclusive=True):
        ensure_service_stopped()
        if _read(root / PENDING) != {"token": token}:
            raise UpdateError("此事务未占用安装门禁，不需要恢复。")
        phase = _phase(work)
        if phase == "applying":
            rollback_package(root, stage_root / "stage", stage_root / "backup")
            _set_phase(work, "rolled_back")
        elif phase not in ("confirmed", "rolled_back"):
            raise UpdateError("无法识别事务阶段，请保留备份。")
        _release_gate(root, token)
    _cleanup_files(work, stage_root)
    _launch(safe_path(root / APP_EXE, kind="file"), [], cwd=root)
    return 0


@contextmanager
def application_gate(token=None):
    """Hold a shared install lease while any packaged mode is running."""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        if token is not None:
            raise UpdateError("源码模式不接受更新确认参数。")
        yield None
        return
    root = Path(sys.executable).parent
    with installation_lock(root):
        pending = _read(root / PENDING)
        if token is None:
            if pending is not None:
                work = _work_path(pending.get("token"))
                raise UpdateError(f"更新进行中或等待恢复。请勿删除更新目录：\n{work}")
            yield None
            return
        work = _work_path(token)
        req, target = _request(work)
        if pending != {"token": token} or not _same_path(root, target) or _phase(work) != "applying":
            raise UpdateError("新版启动确认不属于当前安装事务。")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            identity = _read(work / "candidate.json")
            if identity is not None:
                break
            time.sleep(0.05)
        else:
            raise UpdateError("未收到新版进程身份。")
        if identity != {"pid": os.getpid()} or not _admin():
            raise UpdateError("新版进程与更新器启动的进程不一致。")
        yield (work, req["version"])


def acknowledge_startup(launch, version):
    work, expected_version = launch
    if version != expected_version:
        raise UpdateError("新版内置版本号与更新包不符。")
    _write(work / "ack.json", {"pid": os.getpid(), "version": version})


def cleanup_finished_updates():
    """Best effort, from a normal elevated GUI, after a helper no longer runs."""
    if not can_auto_update() or not _admin():
        return
    root = _install_root()
    for work in _base().glob(PREFIX + "*"):
        token = work.name[len(PREFIX):]
        if not TOKEN.fullmatch(token):
            continue
        try:
            _, target = _request(work)
            if not _same_path(root, target):
                continue
            # Do not remove rollback diagnostics or an active transaction.
            with installation_lock(work, exclusive=True):
                if _phase(work) not in ("confirmed", "cancelled"):
                    continue
                if _read(root / PENDING) == {"token": token}:
                    continue
                # The helper may still be unmapping its own EXE. Try
                # this deletion first, leaving the request intact on failure.
                helper = work / HELPER_DIR / HELPER_EXE
                try:
                    safe_path(helper, kind="file").unlink()
                except FileNotFoundError:
                    pass
                _cleanup_files(work, _stage_root(root, token))
                if _stage_root(root, token).exists():
                    continue
            _remove_tree(work)
        except (OSError, ValueError, UpdateError):
            continue


def _helper_main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("--apply", "--recover") or not _admin():
        return 2
    token = sys.argv[2]
    work = None
    trusted = False
    try:
        work = _trusted_work(_work_path(token))
        if not getattr(sys, "frozen", False) or not _same_path(
                safe_path(Path(sys.executable), kind="file"), work / HELPER_DIR / HELPER_EXE):
            raise UpdateError("只能从独立事务目录运行安装程序。")
        trusted = True
        req, root = _request(work)
        with installation_lock(work, exclusive=True):
            if sys.argv[1] == "--recover":
                return _recover(work, root, token)
            if _phase(work) is not None or _read(work / "ready.json") is not None:
                raise UpdateError("此更新事务已经启动，不能重复提交。")
            return _apply(work, root, token, req)
    except Exception as exc:
        if trusted:
            _record_error(work, exc)
        if sys.argv[1] == "--recover":
            _notice(f"无法恢复更新：{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(_helper_main())
