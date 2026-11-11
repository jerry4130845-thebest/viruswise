import os
import sys
import traceback
import subprocess
from datetime import datetime

ENTRY_SCRIPT = os.path.abspath(__file__)
PROJECT_ROOT = os.path.dirname(ENTRY_SCRIPT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def setup_exception_handler(crash_log):
    def global_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        tb_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        try:
            with open(crash_log, 'w', encoding='utf-8') as f:
                f.write(f"[{datetime.now()}] Unhandled Exception:\n{tb_text}")
        except Exception:
            pass
        try:
            from tkinter import messagebox
            messagebox.showerror("程序崩溃", f"启动失败，日志已保存至:\n{crash_log}\n\n{tb_text[:600]}")
        except Exception:
            print("CRASH LOG SAVED TO:", crash_log)
            print(tb_text)
        sys.exit(1)
    sys.excepthook = global_handler


def is_admin():
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def elevate_if_needed():
    if is_admin():
        return

    # UAC does not require a console; pythonw and packaged GUI launches have no stdin.
    import ctypes
    try:
        args = list(sys.argv[1:])
        if not getattr(sys, 'frozen', False):
            args.insert(0, ENTRY_SCRIPT)
        params = subprocess.list2cmdline(args)
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, PROJECT_ROOT, 1)
        if ret <= 32:
            print(f"提权失败或已取消 (Error: {ret})")
            sys.exit(1)
    except Exception as e:
        print(f"提权调用异常: {e}")
        sys.exit(1)
    sys.exit(0)


def _run_gui():
    # These imports create directories: never run them for management or SCM.
    from utils.paths import BASE_DIR, DATA_DIR, QUARANTINE_DIR, PROFILES_DIR, CRASH_LOG

    try:
        os.chdir(BASE_DIR)
        for directory in (DATA_DIR, QUARANTINE_DIR, PROFILES_DIR):
            os.makedirs(directory, exist_ok=True)
    except Exception as exc:
        print(f"初始化目录失败: {exc}")
        return 1
    setup_exception_handler(CRASH_LOG)
    elevate_if_needed()

    from ui.app import VirusWiseApp
    app = VirusWiseApp()
    app.mainloop()
    return 0


def _write_result(result):
    """Management uses the controller result dict, not the CLI envelope."""
    import json
    try:
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        sys.stdout.flush()
    except (OSError, ValueError, AttributeError):
        # Avoid another failing flush during interpreter shutdown.
        sys.stdout = None
        return 5
    return result["exit_code"]


def _error(code, exit_code, message):
    return _write_result(dict(ok=False, ready=False, code=code,
                              exit_code=exit_code, error=message))


def _install_elevated():
    """Wait for one UAC child; only its exit status crosses the privilege boundary."""
    process = None
    launched = False
    try:
        import win32api
        import win32event
        import win32process
        from win32com.shell import shell, shellcon

        args = ["--install", "--elevated-install"]
        if not getattr(sys, "frozen", False):
            args.insert(0, ENTRY_SCRIPT)
        info = shell.ShellExecuteEx(
            fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
            lpVerb="runas", lpFile=sys.executable,
            lpParameters=subprocess.list2cmdline(args),
            lpDirectory=PROJECT_ROOT, nShow=1)
        launched = True
        process = info.get("hProcess")
        if not process:
            return _error("elevation_wait_failed", 5,
                          "UAC launch returned no process handle; installation outcome is unknown. "
                          "Inspect service state before retrying; no service start was requested.")
        # Bounded waits allow Ctrl+C without terminating an elevated installer midway.
        while True:
            status = win32event.WaitForSingleObject(process, 200)
            if status == win32event.WAIT_OBJECT_0:
                break
            if status != win32event.WAIT_TIMEOUT:
                raise RuntimeError("Unexpected process wait result: %s" % status)
        exit_code = win32process.GetExitCodeProcess(process)
        return _write_result(dict(
            ok=exit_code == 0, ready=False,
            code="elevated_child_exited", exit_code=exit_code,
            child_exit_code=exit_code, evidence="child_exit_code_only",
            message="Elevated installer exited with code %s. "
                    "Its controller JSON was not captured: this does not independently verify "
                    "installation or service readiness. No service start was requested." % exit_code))
    except ImportError:
        return _error("dependency_missing", 3,
                      "pywin32 ShellExecuteEx and process waiting are required for install elevation.")
    except KeyboardInterrupt:
        return _error("cancelled", 130,
                      "Waiting for UAC/installation was interrupted; an elevated child may still run. "
                      "Inspect service state before retrying; no service start was requested.")
    except Exception as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror is None and exc.args and isinstance(exc.args[0], int):
            winerror = exc.args[0]
        if not launched and winerror == 1223:
            return _error("elevation_cancelled", 1223,
                          "Windows UAC was cancelled; the elevated installer was not started.")
        return _error("elevation_wait_failed" if launched else "elevation_failed", 5,
                      ("Unable to confirm elevated installer completion; installation outcome is unknown. "
                       "Inspect service state before retrying. " if launched else
                       "Unable to launch the elevated installer. ") +
                      "Windows error: %s. No service start was requested." % winerror)
    finally:
        if process:
            try:
                win32api.CloseHandle(process)
            except Exception:
                # Do not replace the child's exit status with a cleanup error.
                pass


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return _run_gui()
    # CLI owns all following arguments; it never implies service installation.
    if args[0] == "--cli":
        from cli import main as cli_main
        return cli_main(args[1:])
    if args in (["--help"], ["-h"]):
        print("VirusWise [--install | --uninstall | --cli <arguments> | --help]\n"
              "No arguments: GUI. --install/--uninstall: explicit administrator operations,\n"
              "JSON results; --install requests Windows UAC when needed and waits for completion.\n"
              "--uninstall never elevates automatically. Neither operation starts the service.\n"
              "--cli: existing automation CLI (try --cli --help).\n"
              "--service: internal Windows SCM host, not a manual defense start command.")
        return 0
    elevated_install = args == ["--install", "--elevated-install"]
    if elevated_install:
        args = ["--install"]
    if len(args) != 1 or args[0] not in ("--install", "--uninstall", "--service"):
        return _error("invalid_arguments", 2,
                      "Choose one mode; --install, --uninstall and --service accept no extra arguments.")
    if os.name != "nt":
        return _error("unsupported_platform", 3, "Windows service operations require Windows.")
    try:
        if args[0] == "--service":
            from core.active_defense import run_service_host
            run_service_host()
            return 0
        if args[0] == "--install" and not is_admin():
            if elevated_install:
                return _error("elevation_failed", 4,
                              "Elevated installer still lacks administrator rights; refusing another UAC request.")
            return _install_elevated()
        from core import defense_control
        action = defense_control.install if args[0] == "--install" else defense_control.uninstall
        return _write_result(action(allow_system_effects=True))
    except ImportError:
        return _error("dependency_missing", 3, "Required service runtime dependencies are unavailable.")
    except KeyboardInterrupt:
        return _error("cancelled", 130, "Operation interrupted; inspect service state before retrying.")
    except Exception:
        return _error("service_error", 5,
                      "Service operation failed; --service must be launched by Windows SCM.")


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    sys.exit(main())
