import os
import sys
import traceback
import subprocess
from datetime import datetime

ENTRY_SCRIPT = os.path.abspath(__file__)
PROJECT_ROOT = os.path.dirname(ENTRY_SCRIPT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils.paths import BASE_DIR, DATA_DIR, QUARANTINE_DIR, PROFILES_DIR, CRASH_LOG

try:
    os.chdir(BASE_DIR)
    for _dir in (DATA_DIR, QUARANTINE_DIR, PROFILES_DIR):
        os.makedirs(_dir, exist_ok=True)
except Exception as e:
    print(f"初始化目录失败: {e}")
    sys.exit(1)

def setup_exception_handler():
    def global_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        tb_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        try:
            with open(CRASH_LOG, 'w', encoding='utf-8') as f:
                f.write(f"[{datetime.now()}] Unhandled Exception:\n{tb_text}")
        except Exception:
            pass
        try:
            from tkinter import messagebox
            messagebox.showerror("程序崩溃", f"启动失败，日志已保存至:\n{CRASH_LOG}\n\n{tb_text[:600]}")
        except Exception:
            print("CRASH LOG SAVED TO:", CRASH_LOG)
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


def main():
    setup_exception_handler()
    elevate_if_needed()

    from ui.app import VirusWiseApp
    app = VirusWiseApp()
    app.mainloop()


if __name__ == '__main__':
    main()
