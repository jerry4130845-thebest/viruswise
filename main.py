import os
import sys
import traceback
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---- 目录初始化（原 legacy_patch.py:66-79）----
from utils.paths import BASE_DIR, DATA_DIR, QUARANTINE_DIR, PROFILES_DIR, CRASH_LOG

try:
    os.chdir(BASE_DIR)
    for _dir in (DATA_DIR, QUARANTINE_DIR, PROFILES_DIR):
        os.makedirs(_dir, exist_ok=True)
except Exception as e:
    print(f"初始化目录失败: {e}")
    sys.exit(1)

# ---- 全局异常钩子（原 legacy_patch.py:30-48）----
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


# ---- 管理员提权（原 legacy_patch.py:85-98）----
def is_admin():
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def elevate_if_needed():
    if getattr(sys, 'frozen', False) and sys.argv and sys.argv[0].endswith('.py'):
        return
    if is_admin():
        return
    
    # 增加非交互式检测
    if not hasattr(sys, 'stdin') or sys.stdin is None or not sys.stdin.isatty():
        print("未检测到交互式环境，无法自动提权。请尝试以管理员身份手动运行。")
        return

    import ctypes
    try:
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        if ret <= 32:
            print(f"提权失败 (Error: {ret})")
    except Exception as e:
        print(f"提权调用异常: {e}")
    sys.exit(0)


def main():
    setup_exception_handler()
    elevate_if_needed()

    from ui.app import VirusWiseApp
    app = VirusWiseApp()
    app.mainloop()


if __name__ == '__main__':
    main()
