import sys
from datetime import datetime

def main_log(msg):
    if hasattr(sys, 'app') and sys.app:
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {msg}"
        try:
            sys.app.after(0, lambda: sys.app.main_log_box.insert("end", formatted + "\n"))
        except RuntimeError:
            pass

def scan_log(msg):
    if hasattr(sys, 'app') and sys.app:
        if msg.startswith("=") or msg.startswith("-"):
            try:
                sys.app.after(0, lambda: sys.app.scan_log_box.insert("end", msg + "\n"))
            except RuntimeError:
                pass
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            formatted = f"[{timestamp}] {msg}"
            try:
                sys.app.after(0, lambda: sys.app.scan_log_box.insert("end", formatted + "\n"))
            except RuntimeError:
                pass

def update_progress(value, text):
    if hasattr(sys, 'app') and sys.app:
        try:
            sys.app.after(0, lambda: sys.app._set_progress(value, text))
        except RuntimeError:
            pass
