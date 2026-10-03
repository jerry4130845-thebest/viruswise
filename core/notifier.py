import queue, time, threading
from utils.logging import main_log

class WindowsNotifier:
    def __init__(self):
        self.backend = None
        self.toaster = None
        self.notification_queue = queue.Queue(maxsize=50)
        self.last_notification_time = {}
        try:
            from win10toast import ToastNotifier
            self.toaster = ToastNotifier()
            self.backend = "win10toast"
            threading.Thread(target=self._notification_worker, daemon=True).start()
        except Exception as e: print(f"通知模块初始化失败: {e}")

    def _notification_worker(self):
        while True:
            try:
                title, message, duration = self.notification_queue.get(timeout=2)
                self._do_send(title, message, duration)
            except queue.Empty:
                pass
            except Exception as e:
                main_log(f"通知处理异常: {e}")

    def send(self, title, message, duration=5):
        key = f"{title}:{message[:20]}"
        now = time.time()
        if key in self.last_notification_time and now - self.last_notification_time[key] < 3:
            return
        self.last_notification_time[key] = now
        
        try:
            self.notification_queue.put_nowait((title, message, duration))
        except queue.Full:
            pass

    def _do_send(self, title, message, duration):
        title = str(title) if title else "通知"
        message = str(message) if message else ""
        if self.backend == "win10toast" and self.toaster:
            try:
                self.toaster.show_toast(title, message, duration=duration)
                main_log(f"系统通知已推送: {title}")
            except Exception as e:
                main_log(f"[通知降级] {title}: {message}")
        else:
            main_log(f"[通知] {title}: {message}")

notifier = WindowsNotifier()