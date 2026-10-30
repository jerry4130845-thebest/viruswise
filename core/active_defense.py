import concurrent.futures
import os, sys, time, threading, queue, hashlib
from types import SimpleNamespace
import psutil

from utils.logging import main_log
from utils.whitelist import load_whitelist
from utils.risk import SYSTEM_CRITICAL_PATHS, SYSTEM_PROCESSES, get_risk_level
from utils.config import load_config
from core.notifier import notifier

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


# ---- 全局状态（与 ui.app 保持兼容）----
alerted_processes = set()
alert_lock = threading.Lock()
TEMPORARY_ALLOWED = set()
ad_queue = queue.Queue()
SUSPENDED_PROCS = {}
suspended_lock = threading.Lock()
ACTIVE_DEFENSE_ENABLED = False
MONITOR_DIRS = []


class ProcessRecord:
    __slots__ = ('pid', 'name', 'exe', 'ppid', 'parent_name',
                 'violations', 'score', 'deleted_files_set',
                 'modified_files_set', 'system_writes')

    def __init__(self, pid, name, exe, ppid, parent_name):
        self.pid = pid
        self.name = name
        self.exe = exe
        self.ppid = ppid
        self.parent_name = parent_name
        self.violations = 0
        self.score = 0.0
        self.deleted_files_set = set()
        self.modified_files_set = set()
        self.system_writes = []


class ActiveDefenseHandler(FileSystemEventHandler):
    def __init__(self, ad):
        self.ad = ad

    def _emit(self, src_path, event_type):
        if not src_path:
            return
        try:
            self.ad.event_queue.put_nowait(('file_event', src_path, event_type))
        except queue.Full:
            main_log("[主动防御] 事件队列已满，丢弃事件")

    def on_deleted(self, e):
        if not e.is_directory:
            self._emit(e.src_path, 'deleted')

    def on_modified(self, e):
        if not e.is_directory:
            self._emit(e.src_path, 'modified')

    def on_created(self, e):
        if not e.is_directory:
            self._emit(e.src_path, 'created')


class SystemMonitorHandler(FileSystemEventHandler):
    def __init__(self, ad):
        self.ad = ad

    def _emit(self, src_path, event_type):
        if not src_path:
            return
        try:
            self.ad.event_queue.put_nowait(('system_write', src_path, event_type))
        except queue.Full:
            main_log("[主动防御] 系统事件队列已满，丢弃事件")

    def on_modified(self, e):
        if not e.is_directory:
            self._emit(e.src_path, 'modified')

    def on_created(self, e):
        if not e.is_directory:
            self._emit(e.src_path, 'created')

    def on_deleted(self, e):
        if not e.is_directory:
            self._emit(e.src_path, 'deleted')


executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

class ActiveDefense:
    def __init__(self):
        self.observer = None
        self.running = False
        self.event_queue = queue.Queue(maxsize=1000)
        self._stop = False
        self._worker_thread = None
        self._monitor_thread = None

        self.monitored = {}
        self.monitored_lock = threading.Lock()

        self.whitelist_hashes = set()
        self.whitelist_names = set()
        self.whitelist_paths = []
        self.last_whitelist_mtime = 0
        self.refresh_whitelist()

        self.config = load_config()

    def refresh_whitelist(self):
        try:
            from utils.whitelist import WHITELIST_FILE
            mtime = os.path.getmtime(WHITELIST_FILE)
            if mtime == self.last_whitelist_mtime:
                return
            self.last_whitelist_mtime = mtime
        except Exception:
            pass
        wl = load_whitelist()
        self.whitelist_hashes = {item.get('hash') for item in wl if item.get('hash')}
        self.whitelist_names = {item.get('name', '').lower() for item in wl if item.get('name')}
        self.whitelist_paths = [item.get('path', '').lower() for item in wl if item.get('path')]

    def _is_whitelisted(self, record):
        if not record:
            return True
        if record.name and record.name.lower() in self.whitelist_names:
            return True
        if record.exe:
            exe_lower = record.exe.lower()
            if any(exe_lower.startswith(wp) or exe_lower == wp for wp in self.whitelist_paths):
                return True
        if record.name and record.name.lower() in {'onedrive.exe', 'filesynchoop.exe', 'explorer.exe'}:
            return True
        return False

    def _find_likely_operator(self, filepath, max_checks=5):
        filepath_lower = filepath.lower()
        parent_dir = os.path.dirname(filepath).lower()
        with self.monitored_lock:
            candidates = list(self.monitored.items())
        for pid, rec in candidates[:max_checks]:
            if not psutil.pid_exists(pid):
                continue
            try:
                proc = psutil.Process(pid)
                for f in proc.open_files():
                    fpath = f.path.lower()
                    if fpath == filepath_lower or parent_dir in fpath:
                        return pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def start(self, user_dirs):
        try:
            self._stop = False

            self._worker_thread = threading.Thread(target=self._event_worker, daemon=True)
            self._worker_thread.start()

            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()

            if WATCHDOG_AVAILABLE:
                self.observer = Observer()
                if user_dirs:
                    handler = ActiveDefenseHandler(self)
                    for d in user_dirs:
                        if os.path.exists(d):
                            self.observer.schedule(handler, d, recursive=True)

                sys_handler = SystemMonitorHandler(self)
                for p in SYSTEM_CRITICAL_PATHS:
                    if os.path.exists(p):
                        try:
                            self.observer.schedule(sys_handler, p, recursive=True)
                        except Exception:
                            pass

                self.observer.start()
                main_log("主动防御已开启 (事件驱动，仅监控 Explorer 子进程)")
            else:
                main_log("主动防御已开启 (watchdog 未安装，仅进程监控模式)")

            self.running = True

        except Exception as e:
            main_log(f"主动防御启动失败: {e}")

    def stop(self):
        self._stop = True
        self.running = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
            except Exception:
                pass
        with suspended_lock:
            for pid in list(SUSPENDED_PROCS.keys()):
                try:
                    psutil.Process(pid).resume()
                except Exception:
                    pass
            SUSPENDED_PROCS.clear()
        main_log("主动防御已停止")

    def _monitor_loop(self):
        while not self._stop:
            try:
                alive_pids = set()
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        pid = proc.info['pid']
                        alive_pids.add(pid)

                        if pid in TEMPORARY_ALLOWED:
                            continue

                        name = proc.info.get('name') or ''
                        exe = proc.info.get('exe') or ''
                        if not name:
                            continue
                        if name.lower() in SYSTEM_PROCESSES:
                            continue

                        try:
                            parent = proc.parent()
                            parent_name = parent.name() if parent else ''
                        except Exception:
                            parent_name = ''

                        if parent_name.lower() != 'explorer.exe':
                            continue

                        with self.monitored_lock:
                            if pid not in self.monitored:
                                self.monitored[pid] = ProcessRecord(
                                    pid=pid, name=name, exe=exe,
                                    ppid=proc.ppid() if hasattr(proc, 'ppid') else None,
                                    parent_name=parent_name
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                with self.monitored_lock:
                    dead = [pid for pid in self.monitored if pid not in alive_pids]
                    for pid in dead:
                        del self.monitored[pid]

                with suspended_lock:
                    dead_susp = [pid for pid in SUSPENDED_PROCS if pid not in alive_pids]
                    for pid in dead_susp:
                        del SUSPENDED_PROCS[pid]

            except Exception:
                pass
            time.sleep(6.0)

    def _event_worker(self):
        while not self._stop:
            try:
                event = self.event_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                kind, path, action = event
                if kind == 'file_event':
                    self._handle_file_event(path, action)
                elif kind == 'system_write':
                    self._handle_system_write_event(path, action)
            except Exception as e:
                main_log(f"[主动防御] 事件处理异常: {e}")

    def _is_protected_path(self, path):
        pl = path.lower()
        for wp in self.whitelist_paths:
            if pl.startswith(wp):
                return False
        return True

    def _handle_file_event(self, path, action):
        if action in ('deleted', 'modified') and not self.config.get('delete_protection', True):
            return
        if not self._is_protected_path(path):
            return

        operator_pid = self._find_likely_operator(path)
        if operator_pid is None:
            main_log(f"[文件保护] 检测到 {action}: {os.path.basename(path)} (无法确定进程来源)")
            return

        with self.monitored_lock:
            rec = self.monitored.get(operator_pid)
        if not rec or self._is_whitelisted(rec):
            return

        rec.violations += 1
        rec.score += 10.0

        if action == 'deleted':
            rec.deleted_files_set.add(path)
            main_log(f"[删除保护] {rec.name}(PID {operator_pid}) 尝试删除: {os.path.basename(path)} (违规{rec.violations}次)")
        elif action == 'modified':
            rec.modified_files_set.add(path)
            main_log(f"[修改保护] {rec.name}(PID {operator_pid}) 尝试修改: {os.path.basename(path)} (违规{rec.violations}次)")

        threshold = self.config.get('batch_delete_threshold', 5)
        if rec.violations >= threshold:
            self._suspend_process(operator_pid, rec, f"批量{action}保护触发", path)

    def _handle_system_write_event(self, path, action):
        if not self.config.get('modify_protection', True):
            return
        if get_risk_level(path) != 2:
            return

        operator_pid = self._find_likely_operator(path)
        if operator_pid is None:
            main_log(f"[系统写入保护] 检测到关键路径被修改: {path} (无法确定进程来源)")
            return

        with self.monitored_lock:
            rec = self.monitored.get(operator_pid)
        if not rec or self._is_whitelisted(rec):
            return

        rec.violations += 1
        rec.score += 15.0
        rec.system_writes.append(path)
        main_log(f"[系统写入保护] {rec.name}(PID {operator_pid}) 写入关键路径: {os.path.basename(path)} (违规{rec.violations}次)")

        threshold = self.config.get('batch_delete_threshold', 5)
        if rec.violations >= threshold:
            self._suspend_process(operator_pid, rec, "系统关键路径写入保护", path)

    def _suspend_process(self, pid, record, reason, path=''):
        try:
            psutil.Process(pid).suspend()
        except Exception as e:
            main_log(f"挂起进程失败: {e}")
            return

        with suspended_lock:
            if pid not in SUSPENDED_PROCS:
                SUSPENDED_PROCS[pid] = {
                    'pid': pid, 'name': record.name, 'exe': record.exe,
                    'reason': reason
                }

        main_log(f"[挂起] {record.name}(PID {pid}): {reason}")
        self._trigger_protection_alert(pid, record, path, "保护")

    def _trigger_protection_alert(self, pid, mon, path, operation):
        try:
            if not psutil.pid_exists(pid):
                return
            info = {
                'pid': pid,
                'name': getattr(mon, 'name', '未知'),
                'exe': getattr(mon, 'exe', ''),
                'path': path,
                'operation': operation,
                'rules': [f"{operation}保护触发: {os.path.basename(path) if path else ''}"],
            }
            main_log(f"[保护告警] {info['name']} (PID {pid}) {operation}: {path}")
            try:
                ad_queue.put_nowait(('protection_alert', info))
            except queue.Full:
                pass
        except Exception as e:
            main_log(f"[保护告警] 异常: {e}")
