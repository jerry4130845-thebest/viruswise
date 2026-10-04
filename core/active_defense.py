import os, sys, time, threading, queue, subprocess, pickle, hashlib
from types import SimpleNamespace
import psutil

from utils.logging import main_log
from utils.whitelist import load_whitelist
from utils.risk import SYSTEM_CRITICAL_PATHS, SYSTEM_PROCESSES, get_risk_level
from utils.fake_log import is_fake_log
from utils.network import is_offline
from utils.config import load_config
from core.notifier import notifier
from core.scoring import ProcessScoreTracker, ProcessAnalyzer

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

alerted_processes = set()
alert_lock = threading.Lock()
TEMPORARY_ALLOWED = set()
ad_queue = queue.Queue()
SUSPENDED_PROCS = {}
suspended_lock = threading.Lock()
ACTIVE_DEFENSE_ENABLED = False
MONITOR_DIRS = []

if WATCHDOG_AVAILABLE:

    class ActiveDefenseHandler(FileSystemEventHandler):
        def __init__(self, ad):
            self.ad = ad

        def on_deleted(self, e):
            if not e.is_directory:
                self.ad.handle_user_delete(e.src_path)

        def on_modified(self, e):
            if not e.is_directory:
                self.ad.handle_user_modify(e.src_path)


    class SystemMonitorHandler(FileSystemEventHandler):
        def __init__(self, ad):
            self.ad = ad

        def on_modified(self, e):
            if not e.is_directory:
                self.ad.handle_system_write(e.src_path)

        def on_created(self, e):
            if not e.is_directory:
                self.ad.handle_system_write(e.src_path)

        def on_deleted(self, e):
            if not e.is_directory:
                self.ad.handle_user_delete(e.src_path)


class ActiveDefense:
    def __init__(self):
        self.observer = None
        self.running = False
        self.known = {}
        self.monitored = {}
        self.monitored_lock = threading.Lock()
        self.whitelist_hashes = set()
        self.whitelist_names = set()
        self.whitelist_paths = []
        self.refresh_whitelist()
        self.analyzer = ProcessAnalyzer()
        self.score_tracker = ProcessScoreTracker()
        self.config = load_config()

        self.file_handle_cache = {}
        self.cache_lock = threading.Lock()
        self._handle_thread = None
        self._handle_stop = False

    def refresh_whitelist(self):
        wl = load_whitelist()
        self.whitelist_hashes = {item.get('hash') for item in wl if item.get('hash')}
        self.whitelist_names = {item.get('name', '').lower() for item in wl if item.get('name')}
        self.whitelist_paths = [item.get('path', '').lower() for item in wl if item.get('path')]

    def _is_whitelisted(self, pid=None, name=None, exe=None):
        if pid and pid in self.known:
            return True
        if name:
            n = name.lower()
            if n in {'onedrive.exe', 'filesynchoop.exe', 'explorer.exe'}:
                return True
            if self.config.get('wl_by_name') and n in self.whitelist_names:
                return True
        if exe:
            exe_lower = exe.lower()
            if self.config.get('wl_by_hash') and os.path.exists(exe):
                try:
                    with open(exe, 'rb') as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                    if h in self.whitelist_hashes:
                        return True
                except:
                    pass
            if any(exe_lower.startswith(wp) or exe_lower == wp for wp in self.whitelist_paths):
                return True
        return False

    def _find_file_operator(self, filepath, monitored_copy):

        filepath_lower = filepath.lower()
        parent_dir = os.path.dirname(filepath).lower()

        with self.cache_lock:
            handle_cache = dict(self.file_handle_cache)  # 快照

        candidate_pids = set()
        if filepath_lower in handle_cache:
            candidate_pids.add(handle_cache[filepath_lower])
        if parent_dir in handle_cache:
            candidate_pids.add(handle_cache[parent_dir])

        if not candidate_pids:
            time.sleep(0.2)
            with self.cache_lock:
                handle_cache = dict(self.file_handle_cache)
            if filepath_lower in handle_cache:
                candidate_pids.add(handle_cache[filepath_lower])
            if parent_dir in handle_cache:
                candidate_pids.add(handle_cache[parent_dir])

        monitored_pids = {pid for pid, _ in monitored_copy}
        valid_pids = [pid for pid in candidate_pids if pid in monitored_pids]
        if valid_pids:
            return valid_pids

        suspect_pids = []
        for pid in monitored_pids:
            if not psutil.pid_exists(pid):
                continue
            try:
                proc = psutil.Process(pid)
                for f in proc.open_files():
                    f_path = f.path.lower()
                    if f_path == filepath_lower or parent_dir in f_path:
                        suspect_pids.append(pid)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if suspect_pids:
            return suspect_pids

        active = []
        for pid in monitored_pids:
            try:
                proc = psutil.Process(pid)
                cpu = proc.cpu_percent(interval=0.01)
                if cpu > 0.1:
                    active.append((pid, cpu))
            except:
                pass
        if active:
            active.sort(key=lambda x: x[1], reverse=True)
            return [pid for pid, _ in active[:max(1, len(active)//3+1)]]

        return []

    def _handle_snapshot_worker(self):
        while not self._handle_stop:
            new_cache = {}
            for proc in psutil.process_iter(['pid']):
                try:
                    pid = proc.info['pid']
                    for f in proc.open_files():
                        path = f.path.lower()
                        new_cache[path] = pid
                        parent = os.path.dirname(path)
                        if parent:
                            new_cache[parent] = pid
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            with self.cache_lock:
                self.file_handle_cache = new_cache
            time.sleep(0.5)

    def start(self, user_dirs):
        try:
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
                    except:
                        pass

            self.observer.start()
            self.running = True

            if not self._handle_thread or not self._handle_thread.is_alive():
                self._handle_stop = False
                self._handle_thread = threading.Thread(target=self._handle_snapshot_worker, daemon=True)
                self._handle_thread.start()

            def start_monitor_threads():
                time.sleep(2)
                threading.Thread(target=self._monitor_loop, daemon=True).start()
                time.sleep(1)
                threading.Thread(target=self._monitor_startup_and_services, daemon=True).start()

            threading.Thread(target=start_monitor_threads, daemon=True).start()
            main_log("主动防御已开启 (watchdog 全接管)")

        except Exception as e:
            main_log(f"主动防御启动失败: {e}")

    def stop(self):
        self._handle_stop = True
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        self.running = False
        main_log("主动防御已停止")

    def handle_user_delete(self, path):
        if not self.config.get('delete_protection', True):
            return
        with self.monitored_lock:
            monitored_copy = list(self.monitored.items())
        suspect_pids = self._find_file_operator(path, monitored_copy)

        matched = False
        if suspect_pids:
            for pid in suspect_pids:
                if pid not in dict(monitored_copy):
                    continue
                mon = dict(monitored_copy)[pid]
                if pid in TEMPORARY_ALLOWED or not psutil.pid_exists(pid):
                    continue
                if self._is_whitelisted(pid=pid, name=mon.name, exe=mon.exe):
                    continue
                if not hasattr(mon, 'delete_count'):
                    mon.delete_count = 0
                if not hasattr(mon, 'deleted_files'):
                    mon.deleted_files = []
                    mon.deleted_files_set = set()
                mon.delete_count += 1
                if len(mon.deleted_files) < 10:
                    mon.deleted_files.append(path)
                mon.deleted_files_set.add(path)
                main_log(f"[删除保护] {mon.name} 尝试删除: {os.path.basename(path)}")

                if len(mon.deleted_files_set) >= self.config.get('batch_delete_threshold', 5):
                    try:
                        psutil.Process(pid).suspend()
                        with suspended_lock:
                            if pid not in SUSPENDED_PROCS:
                                SUSPENDED_PROCS[pid] = {'pid': pid, 'name': mon.name, 'exe': mon.exe,
                                                        'reason': "批量删除保护目录"}
                    except:
                        pass
                    self._trigger_protection_alert(pid, mon, path, "删除")
                matched = True

        if not matched:
            main_log(f"[删除保护] 检测到受保护文件被删除: {os.path.basename(path)} (但无法确定进程来源)")

    def handle_user_modify(self, path):
        if not self.config.get('modify_protection', True):
            return
        with self.monitored_lock:
            monitored_copy = list(self.monitored.items())
        suspect_pids = self._find_file_operator(path, monitored_copy)

        matched = False
        if suspect_pids:
            for pid in suspect_pids:
                if pid not in dict(monitored_copy):
                    continue
                mon = dict(monitored_copy)[pid]
                if pid in TEMPORARY_ALLOWED or not psutil.pid_exists(pid):
                    continue
                if self._is_whitelisted(pid=pid, name=mon.name, exe=mon.exe):
                    continue
                if not hasattr(mon, 'modify_count'):
                    mon.modify_count = 0
                    mon.modified_files = set()
                mon.modify_count += 1
                mon.modified_files.add(path)
                main_log(f"[修改保护] {mon.name} 尝试修改: {os.path.basename(path)}")

                if len(mon.modified_files) >= self.config.get('batch_modify_threshold', self.config.get('batch_delete_threshold', 5)):
                    try:
                        psutil.Process(pid).suspend()
                        with suspended_lock:
                            if pid not in SUSPENDED_PROCS:
                                SUSPENDED_PROCS[pid] = {'pid': pid, 'name': mon.name, 'exe': mon.exe,
                                                        'reason': "批量修改保护目录"}
                    except:
                        pass
                    self._trigger_protection_alert(pid, mon, path, "修改")
                matched = True

        if not matched:
            main_log(f"[修改保护] 检测到受保护文件被修改: {os.path.basename(path)} (但无法确定进程来源)")
