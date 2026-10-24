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
# ------------------------------------------------------------------
    # 系统关键路径写入保护（SystemMonitorHandler 调用）
    # ------------------------------------------------------------------
    def handle_system_write(self, path):
        if not self.config.get('modify_protection', True):
            return
        if get_risk_level(path) != 2:
            return
        main_log(f"[系统写入保护] 检测到关键系统路径被修改: {path}")
        # 尽量找到操作该路径的进程并挂起
        with self.monitored_lock:
            monitored_copy = list(self.monitored.items())
        suspect_pids = self._find_file_operator(path, monitored_copy)
        if not suspect_pids:
            main_log(f"[系统写入保护] 无法确定修改 {path} 的进程来源")
            return
        matched = False
        for pid in suspect_pids:
            if pid not in dict(monitored_copy):
                continue
            mon = dict(monitored_copy)[pid]
            if pid in TEMPORARY_ALLOWED or not psutil.pid_exists(pid):
                continue
            if self._is_whitelisted(pid=pid, name=mon.name, exe=mon.exe):
                continue
            try:
                psutil.Process(pid).suspend()
                with suspended_lock:
                    if pid not in SUSPENDED_PROCS:
                        SUSPENDED_PROCS[pid] = {
                            'pid': pid, 'name': mon.name, 'exe': mon.exe,
                            'reason': "系统关键路径写入保护"
                        }
            except Exception:
                pass
            self._trigger_protection_alert(pid, mon, path, "系统写入")
            matched = True

        if not matched:
            main_log(f"[系统写入保护] 检测到关键路径被修改: {os.path.basename(path)} (但无法确定进程来源)")

    # ------------------------------------------------------------------
    # 保护告警：弹窗并挂起进程
    # ------------------------------------------------------------------
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
                'rules': [f"{operation}保护触发: {os.path.basename(path)}"],
            }
            main_log(f"[保护告警] {info['name']} (PID {pid}) {operation}: {path}")
            # 尝试通过全局 app 实例弹窗
            app = getattr(sys, 'app', None)
            if app and hasattr(app, 'show_protection_alert'):
                try:
                    app.after(0, lambda: app.show_protection_alert(info))
                except Exception:
                    pass
        except Exception as e:
            main_log(f"[保护告警] 异常: {e}")

    # ------------------------------------------------------------------
    # 进程行为监控循环（原 legacy_patch._monitor_loop）
    # ------------------------------------------------------------------
    def _monitor_loop(self):
        while self.running:
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
                        if not name or name.lower() in SYSTEM_PROCESSES:
                            continue
                        with self.monitored_lock:
                            if pid not in self.monitored:
                                self.monitored[pid] = SimpleNamespace(
                                    name=name, exe=exe,
                                    delete_count=0, deleted_files=[], deleted_files_set=set(),
                                    modify_count=0, modified_files=set(), system_writes=[],
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                # 清理已退出进程的监控条目，防止内存泄漏
                with self.monitored_lock:
                    dead = [pid for pid in self.monitored if pid not in alive_pids]
                    for pid in dead:
                        del self.monitored[pid]
                # 清理已退出进程的挂起记录
                with suspended_lock:
                    dead_susp = [pid for pid in SUSPENDED_PROCS if pid not in alive_pids]
                    for pid in dead_susp:
                        del SUSPENDED_PROCS[pid]
            except Exception:
                pass
            time.sleep(2)

    # ------------------------------------------------------------------
    # 启动项与服务监控（原 legacy_patch._monitor_startup_and_services）
    # ------------------------------------------------------------------
    def _monitor_startup_and_services(self):
        while self.running:
            try:
                # 轻量级轮询：仅记录日志，不自动干预，避免误杀
                startup_paths = [
                    os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
                    os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
                ]
                for sp in startup_paths:
                    if os.path.isdir(sp):
                        for name in os.listdir(sp):
                            full = os.path.join(sp, name)
                            if get_risk_level(full) == 2:
                                main_log(f"[启动项监控] 发现高风险启动项: {full}")
            except Exception:
                pass
            time.sleep(10)
