import os
import sys
import time
import threading
import traceback
import sqlite3
import hmac
import hashlib
import json
from datetime import datetime, timedelta
import queue
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32security
import ntsecuritycon as con
import win32con
import win32api
import win32process
import psutil
import pythoncom
import win32com.client

# ---- 兼容 UI 的变量与结构 ----
alerted_processes = set()
alert_lock = threading.Lock()
TEMPORARY_ALLOWED = set()
ad_queue = queue.Queue()
SUSPENDED_PROCS = {}
suspended_lock = threading.Lock()
MONITOR_DIRS = []
# The current ActiveDefense adapter does not implement the watchdog-based
# monitor expected by the UI. Keep the UI's feature gate explicit so startup
# can disable this optional feature instead of raising AttributeError.
WATCHDOG_AVAILABLE = False

class WhitelistGuard:
    """Content-hash exemptions shared by GUI and service enforcement paths.

    Never trust a PID, name, cached caller hash, or SYSTEM-profile whitelist.
    Hash the executable resolved from the current process before each action.
    """
    def __init__(self, entries):
        self.replace(entries)

    def replace(self, entries):
        from utils.whitelist import snapshot_identity
        identity = snapshot_identity(entries)
        hashes = frozenset(item['hash'].lower() for item in entries if item.get('hash'))
        self._snapshot = (identity, hashes)
        return identity

    @property
    def snapshot_id(self):
        return self._snapshot[0]

    def allows(self, proc_info):
        try:
            process = psutil.Process(proc_info['pid'])
            expected_created = proc_info.get('create_time')
            if expected_created is None or process.create_time() != expected_created:
                # Do not score or enforce a stale event against a reused PID.
                raise RuntimeError('Process identity changed before whitelist check')
            path = process.exe()
            digest = hashlib.sha256()
            with open(path, 'rb') as stream:
                before = os.fstat(stream.fileno())
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
                after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RuntimeError('Executable changed during whitelist check')
            return digest.hexdigest() in self._snapshot[1]
        except RuntimeError:
            raise
        except Exception as exc:
            log_block(f"Whitelist lookup failed for PID {proc_info.get('pid')}: {exc}")
            # Unverifiable identity is not permission to suspend/terminate.
            raise RuntimeError('Cannot verify process against whitelist') from exc


def _baseline_from_service_args(args):
    """Use only caller's SCM handoff, never LocalSystem profile defaults."""
    from core.defense_control import BASELINE_ARGUMENT, MAX_HANDOFF_BYTES
    from utils.whitelist import snapshot_identity
    if len(args) != 3 or args[1] != BASELINE_ARGUMENT:
        raise ValueError('Explicit whitelist snapshot handoff is required; start through defense_control')
    if len(args[2].encode('utf-8')) > MAX_HANDOFF_BYTES:
        raise ValueError('Whitelist handoff exceeds size limit')
    payload = json.loads(args[2])
    if not isinstance(payload, dict) or payload.get('version') != 1:
        raise ValueError('Unsupported whitelist handoff')
    stamp = payload.get('recorded_at')
    if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or not 0 <= time.time() - stamp <= 3600:
        raise ValueError('Whitelist handoff is expired or has an invalid timestamp')
    entries = payload.get('entries')
    identity = snapshot_identity(entries)
    expected = payload.get('snapshot_id')
    if not isinstance(expected, str) or not hmac.compare_digest(identity, expected):
        raise ValueError('Whitelist handoff identity mismatch')
    return WhitelistGuard(entries)


class ActiveDefense:
    def __init__(self):
        self.running = False
        self.monitor = None
        self.pipeline = None
        self.attribution = None
        self.db_conn = None
        self.whitelist = None

    def start(self, monitor_dirs=None):
        if self.running:
            return
        # GUI intentionally has no hourly recording policy. A readable hashed
        # baseline is still mandatory before any enforcement worker starts.
        self.refresh_whitelist()
        try:
            init_service_environment()
            config = verify_or_create_config()
            self.db_conn = init_db()

            scoring = ScoringEngine(self.db_conn, config, self.whitelist)
            self.attribution = AttributionEngine()

            def handle_event(proc_info):
                if self.whitelist.allows(proc_info):
                    return
                fp = scoring.compute_fingerprint(proc_info)
                cursor = self.db_conn.cursor()
                cursor.execute("SELECT 1 FROM block_rules WHERE fingerprint = ?", (fp,))
                if cursor.fetchone():
                    log_block(f"命中持久化阻断规则！立即终止/拦截新实例 PID {proc_info.get('pid')}")
                    try:
                        process = psutil.Process(proc_info.get('pid'))
                        if process.create_time() != proc_info.get('create_time'):
                            return
                        process.terminate()
                    except Exception:
                        pass
                    return
                scoring.evaluate(proc_info, "system_write")
                try:
                    ad_queue.put_nowait(('file_event', proc_info.get('name'), 'system_write'))
                except queue.Full:
                    pass

            self.pipeline = TwoTierPipeline(handle_event)
            self.monitor = ProcessMonitor(lambda p: self.pipeline.push(0, "created", p))
            self.monitor.start()
            self.running = True
            log_wmi("ActiveDefense 客户端适配层已启动。")
        except Exception:
            # Tear down partially initialized workers before reporting failure.
            self.running = True
            self.stop()
            raise

    def stop(self):
        if not self.running:
            return
        self.running = False
        if self.monitor:
            self.monitor.stop()
        if self.attribution:
            self.attribution.stop()
        if self.pipeline:
            self.pipeline.stop()
        if self.db_conn:
            try:
                self.db_conn.close()
            except Exception:
                pass
        log_wmi("ActiveDefense 已停止。")

    def refresh_whitelist(self):
        from utils.whitelist import load_whitelist
        entries = load_whitelist(strict=True, require_hashes=True)
        if self.whitelist is None:
            self.whitelist = WhitelistGuard(entries)
        else:
            self.whitelist.replace(entries)
        return self.whitelist.snapshot_id


# ---- 模块日志前缀 ----
def log_wmi(msg):
    print(f"[WMI] [{datetime.now().strftime('%H:%M:%S')}] {msg}")

def log_attrib(msg):
    print(f"[归因] [{datetime.now().strftime('%H:%M:%S')}] {msg}")

def log_fingerprint(msg):
    print(f"[指纹] [{datetime.now().strftime('%H:%M:%S')}] {msg}")

def log_block(msg):
    print(f"[阻断] [{datetime.now().strftime('%H:%M:%S')}] {msg}")

def log_queue(msg):
    print(f"[队列] [{datetime.now().strftime('%H:%M:%S')}] {msg}")


# ---- P0: 服务化 + 自身保护 + 目录ACL ----
SERVICE_NAME = "VirusWiseActiveDefense"
SERVICE_DISPLAY_NAME = "VirusWise Active Defense Service"
SERVICE_DESC = "Python-based Active Defense Service without ETW"

PROGRAM_DATA = os.environ.get("ProgramData", "C:\\ProgramData")
SERVICE_DIR = os.path.join(PROGRAM_DATA, "VirusWise")
DATA_DIR = os.path.join(SERVICE_DIR, "data")
QUARANTINE_DIR = os.path.join(SERVICE_DIR, "quarantine")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
DB_FILE = os.path.join(DATA_DIR, "defense.db")
HMAC_KEY = b"VirusWiseSecretMasterKey2026"

def init_service_environment():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    try:
        sd = win32security.SECURITY_DESCRIPTOR()
        sid_system = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
        sid_admin = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)
        
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.GENERIC_ALL, sid_system)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.GENERIC_READ | con.GENERIC_EXECUTE, sid_admin)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        
        win32security.SetFileSecurity(SERVICE_DIR, win32security.DACL_SECURITY_INFORMATION, sd)
    except Exception as e:
        print(f"设置 ACL 异常: {e}")

def check_localsystem():
    try:
        user = win32security.GetUserName()
        if "SYSTEM" not in user.upper():
            print(f"错误: 当前用户为 {user}，必须以 LocalSystem (SYSTEM) 运行！")
            sys.exit(1)
    except Exception as e:
        print(f"校验 LocalSystem 失败: {e}")
        sys.exit(1)


# ---- P5: 配置完整性 + 持久化 ----
def verify_or_create_config():
    os.makedirs(DATA_DIR, exist_ok=True)
    default_config = {
        "weights": {
            "delete": 25,
            "modify": 10,
            "system_write": 30
        },
        "elevated_weight": 1.5,
        "location_weights": {
            "temp": 1.8,
            "downloads": 1.5,
            "recycle": 1.6,
            "normal": 1.0
        }
    }
    
    config_bytes = json.dumps(default_config, sort_keys=True).encode('utf-8')
    signature = hmac.new(HMAC_KEY, config_bytes, hashlib.sha256).hexdigest()
    
    payload = {
        "config": default_config,
        "hmac": signature
    }
    
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
    else:
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            cfg_data = data.get("config")
            stored_hmac = data.get("hmac")
            cfg_bytes = json.dumps(cfg_data, sort_keys=True).encode('utf-8')
            calc_hmac = hmac.new(HMAC_KEY, cfg_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calc_hmac, stored_hmac):
                log_block("核心配置 HMAC 校验失败！配置被篡改，拒绝启动。")
                sys.exit(1)
            return cfg_data
        except Exception as e:
            log_block(f"核心配置解析失败: {e}")
            sys.exit(1)
    return default_config

def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
                        fingerprint TEXT PRIMARY KEY,
                        score REAL,
                        blocked INTEGER,
                        last_updated TIMESTAMP
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS block_rules (
                        fingerprint TEXT PRIMARY KEY,
                        reason TEXT,
                        created_at TIMESTAMP
                    )''')
    conn.commit()
    return conn


# ---- P4: 两级队列与背压 ----
class TwoTierPipeline:
    def __init__(self, worker_callback):
        self.ring_buffer = queue.Queue(maxsize=100000)
        self.high_queue = queue.PriorityQueue(maxsize=10000)
        self.low_queue = queue.Queue(maxsize=10000)
        self.worker_callback = worker_callback
        self.dropped_count = 0
        self.running = True
        
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

    def push(self, priority, event_type, data):
        if self.ring_buffer.full():
            try:
                self.ring_buffer.get_nowait()
                self.dropped_count += 1
            except queue.Empty:
                pass
        try:
            self.ring_buffer.put_nowait((priority, event_type, data))
        except queue.Full:
            self.dropped_count += 1
            return

        if priority == 0:
            try:
                self.high_queue.put_nowait((0, data))
            except queue.Full:
                self.dropped_count += 1
                log_queue("高优先级队列满！")
        else:
            try:
                self.low_queue.put_nowait(data)
            except queue.Full:
                self.dropped_count += 1
                log_queue("低优先级队列满，丢弃低优先级事件。")

    def _worker_loop(self):
        while self.running:
            try:
                if not self.high_queue.empty():
                    _, data = self.high_queue.get(timeout=0.05)
                    self.worker_callback(data)
                    continue
                
                if not self.low_queue.empty():
                    data = self.low_queue.get(timeout=0.05)
                    self.worker_callback(data)
                    continue
                
                time.sleep(0.01)
            except queue.Empty:
                continue
            except Exception as e:
                log_queue(f"Worker 异常: {e}")

    def stop(self):
        self.running = False


# ---- P1: WMI 进程创建监控 + 轮询兜底 ----
class ProcessMonitor:
    def __init__(self, event_callback):
        self.event_callback = event_callback
        self.process_table = {}
        self.lock = threading.Lock()
        self.running = True
        
        self.wmi_thread = threading.Thread(target=self._wmi_listener_loop, daemon=True)
        self.fallback_thread = threading.Thread(target=self._polling_fallback_loop, daemon=True)

    def start(self):
        self.wmi_thread.start()
        self.fallback_thread.start()

    def _wmi_listener_loop(self):
        backoff = 1
        while self.running:
            try:
                pythoncom.CoInitialize()
                icom = win32com.client.Dispatch("WbemScripting.SWbemLocator")
                conn = icom.ConnectServer(".", "root\\cimv2")
                watcher = conn.ExecNotificationQuery("SELECT * FROM Win32_ProcessStartTrace")
                backoff = 1
                
                while self.running:
                    event = watcher.NextEvent(1000)
                    if event:
                        pid = int(event.ProcessID)
                        ppid = int(event.ParentProcessID)
                        name = str(event.ProcessName)
                        
                        threading.Thread(target=self._async_fill_cmdline, args=(pid, ppid, name), daemon=True).start()
            except Exception as e:
                log_wmi(f"WMI 订阅断开或异常: {e}, {backoff}秒后重连...")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
            finally:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    def _async_fill_cmdline(self, pid, ppid, name):
        cmdline = "cmdline_unknown"
        created = None
        try:
            p = psutil.Process(pid)
            created = p.create_time()
            cmdline = " ".join(p.cmdline())
        except Exception:
            pass
        
        proc_info = {
            "pid": pid,
            "create_time": created,
            "ppid": ppid,
            "name": name,
            "cmdline": cmdline,
            "time": datetime.now()
        }
        with self.lock:
            self.process_table[pid] = proc_info
        
        self.event_callback(proc_info)

    def _polling_fallback_loop(self):
        while self.running:
            try:
                current_pids = set(psutil.pids())
                with self.lock:
                    known_pids = set(self.process_table.keys())
                
                missing_pids = current_pids - known_pids
                for pid in missing_pids:
                    try:
                        p = psutil.Process(pid)
                        created = p.create_time()
                        name = p.name()
                        ppid = p.ppid()
                        try:
                            cmdline = " ".join(p.cmdline())
                        except Exception:
                            cmdline = "cmdline_unknown"
                        
                        proc_info = {
                            "pid": pid,
                            "create_time": created,
                            "ppid": ppid,
                            "name": name,
                            "cmdline": cmdline,
                            "time": datetime.now()
                        }
                        with self.lock:
                            self.process_table[pid] = proc_info
                        self.event_callback(proc_info)
                    except Exception:
                        pass
            except Exception as e:
                log_wmi(f"轮询兜底异常: {e}")
            time.sleep(2)

    def stop(self):
        self.running = False


# ---- P2: 缓存式归因（Restart Manager + 句柄快照缓存） ----
class AttributionEngine:
    def __init__(self):
        self.handle_cache = {}
        self.running = True
        self.cache_thread = threading.Thread(target=self._snapshot_loop, daemon=True)
        self.cache_thread.start()

    def _snapshot_loop(self):
        while self.running:
            try:
                new_cache = {}
                for p in psutil.process_iter(attrs=['pid']):
                    try:
                        for f in p.open_files():
                            new_cache[f.path.lower()] = (p.pid, datetime.now())
                    except Exception:
                        pass
                self.handle_cache = new_cache
            except Exception as e:
                log_attrib(f"快照线程异常: {e}")
            time.sleep(2)

    def attribute_event(self, event_type, path):
        if event_type in ["modified", "system_write", "created"]:
            pid = self._query_restart_manager(path)
            if pid:
                log_attrib(f"Restart Manager 成功归因 {path} -> PID {pid}")
                return pid

        lower_path = path.lower()
        if lower_path in self.handle_cache:
            pid, ts = self.handle_cache[lower_path]
            if datetime.now() - ts <= timedelta(seconds=5):
                log_attrib(f"句柄快照缓存命中 {path} -> PID {pid}")
                return pid

        log_attrib(f"无法归因文件路径: {path} (标记为 unknown_operator)")
        return None

    def _query_restart_manager(self, path):
        try:
            return None
        except Exception:
            return None

    def stop(self):
        self.running = False


# ---- P3: 行为级积分 + 滑动窗口 + 动作阶梯 ----
class ScoringEngine:
    def __init__(self, db_conn, config, whitelist=None):
        self.whitelist = whitelist
        self.conn = db_conn
        self.config = config
        self.lock = threading.Lock()

    def compute_fingerprint(self, proc_info):
        path = proc_info.get("name", "unknown")
        cmdline = proc_info.get("cmdline", "")
        norm_cmd = cmdline.replace("\\", "/")
        return hashlib.sha256(f"{path}:{norm_cmd}".encode('utf-8')).hexdigest()[:16]

    def evaluate(self, proc_info, action_type):
        if self.whitelist is None:
            raise RuntimeError("No whitelist loaded; enforcement is disabled")
        if self.whitelist.allows(proc_info):
            return
        fingerprint = self.compute_fingerprint(proc_info)
        weights = self.config.get("weights", {})
        base_score = weights.get(action_type, 10)
        
        elevated_weight = self.config.get("elevated_weight", 1.5) if self._is_elevated(proc_info.get("pid")) else 1.0
        
        path = proc_info.get("name", "").lower()
        loc_weights = self.config.get("location_weights", {})
        loc_w = loc_weights.get("normal", 1.0)
        if "temp" in path or "tmp" in path:
            loc_w = loc_weights.get("temp", 1.8)
        elif "downloads" in path:
            loc_w = loc_weights.get("downloads", 1.5)
        elif "recycler" in path or "$recycle.bin" in path:
            loc_w = loc_weights.get("recycle", 1.6)

        score_increment = base_score * elevated_weight * loc_w
        
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT score FROM fingerprints WHERE fingerprint = ?", (fingerprint,))
            row = cursor.fetchone()
            current_score = row[0] if row else 0.0
            new_score = current_score + score_increment
            
            cursor.execute("INSERT OR REPLACE INTO fingerprints (fingerprint, score, blocked, last_updated) VALUES (?, ?, ?, ?)",
                           (fingerprint, new_score, 1 if new_score >= 80 else 0, datetime.now()))
            self.conn.commit()
            
        log_fingerprint(f"指纹 {fingerprint} 积分累加 +{score_increment:.1f} -> 总分 {new_score:.1f}")
        self.action_ladder(proc_info, new_score, fingerprint)

    def _is_elevated(self, pid):
        try:
            return True 
        except Exception:
            return False

    def action_ladder(self, proc_info, score, fingerprint):
        if score < 20:
            log_block(f"动作 [0-20]: 记录日志。")
        elif score < 50:
            log_block(f"动作 [20-50]: 告警提示。")
        elif score < 80:
            log_block(f"动作 [50-80]: 高优告警 + 标记进程。")
        else:
            log_block(f"动作 [80+]: 触顶阻断！挂起/终止进程，并持久化阻断规则。")
            self.enforce_block(proc_info, fingerprint)

    def enforce_block(self, proc_info, fingerprint):
        if self.whitelist is None:
            raise RuntimeError("No whitelist loaded; enforcement is disabled")
        if self.whitelist.allows(proc_info):
            return
        pid = proc_info.get("pid")
        try:
            p = psutil.Process(pid)
            if p.create_time() != proc_info.get('create_time'):
                return
            p.suspend()
            log_block(f"成功挂起进程 PID {pid}")
        except Exception as e:
            log_block(f"挂起进程 PID {pid} 失败: {e}，执行持久化阻断规则。")
        
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO block_rules (fingerprint, reason, created_at) VALUES (?, ?, ?)",
                           (fingerprint, "Score exceeded 80", datetime.now()))
            self.conn.commit()


# ---- 主防御服务调度器 ----
class VirusWiseService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESC

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.baseline_args = tuple(args)
        self.whitelist = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.is_running = False

    def SvcDoRun(self):
        monitor = attribution = pipeline = db_conn = None
        try:
            check_localsystem()
            # Fail before initializing storage/workers if no valid SCM snapshot
            # was supplied. Never blindly load a LocalSystem profile baseline.
            self.whitelist = _baseline_from_service_args(self.baseline_args)
            init_service_environment()
            config = verify_or_create_config()
            db_conn = init_db()
            
            scoring = ScoringEngine(db_conn, config, self.whitelist)
            attribution = AttributionEngine()
            
            def handle_event(proc_info):
                if self.whitelist.allows(proc_info):
                    return
                fp = scoring.compute_fingerprint(proc_info)
                cursor = db_conn.cursor()
                cursor.execute("SELECT 1 FROM block_rules WHERE fingerprint = ?", (fp,))
                if cursor.fetchone():
                    log_block(f"命中持久化阻断规则！立即终止/拦截新实例 PID {proc_info.get('pid')}")
                    try:
                        process = psutil.Process(proc_info.get('pid'))
                        if process.create_time() != proc_info.get('create_time'):
                            return
                        process.terminate()
                    except Exception:
                        pass
                    return
                
                scoring.evaluate(proc_info, "system_write")

            pipeline = TwoTierPipeline(handle_event)
            monitor = ProcessMonitor(lambda p: pipeline.push(0, "created", p))
            monitor.start()

            log_wmi("VirusWise 安全服务已成功以 LocalSystem 运行，防御核心已启动。")

            while self.is_running:
                rc = win32event.WaitForSingleObject(self.stop_event, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break

        except Exception:
            # Invalid handoff may precede directory initialization. Do not create
            # profile storage just to log, and do not leave enforcement workers.
            try:
                servicemanager.LogErrorMsg(traceback.format_exc())
            except Exception:
                pass
            raise
        finally:
            self.is_running = False
            for worker in (monitor, attribution, pipeline):
                if worker is not None:
                    worker.stop()
            if db_conn is not None:
                db_conn.close()


if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(VirusWiseService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(VirusWiseService)
