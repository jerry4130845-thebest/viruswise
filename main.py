import os, sys, ctypes, requests, copy, hashlib, threading, zipfile, mmap, subprocess, time, queue, json, psutil, pickle, traceback, random, struct
from datetime import datetime
from types import SimpleNamespace
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from ctypes import wintypes
from utils.config import load_config, save_config
from utils.whitelist import load_whitelist, save_whitelist
from utils.hash import get_file_hash
from utils.quarantine import quarantine
from utils.risk import RISK_LEVEL_1, RISK_LEVEL_2, SYSTEM_CRITICAL_PATHS, SYSTEM_PROCESSES, get_risk_level
from utils.signature import check_digital_signature
from utils.network import is_offline
from utils.fake_log import is_fake_log
from utils.logging import main_log, scan_log, update_progress
from core.notifier import notifier

CRASH_LOG = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "crash.log")

def setup_exception_handler():
    def global_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        tb_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        try:
            with open(CRASH_LOG, 'w', encoding='utf-8') as f:
                f.write(f"[{datetime.now()}] Unhandled Exception:\n{tb_text}")
        except:
            pass
        try:
            messagebox.showerror("程序崩溃", f"启动失败，日志已保存至:\n{CRASH_LOG}\n\n{tb_text[:600]}")
        except:
            print("CRASH LOG SAVED TO:", CRASH_LOG)
            print(tb_text)
        sys.exit(1)
    sys.excepthook = global_handler
setup_exception_handler()

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

def safe_get_base_dir():
    return os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__))

try:
    from utils.paths import BASE_DIR, DATA_DIR, QUARANTINE_DIR, WHITELIST_FILE, PROFILES_DIR, CONFIG_FILE, THEME_WARM_YELLOW, CRASH_LOG
    os.chdir(BASE_DIR)
    DATA_DIR = os.path.join(BASE_DIR, "data")
    QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
    WHITELIST_FILE = os.path.join(DATA_DIR, "whitelist.json")
    PROFILES_DIR = os.path.join(DATA_DIR, "profiles")
    CONFIG_FILE = os.path.join(DATA_DIR, "config.txt")
    THEME_WARM_YELLOW = os.path.join(DATA_DIR, "warm_yellow.json")
    for dir_path in [DATA_DIR, QUARANTINE_DIR, PROFILES_DIR]:
        os.makedirs(dir_path, exist_ok=True)
except Exception as e:
    print(f"初始化目录失败: {e}")
    sys.exit(1)

WARM_YELLOW_THEME_JSON = r'''{
  "CTk": {"fg_color": ["#1a1a1a", "#1a1a1a"]},
  "CTkButton": {"fg_color": ["#E67E22", "#D35400"], "hover_color": ["#F39C12", "#E67E22"], "border_color": ["#E67E22", "#D35400"], "text_color": ["#FFFFFF", "#FFFFFF"], "text_color_disabled": ["#7F7F7F", "#7F7F7F"]},
  "CTkLabel": {"text_color": ["#FFFFFF", "#FFFFFF"], "fg_color": "transparent"},
  "CTkEntry": {"fg_color": ["#3A3A3A", "#3A3A3A"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "placeholder_text_color": ["#7F7F7F", "#7F7F7F"]},
  "CTkCheckBox": {"fg_color": ["#E67E22", "#D35400"], "border_color": ["#8A8A8A", "#8A8A8A"], "hover_color": ["#F39C12", "#E67E22"], "text_color": ["#FFFFFF", "#FFFFFF"], "checkmark_color": ["#FFFFFF", "#FFFFFF"]},
  "CTkComboBox": {"fg_color": ["#3A3A3A", "#3A3A3A"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "button_color": ["#E67E22", "#D35400"], "button_hover_color": ["#F39C12", "#E67E22"], "dropdown_fg_color": ["#2E2E2E", "#2E2E2E"], "dropdown_hover_color": ["#3A3A3A", "#3A3A3A"], "dropdown_text_color": ["#FFFFFF", "#FFFFFF"]},
  "CTkFrame": {"fg_color": ["#2E2E2E", "#2E2E2E"], "border_color": ["#5E5E5E", "#5E5E5E"], "top_fg_color": ["#2E2E2E", "#2E2E2E"], "border_width": 0},
  "CTkProgressBar": {"fg_color": ["#5D4037", "#5D4037"], "progress_color": ["#E67E22", "#D35400"], "border_color": ["#5E5E5E", "#5E5E5E"]},
  "CTkScrollableFrame": {"fg_color": ["#1e1e1e", "#1e1e1e"], "border_color": ["#5E5E5E", "#5E5E5E"], "label_fg_color": ["#2E2E2E", "#2E2E2E"], "label_text_color": ["#FFFFFF", "#FFFFFF"]},
  "CTkScrollbar": {"fg_color": ["#2E2E2E", "#2E2E2E"], "button_color": ["#5E5E5E", "#5E5E5E"], "button_hover_color": ["#7A7A7A", "#7A7A7A"]},
  "CTkTextbox": {"fg_color": ["#1a1a1a", "#1a1a1a"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "scrollbar_button_color": ["#5E5E5E", "#5E5E5E"], "scrollbar_button_hover_color": ["#7A7A7A", "#7A7A7A"]},
  "CTkOptionMenu": {"fg_color": ["#3A3A3A", "#3A3A3A"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "button_color": ["#E67E22", "#D35400"], "button_hover_color": ["#F39C12", "#E67E22"]},
  "CTkSlider": {"fg_color": ["#5E5E5E", "#5E5E5E"], "progress_color": ["#E67E22", "#D35400"], "button_color": ["#E67E22", "#D35400"], "button_hover_color": ["#F39C12", "#E67E22"]},
  "CTkSwitch": {"fg_color": ["#5E5E5E", "#5E5E5E"], "progress_color": ["#E67E22", "#D35400"], "button_color": ["#FFFFFF", "#FFFFFF"], "button_hover_color": ["#F39C12", "#E67E22"]},
  "CTkTabview": {"fg_color": ["#2E2E2E", "#2E2E2E"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "segmented_button_fg_color": ["#3A3A3A", "#3A3A3A"], "segmented_button_selected_color": ["#E67E22", "#D35400"], "segmented_button_unselected_color": ["#3A3A3A", "#3A3A3A"], "segmented_button_hover_color": ["#F39C12", "#E67E22"]}
}'''

with open(THEME_WARM_YELLOW, 'w', encoding='utf-8') as f:
    f.write(WARM_YELLOW_THEME_JSON)

API_KEY = ""
BASE_URL = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_SIZE = 30 * 1024 * 1024
alerted_processes = set()
alert_lock = threading.Lock()
TEMPORARY_ALLOWED = set()
ad_queue = queue.Queue()
danger_files = []
file_checkbuttons = []
SUSPENDED_PROCS = {}
suspended_lock = threading.Lock()
ACTIVE_DEFENSE_ENABLED = False
MONITOR_DIRS = []

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    try:
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        if ret <= 32: print(f"提权失败 (Error: {ret})")
        else: sys.exit(0)
    except Exception as e:
        print(f"提权调用异常: {e}")
        sys.exit(0)

THEME_PRESETS = {
    'default': ("dark", "blue"),
    '绿色 (暗绿)': ("dark", "green"),
    '深色暖黄': ("dark", THEME_WARM_YELLOW),
    '浅色蓝': ("light", "blue"),
    '浅色绿': ("light", "green"),
}

def apply_startup_theme(theme_name):
    if theme_name in THEME_PRESETS: mode, color_theme = THEME_PRESETS[theme_name]
    else: mode, color_theme = "dark", "blue"
    try:
        ctk.set_appearance_mode(mode)
        if isinstance(color_theme, str) and os.path.exists(color_theme):
            ctk.set_default_color_theme("blue")
            with open(color_theme, 'r', encoding='utf-8') as f:
                custom_theme = json.load(f)
            merged_theme = copy.deepcopy(ctk.ThemeManager.theme)
            for key, value in custom_theme.items():
                if key in merged_theme: merged_theme[key].update(value)
                else: merged_theme[key] = value
            ctk.ThemeManager.theme = merged_theme
        else:
            ctk.set_default_color_theme(color_theme)
    except Exception as e:
        print(f"主题加载失败: {e}，回退到默认暗蓝")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

def collect_files(path):
    if os.path.isfile(path): return [path]
    result = []
    for r, _, fs in os.walk(path):
        for f in fs:
            result.append(os.path.join(r, f))
    return result

class DefenderScanner:
    name = "Windows Defender"
    def __init__(self, offline_only=True, force_use=False):
        self.available = False
        self.offline_only = offline_only
        self.force_use = force_use
        self.mpcmdrun_path = os.path.join(
            os.environ.get('ProgramFiles', 'C:\\Program Files'),
            'Windows Defender', 'MpCmdRun.exe'
        )
        self._check_available()

    def _check_available(self):
        if os.path.exists(self.mpcmdrun_path):
            self.available = True
            main_log("Windows Defender (MpCmdRun) 可用")
        else:
            self.available = False
            main_log(f"找不到 MpCmdRun.exe: {self.mpcmdrun_path}")

    def should_use(self):
        if not self.available:
            return False
        if self.force_use:
            return True
        if self.offline_only:
            return is_offline()
        return True

    def full_scan(self):
        threats = []
        try:
            main_log("正在启动 Windows Defender 全盘扫描，请耐心等待...")
            result = subprocess.run(
                [self.mpcmdrun_path, '-Scan', '-ScanType', '2'],
                capture_output=True, text=True, timeout=7200,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = result.stdout + result.stderr
            main_log(f"Defender 扫描完成，返回码: {result.returncode}")
            
            for line in output.split('\n'):
                line_stripped = line.strip()
                if 'Threat' in line_stripped and ':' in line_stripped:
                    parts = line_stripped.split(':', 1)
                    if len(parts) == 2 and parts[1].strip():
                        threats.append({'name': parts[1].strip(), 'path': '全盘扫描'})
            
            if not threats:
                main_log("未发现威胁")
            else:
                main_log(f"全盘扫描发现 {len(threats)} 个威胁")
        except subprocess.TimeoutExpired:
            main_log("全盘扫描超时")
        except Exception as e:
            main_log(f"全盘扫描出错: {e}")
        return threats

    def scan_drive(self, drive):
        threats = []
        try:
            main_log(f"正在扫描 {drive} ...")
            result = subprocess.run(
                [self.mpcmdrun_path, '-Scan', '-ScanType', '3', '-File', drive],
                capture_output=True, text=True, timeout=7200,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = result.stdout + result.stderr
            
            for line in output.split('\n'):
                line_stripped = line.strip()
                if 'Threat' in line_stripped and ':' in line_stripped:
                    parts = line_stripped.split(':', 1)
                    if len(parts) == 2 and parts[1].strip():
                        threats.append({'name': parts[1].strip(), 'path': drive})
        except subprocess.TimeoutExpired:
            main_log(f"扫描 {drive} 超时")
        except Exception as e:
            main_log(f"扫描 {drive} 出错: {e}")
        return threats
    
class ProcessProfiler:
    def __init__(self):
        self.profiles = {}
        self.load_profiles()

    def get_profile_path(self, name):
        safe = name.replace('/', '').replace('\\', '').replace(':', '_')
        return os.path.join(PROFILES_DIR, f"{safe}.pkl")

    def load_profiles(self):
        if not os.path.exists(PROFILES_DIR): return
        for f in os.listdir(PROFILES_DIR):
            if f.endswith('.pkl'):
                try:
                    with open(os.path.join(PROFILES_DIR, f), 'rb') as pf:
                        prof = pickle.load(pf)
                        self.profiles[prof['name']] = prof
                except: pass

class ProcessAnalyzer:
    def __init__(self):
        self.profiler = ProcessProfiler()
        self.config = load_config()

    def calculate_risk(self, monitor):
        score = 0
        if self.config['delete_protection'] and hasattr(monitor, 'delete_count'):
            if monitor.delete_count >= self.config['batch_delete_threshold']: score += 0.6
        if hasattr(monitor, 'deleted_files'):
            risk2 = sum(1 for f in monitor.deleted_files if get_risk_level(f) == 2)
            score += min(0.5, risk2 * 0.1)
        if hasattr(monitor, 'system_writes'):
            risk2 = sum(1 for w in monitor.system_writes if get_risk_level(w) == 2)
            score += min(0.4, risk2 * 0.1)
        return score

class TrustedPublishers:
    STRONG_TRUSTED = {
        'microsoft corporation', 'google llc', 'adobe inc', 'jetbrains',
        'apple inc', 'github', 'mozilla corporation', 'oracle corporation',
        'amazon.com inc', 'intel corporation', 'nvidia corporation',
        'vmware inc', 'citrix systems', 'wireshark foundation',
        'blender foundation', 'gimp development team', 'vlc media player',
        'canonical ltd', 'fedora project', 'red hat', 'suse',
        'arista networks', 'broadcom', 'cisco systems',
    }

class ProcessBehavior:
    def __init__(self, pid, name, exe):
        self.pid = pid
        self.name = name
        self.exe = exe
        self.start_time = time.time()
        self.last_score_update = time.time()
        self.appdata_writes = []
        self.programdata_writes = []
        self.system32_writes = []
        self.temp_writes = []
        self.exe_dll_writes = []
        self.fake_log_writes = []
        self.normal_log_writes = []
        self.child_processes = []
        self.process_injections = []
        self.api_hooks = []
        self.remote_thread_injections = []
        self.https_requests = []
        self.suspicious_ip_requests = []
        self.encrypted_communications = []
        self.c2_behaviors = []
        self.startup_registrations = []
        self.service_creations = []
        self.registry_writes = []
        self.self_extraction = False
        self.persistence_behavior = False
        self.signature_valid = None
        self.publisher = None
        self.signature_forged = False

class ScoringEngine:
    def __init__(self):
        self.trusted_publishers = TrustedPublishers()
        self.high_risk_dirs = {'C:\\Windows\\System32': True, 'C:\\Windows\\SysWOW64': True, 'C:\\Windows\\System32\\drivers': True}

    def calculate_total_score(self, behavior):
        score = 0
        triggered_rules = []
        sig_score, sig_rules = self._calculate_signature_score(behavior)
        score += sig_score; triggered_rules.extend(sig_rules)
        write_score, write_rules = self._calculate_file_write_score(behavior)
        score += write_score; triggered_rules.extend(write_rules)
        proc_score, proc_rules = self._calculate_process_behavior_score(behavior)
        score += proc_score; triggered_rules.extend(proc_rules)
        net_score, net_rules = self._calculate_network_behavior_score(behavior)
        score += net_score; triggered_rules.extend(net_rules)
        other_score, other_rules = self._calculate_other_behavior_score(behavior)
        score += other_score; triggered_rules.extend(other_rules)
        combo_score, combo_rules = self._calculate_combination_rules(behavior)
        if combo_score > score:
            score = combo_score; triggered_rules = combo_rules
        return score, triggered_rules

    def _calculate_signature_score(self, behavior):
        score = 0; rules = []
        if behavior.signature_forged:
            score += 80; rules.append("签名伪造/异常+80")
            return score, rules
        if behavior.signature_valid is None:
            behavior.signature_valid = self._check_signature(behavior.exe)
        if behavior.signature_valid:
            if behavior.publisher and behavior.publisher.lower() in self.trusted_publishers.STRONG_TRUSTED:
                score -= 40; rules.append("强可信签名-40")
            else:
                score -= 15; rules.append("有效数字签名(未知厂商)-15")
        else:
            score += 40; rules.append("无签名+40")
        return score, rules

    def _calculate_file_write_score(self, behavior):
        score = 0; rules = []
        if behavior.appdata_writes:
            score += 5 * len(behavior.appdata_writes); rules.append(f"写AppData+5x{len(behavior.appdata_writes)}")
        if behavior.programdata_writes:
            score += 10 * len(behavior.programdata_writes); rules.append(f"写ProgramData+10x{len(behavior.programdata_writes)}")
        if behavior.system32_writes:
            score += 15 * len(behavior.system32_writes); rules.append(f"写System32+15x{len(behavior.system32_writes)}")
        if behavior.temp_writes:
            score += 1 * len(behavior.temp_writes); rules.append(f"写Temp+1x{len(behavior.temp_writes)}")
        if behavior.exe_dll_writes:
            score += 50 * len(behavior.exe_dll_writes); rules.append(f"写EXE/DLL+50x{len(behavior.exe_dll_writes)}")
        if behavior.fake_log_writes:
            score += 30 * len(behavior.fake_log_writes); rules.append(f"写伪日志文件+30x{len(behavior.fake_log_writes)}")
        return score, rules

    def _calculate_process_behavior_score(self, behavior):
        score = 0; rules = []
        if behavior.child_processes:
            score += 10 * len(behavior.child_processes); rules.append(f"创建子进程+10x{len(behavior.child_processes)}")
        if behavior.process_injections:
            score += 60 * len(behavior.process_injections); rules.append(f"注入其他进程+60x{len(behavior.process_injections)}")
        if behavior.api_hooks:
            score += 50 * len(behavior.api_hooks); rules.append(f"Hook API+50x{len(behavior.api_hooks)}")
        if behavior.remote_thread_injections:
            score += 80 * len(behavior.remote_thread_injections); rules.append(f"远程线程注入+80x{len(behavior.remote_thread_injections)}")
        return score, rules

    def _calculate_network_behavior_score(self, behavior):
        score = 0; rules = []
        if behavior.suspicious_ip_requests:
            score += 40 * len(behavior.suspicious_ip_requests); rules.append(f"可疑IP通信+40x{len(behavior.suspicious_ip_requests)}")
        if behavior.encrypted_communications:
            score += 50 * len(behavior.encrypted_communications); rules.append(f"加密通信+非标准端口+50x{len(behavior.encrypted_communications)}")
        if behavior.c2_behaviors:
            score += 90 * len(behavior.c2_behaviors); rules.append(f"C2行为特征+90x{len(behavior.c2_behaviors)}")
        return score, rules

    def _calculate_other_behavior_score(self, behavior):
        score = 0; rules = []
        if behavior.startup_registrations:
            score += 15 * len(behavior.startup_registrations); rules.append(f"启动项注册+15x{len(behavior.startup_registrations)}")
        if behavior.service_creations:
            score += 15 * len(behavior.service_creations); rules.append(f"创建服务+15x{len(behavior.service_creations)}")
        if behavior.registry_writes:
            score += 30 * len(behavior.registry_writes); rules.append(f"写入注册表Run键+30x{len(behavior.registry_writes)}")
        if behavior.self_extraction and behavior.persistence_behavior:
            score += 70; rules.append("自解压+持久化+70")
        return score, rules

    def _calculate_combination_rules(self, behavior):
        if not behavior.signature_valid and behavior.system32_writes:
            return 50, ["无签名+写System32+50"]
        if not behavior.signature_valid and behavior.process_injections:
            return 80, ["无签名+注入进程+80"]
        if behavior.system32_writes and behavior.startup_registrations:
            return 60, ["写System32+启动项+60"]
        return 0, []

    def _check_signature(self, exe_path):
        try:
            ps_command = f"""
$file = '{exe_path}'
if (Test-Path $file) {{
    $sig = Get-AuthenticodeSignature $file
    if ($sig.Status -eq 'Valid') {{ Write-Output "Valid" }}
    else {{ Write-Output "Invalid" }}
}} else {{ Write-Output "NotFound" }}
"""
            result = subprocess.run(['powershell', '-Command', ps_command],
                                  capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            return result.stdout.strip() == "Valid"
        except: return False

class ProcessScoreTracker:
    def __init__(self):
        self.process_scores = {}
        self.scoring_engine = ScoringEngine()
        self.score_decay_rate = 2
        self.alert_threshold = 60
        self.kill_threshold = 120
        self.score_lock = threading.Lock()

    def add_or_update_process(self, pid, name, exe):
        with self.score_lock:
            if pid not in self.process_scores:
                behavior = ProcessBehavior(pid, name, exe)
                self.process_scores[pid] = {'behavior': behavior, 'score': 0, 'last_update': time.time(), 'alerted': False, 'triggered_rules': []}
            return self.process_scores[pid]

    def get_process_score(self, pid):
        with self.score_lock:
            if pid not in self.process_scores: return 0, []
            record = self.process_scores[pid]
            decayed = max(0, record['score'] - self.score_decay_rate * (time.time() - record['last_update']))
            return decayed, record['triggered_rules']

    def update_process_score(self, pid, name, exe):
        with self.score_lock:
            if pid not in self.process_scores:
                self.add_or_update_process(pid, name, exe)
            record = self.process_scores[pid]
            new_score, triggered_rules = self.scoring_engine.calculate_total_score(record['behavior'])
            record['score'] = new_score
            record['last_update'] = time.time()
            record['triggered_rules'] = triggered_rules
            return new_score, triggered_rules

    def record_file_write(self, pid, file_path):
        with self.score_lock:
            if pid not in self.process_scores: return
            behavior = self.process_scores[pid]['behavior']
            fl = file_path.lower()
            if 'appdata' in fl: behavior.appdata_writes.append(file_path)
            elif 'programdata' in fl: behavior.programdata_writes.append(file_path)
            elif 'system32' in fl or 'syswow64' in fl: behavior.system32_writes.append(file_path)
            elif 'temp' in fl or 'cache' in fl: behavior.temp_writes.append(file_path)
            elif fl.endswith(('.exe', '.dll')): behavior.exe_dll_writes.append(file_path)

    def record_log_write(self, pid, file_path, is_fake):
        with self.score_lock:
            if pid not in self.process_scores: return
            behavior = self.process_scores[pid]['behavior']
            if is_fake: behavior.fake_log_writes.append(file_path)
            else: behavior.normal_log_writes.append(file_path)

    def record_process_injection(self, pid, target_pid):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].process_injections.append(target_pid)

    def record_remote_thread_injection(self, pid, target_pid):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].remote_thread_injections.append(target_pid)

    def record_child_process(self, pid, child_pid, child_name):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].child_processes.append({'pid': child_pid, 'name': child_name})

    def record_startup_registration(self, pid, registry_path):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].startup_registrations.append(registry_path)

    def record_service_creation(self, pid, service_name):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].service_creations.append(service_name)

    def record_suspicious_network(self, pid, ip_address):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].suspicious_ip_requests.append(ip_address)

    def record_c2_behavior(self, pid, behavior_desc):
        with self.score_lock:
            if pid not in self.process_scores: return
            self.process_scores[pid]['behavior'].c2_behaviors.append(behavior_desc)

    def remove_process(self, pid):
        with self.score_lock:
            if pid in self.process_scores: del self.process_scores[pid]

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

def handle_system_write(self, path):
    file_lower = path.lower()
    with self.monitored_lock:
        monitored_copy = list(self.monitored.items())
    suspect_pids = self._find_file_operator(path, monitored_copy)

    if not suspect_pids:
        risk_lvl = get_risk_level(path)
        if risk_lvl == 3 and ('log' in file_lower or file_lower.endswith(('.txt', '.dat'))):
            if not is_fake_log(path):
                return
        if risk_lvl == 3:
            return
        main_log(f"[系统写入检测] 检测到系统目录写入但无法确定进程来源: {os.path.basename(path)} "
                 f"(风险等级:{risk_lvl})")
        return

    for pid in suspect_pids:
        if pid not in dict(monitored_copy):
            continue
        mon = dict(monitored_copy)[pid]
        if pid in TEMPORARY_ALLOWED or not psutil.pid_exists(pid):
            continue
        if self._is_whitelisted(pid=pid, name=mon.name, exe=mon.exe):
            continue
        risk_lvl = get_risk_level(path)
        if risk_lvl == 1:
            main_log(f"[高风险系统目录写入] {mon.name} 写入: {path}")
            self.score_tracker.record_file_write(pid, path)
            self._block_risk1(pid, mon, path, "写入")
        elif risk_lvl == 2:
            if not hasattr(mon, 'system_writes'):
                mon.system_writes = []
            if len(mon.system_writes) < 10:
                mon.system_writes.append(path)
            self.score_tracker.record_file_write(pid, path)
            main_log(f"[低危写入记录] {mon.name} 写入敏感目录: {os.path.basename(path)}")
        elif 'log' in file_lower and (file_lower.endswith(('.log', '.log1', '.txt', '.dat')) or '.log' in file_lower):
            if is_fake_log(path):
                main_log(f"[伪日志检测] {mon.name} 写入伪日志: {os.path.basename(path)}")
                self.score_tracker.record_log_write(pid, path, True)
            else:
                self.score_tracker.record_log_write(pid, path, False)
    def _block_risk1(self, pid, mon, path, op):
        try:
            psutil.Process(pid).suspend()
            notifier.send("病毒和威胁防护", f"已阻止 {mon.name} {op} {os.path.basename(path)}", 8)
            main_log(f"已阻止一级风险: {mon.name} 尝试 {op} {path}")
            with suspended_lock:
                SUSPENDED_PROCS[pid] = {'pid': pid, 'name': mon.name, 'exe': mon.exe,
                                        'reason': f"一级风险拦截 ({op})"}
        except Exception as e:
            main_log(f"阻止/挂起失败: {mon.name} - {e}")

    def _trigger_alert(self, pid, mon, reason):
        global alerted_processes
        with alert_lock:
            if pid in alerted_processes:
                return
            alerted_processes.add(pid)
            try:
                psutil.Process(pid).suspend()
                main_log(f"挂起可疑进程: {mon.name} ({reason})")
                with suspended_lock:
                    SUSPENDED_PROCS[pid] = {'pid': pid, 'name': mon.name, 'exe': mon.exe, 'reason': reason}
                ad_queue.put(('alert', {
                    'pid': pid, 'name': mon.name, 'exe': mon.exe, 'risk_score': 0.6,
                    'delete_count': getattr(mon, 'delete_count', 0),
                    'modify_count': getattr(mon, 'modify_count', 0),
                    'system_writes': getattr(mon, 'system_writes', []),
                    'deleted_files': getattr(mon, 'deleted_files', [])
                }))
            except Exception as e:
                main_log(f"触发告警失败: {e}")

    def _trigger_protection_alert(self, pid, mon, path, operation):
        global alerted_processes
        with alert_lock:
            if pid != 0 and pid in alerted_processes:
                return
            if pid != 0:
                alerted_processes.add(pid)
        try:
            main_log(f"[保护触发] {mon.name if mon else '未知'} 尝试{operation}: {path}")
            ad_queue.put(('protection_alert', {
                'pid': pid, 'name': mon.name if mon else '未知进程',
                'exe': getattr(mon, 'exe', '未知'), 'operation': operation, 'path': path,
                'risk_level': get_risk_level(path),
                'delete_count': len(getattr(mon, 'deleted_files_set', set())),
                'modify_count': len(getattr(mon, 'modified_files', set())),
                'system_writes': getattr(mon, 'system_writes', []),
                'deleted_files': getattr(mon, 'deleted_files', [])
            }))
        except Exception as e:
            main_log(f"触发保护警报失败: {e}")

    def _monitor_loop(self):
        refresh_counter = 0
        score_check_counter = 0
        while self.running:
            refresh_counter += 1
            score_check_counter += 1
            if refresh_counter % 15 == 0:
                self.refresh_whitelist()
            current = set()
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
                try:
                    pid = proc.info['pid']
                    if proc.info['name'].lower() in SYSTEM_PROCESSES:
                        continue
                    if pid not in self.known and pid not in self.monitored and pid not in TEMPORARY_ALLOWED:
                        self._add_process(proc)
                    current.add(pid)
                except:
                    continue
            for pid in list(self.known):
                if pid not in current:
                    del self.known[pid]
            to_remove = []
            if score_check_counter >= 1:
                score_check_counter = 0
                with self.monitored_lock:
                    monitored_copy = list(self.monitored.items())
                for pid, mon in monitored_copy:
                    if not psutil.pid_exists(pid):
                        to_remove.append(pid)
                        self.score_tracker.remove_process(pid)
                        continue
                    if self._is_whitelisted(pid=pid, name=mon.name, exe=mon.exe):
                        to_remove.append(pid)
                        self.score_tracker.remove_process(pid)
                        continue
                    score, rules = self.score_tracker.update_process_score(pid, mon.name, mon.exe)
                    if score >= 120:
                        main_log(f"[积分报毒] {mon.name} 积分达到{score:.0f}分，直接挂起+报毒")
                        self._trigger_viral_alert(pid, mon, score, rules)
                        to_remove.append(pid)
                        self.score_tracker.remove_process(pid)
                    elif score >= 60 and not self.score_tracker.process_scores[pid]['alerted']:
                        self.score_tracker.process_scores[pid]['alerted'] = True
                        ad_queue.put(('scoring_alert', {
                            'pid': pid, 'name': mon.name, 'exe': mon.exe,
                            'score': score, 'rules': rules,
                            'behavior': self.score_tracker.process_scores[pid]['behavior']
                        }))
            for pid in to_remove:
                with self.monitored_lock:
                    self.monitored.pop(pid, None)
                with alert_lock:
                    alerted_processes.discard(pid)
            time.sleep(1)

    def _trigger_viral_alert(self, pid, mon, score, rules):
        global alerted_processes
        with alert_lock:
            if pid in alerted_processes:
                return
            alerted_processes.add(pid)
            try:
                psutil.Process(pid).suspend()
                main_log(f"[报毒] 挂起恶意进程: {mon.name} (积分: {score:.0f})")
                with suspended_lock:
                    SUSPENDED_PROCS[pid] = {'pid': pid, 'name': mon.name, 'exe': mon.exe,
                                            'reason': f"积分报毒 (积分: {score:.0f})"}
                ad_queue.put(('viral_alert', {'pid': pid, 'name': mon.name, 'exe': mon.exe,
                                              'score': score, 'rules': rules}))
            except Exception as e:
                main_log(f"报毒处理失败: {e}")

    def _add_process(self, proc):
        try:
            pid, name, exe = proc.info['pid'], proc.info['name'], proc.info['exe']
            if self._is_whitelisted(pid=pid, name=name, exe=exe):
                self.known[pid] = {'whitelisted': True}
                return
            if not exe:
                return
            mon = SimpleNamespace()
            mon.pid = pid
            mon.name = name
            mon.exe = exe
            mon.start = time.time()
            mon.delete_count = 0
            mon.modify_count = 0
            mon.deleted_files = []
            mon.system_writes = []
            mon.deleted_files_set = set()
            mon.modified_files = set()
            with self.monitored_lock:
                self.monitored[pid] = mon
            self.score_tracker.add_or_update_process(pid, name, exe)
            main_log(f"监控新进程: {name} (积分系统)")
        except Exception as e:
            main_log(f"监控进程失败: {e}")

    def _monitor_startup_and_services(self):
        import winreg
        known_startups = set()
        known_services = set()
        startup_silence_time = 30
        startup_time = time.time()
        check_interval = 10
        last_check_time = 0

        while self.running:
            current_time = time.time()
            if current_time - last_check_time < check_interval:
                time.sleep(min(5, check_interval - (current_time - last_check_time)))
                continue

            last_check_time = current_time
            try:
                startup_paths = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                ]
                should_notify = (time.time() - startup_time) > startup_silence_time

                for hive, path in startup_paths:
                    try:
                        with winreg.OpenKey(hive, path) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    startup_key = f"{path}\\{name}"
                                    if startup_key not in known_startups:
                                        known_startups.add(startup_key)
                                        if should_notify:
                                            for pid, rec in list(self.score_tracker.process_scores.items()):
                                                try:
                                                    if psutil.pid_exists(pid):
                                                        self.score_tracker.record_startup_registration(pid, startup_key)
                                                        notifier.send("主动防御", f"检测到{rec['behavior'].name}注册开机自启动", 5)
                                                except:
                                                    pass
                                    i += 1
                                except OSError:
                                    break
                    except:
                        pass

                try:
                    result = subprocess.run(['wmic', 'service', 'list', 'brief'],
                                            capture_output=True, text=True, timeout=5,
                                            creationflags=subprocess.CREATE_NO_WINDOW)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n')[1:]:
                            if line.strip():
                                try:
                                    parts = line.split()
                                    if parts:
                                        sname = parts[0]
                                        if sname not in known_services:
                                            known_services.add(sname)
                                            if should_notify:
                                                for pid, rec in list(self.score_tracker.process_scores.items()):
                                                    try:
                                                        if psutil.pid_exists(pid):
                                                            self.score_tracker.record_service_creation(pid, sname)
                                                    except:
                                                        pass
                                except:
                                    pass
                except:
                    pass
            except Exception as e:
                main_log(f"启动项/服务监控异常: {e}")

def record_processes_for_30_seconds():
    global ACTIVE_DEFENSE_ENABLED, MONITOR_DIRS
    ad_was_running = False
    if hasattr(sys, 'app') and sys.app and sys.app.ad and sys.app.ad.running:
        ad_was_running = True
        sys.app.ad.stop()
    main_log("主动防御已暂停，开始记录白名单...")
    popup = ctk.CTkToplevel(sys.app)
    popup.title("白名单记录中")
    popup.geometry("300x150")
    popup.attributes("-topmost", True)
    ctk.CTkLabel(popup, text="正在记录进程到白名单\n持续时间: 30秒\n主动防御已暂停", font=("Arial", 12)).pack(pady=20)
    popup.update()

    def record():
        whitelist = load_whitelist()
        existing = {item.get('hash') for item in whitelist if item.get('hash')}
        count = 0
        recorded = set()
        for _ in range(30):
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        pid = proc.info['pid']
                        if pid in recorded: continue
                        name, exe = proc.info['name'], proc.info['exe']
                        if name.lower() in SYSTEM_PROCESSES: recorded.add(pid); continue
                        if exe and os.path.exists(exe):
                            try:
                                with open(exe, 'rb') as f: h = hashlib.sha256(f.read()).hexdigest()
                                if h not in existing:
                                    whitelist.append({'name': name, 'pid': pid, 'path': exe, 'hash': h, 'time': time.time()})
                                    existing.add(h); recorded.add(pid); count += 1
                            except: pass
                    except: pass
            except: pass
            time.sleep(1)
        save_whitelist(whitelist)
        if ad_was_running and ACTIVE_DEFENSE_ENABLED and WATCHDOG_AVAILABLE and hasattr(sys, 'app') and sys.app:
            try:
                sys.app.ad = ActiveDefense()
                sys.app.ad.start(MONITOR_DIRS)
                main_log(f"30秒记录完成，共添加 {count} 个新进程到白名单，主动防御已恢复")
            except Exception as e:
                main_log(f"主动防御恢复失败: {e}")
        else:
            main_log(f"30秒记录完成，共添加 {count} 个新进程到白名单")
        try:
            popup.after(0, popup.destroy)
        except RuntimeError:
            pass
        except:
            pass
    threading.Thread(target=record, daemon=True).start()

class VirusWiseApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        sys.app = self
        self.title("VirusWise 2.6.6+")
        self.geometry("900x650")
        self.minsize(900, 650)

        self.config = load_config()
        global API_KEY, ACTIVE_DEFENSE_ENABLED, MONITOR_DIRS
        API_KEY = self.config.get('apikey', '').strip()

        theme = self.config.get('theme', 'default')
        apply_startup_theme(theme)

        self.danger_files = []
        self.file_checkbuttons = []
        self.ad = None
        self.scanning = False
        self.ad_restarting = False
        self.alert_cooldown = {}
        self._rick_cleanup_done = False
        self._rick_popups = []
        self.defender = None
        ACTIVE_DEFENSE_ENABLED = self.config['ad_enabled']
        MONITOR_DIRS = self.config['monitor_dirs'].copy()

        self._build_ui()
        self._init_defender_check()
        self._start_timers()

        if ACTIVE_DEFENSE_ENABLED and WATCHDOG_AVAILABLE:
            self.after(1000, self._delayed_start_active_defense)
        elif ACTIVE_DEFENSE_ENABLED and not WATCHDOG_AVAILABLE:
            main_log("警告: watchdog模块未安装，主动防御已禁用")
            messagebox.showwarning("警告", "watchdog模块未安装，主动防御功能不可用。")

    def _build_ui(self):
        self.nav_frame = ctk.CTkFrame(self, width=150, corner_radius=0)
        self.nav_frame.pack(side="left", fill="y")
        self.nav_frame.pack_propagate(False)

        nav_buttons = [
            ("🏠 主页", self.show_main),
            ("🔎 扫描", self.show_scan),
            ("⚙ 设置", self.show_settings),
            ("🔧 工具", self.show_tools),
            ("⏸️ 已挂起的进程", self.show_suspended),
            ("📃 白名单", self.show_whitelist),
        ]
        for text, cmd in nav_buttons:
            btn = ctk.CTkButton(self.nav_frame, text=text, command=cmd, width=130)
            btn.pack(pady=5, padx=10)

        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.pack(side="right", expand=True, fill="both")

        self.pages = {}
        self.pages["main"] = self._build_main_page()
        self.pages["scan"] = self._build_scan_page()
        self.pages["settings"] = self._build_settings_page()
        self.pages["tools"] = self._build_tools_page()
        self.pages["suspended"] = self._build_suspended_page()
        self.pages["whitelist"] = self._build_whitelist_page()

        self.show_main()

    def _show_page(self, name):
        for page in self.pages.values(): page.pack_forget()
        self.pages[name].pack(expand=True, fill="both")

    def show_main(self): self._show_page("main")
    def show_scan(self): self._show_page("scan")
    def show_settings(self): self._show_page("settings")
    def show_tools(self): self._show_page("tools")
    def show_suspended(self):
        self.refresh_suspended_table()
        self._show_page("suspended")
    def show_whitelist(self):
        self.refresh_whitelist_display()
        self._show_page("whitelist")

    def _build_main_page(self):
        frame = ctk.CTkFrame(self.content_frame)
        self.main_log_box = ctk.CTkTextbox(frame, wrap="word")
        self.main_log_box.pack(expand=True, fill="both", padx=10, pady=10)
        ctk.CTkButton(frame, text="退出程序", command=self.quit).pack(pady=10)
        return frame

    def _build_scan_page(self):
        frame = ctk.CTkFrame(self.content_frame)
        ctk.CTkLabel(frame, text="病毒查杀", font=("Arial", 16, "bold")).pack(anchor="w", padx=10, pady=5)

        mode_frame = ctk.CTkFrame(frame)
        mode_frame.pack(fill="x", padx=10, pady=5)
        self.scan_mode = ctk.CTkComboBox(mode_frame, values=["单文件查杀", "文件夹查杀", "全盘查杀 (Defender)"])
        self.scan_mode.pack(side="left", padx=5)
        self.scan_mode.set("单文件查杀")
        self.sig_var = ctk.CTkCheckBox(mode_frame, text="数字签名验证")
        self.sig_var.pack(side="left", padx=10)

        prog_frame = ctk.CTkFrame(frame)
        prog_frame.pack(fill="x", padx=10, pady=5)
        self.prog_label = ctk.CTkLabel(prog_frame, text="准备就绪")
        self.prog_label.pack(side="left", padx=5)
        self.prog_bar = ctk.CTkProgressBar(prog_frame, width=300)
        self.prog_bar.pack(side="left", padx=10)
        self.prog_bar.set(0)

        self.scan_log_box = ctk.CTkTextbox(frame, height=100)
        self.scan_log_box.pack(fill="x", padx=10, pady=5)

        self.file_scroll_frame = ctk.CTkScrollableFrame(frame, height=200)
        self.file_scroll_frame.pack(expand=True, fill="both", padx=10, pady=5)

        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(fill="x", padx=10, pady=5)
        self.exec_btn = ctk.CTkButton(btn_frame, text="执行扫描", command=self.start_scan_thread)
        self.exec_btn.pack(side="left", padx=5)
        self.sel_btn = ctk.CTkButton(btn_frame, text="全选/取消", width=100, command=self.toggle_all)
        self.sel_btn.pack(side="left", padx=5)
        self.proc_btn = ctk.CTkButton(btn_frame, text="一键处理", width=100, command=self.process_selected)
        self.proc_btn.pack(side="left", padx=5)
        self.proc_btn.configure(state="disabled")
        return frame

    def _build_settings_page(self):
        frame = ctk.CTkScrollableFrame(self.content_frame)

        mode_frame = ctk.CTkFrame(frame)
        mode_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(mode_frame, text="扫描模式", font=("Arial", 13, "bold")).pack(anchor="w", pady=(0,5))
        self.sensitive_var = ctk.CTkCheckBox(mode_frame, text="高灵敏模式",
                                            command=lambda: self.save_config_key('sensitive', self.sensitive_var.get()))
        self.sensitive_var.pack(anchor="w", pady=2)
        if self.config.get('sensitive'): self.sensitive_var.select()
        self.auto_var = ctk.CTkCheckBox(mode_frame, text="自动处理",
                                       command=lambda: self.save_config_key('auto_process', self.auto_var.get()))
        self.auto_var.pack(anchor="w", pady=2)
        if self.config.get('auto_process'): self.auto_var.select()

        engine_frame = ctk.CTkFrame(frame)
        engine_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(engine_frame, text="扫描引擎", font=("Arial", 13, "bold")).pack(anchor="w", pady=(0,5))
        self.vt_var = ctk.CTkCheckBox(engine_frame, text="VirusTotal云查杀")
        self.vt_var.pack(anchor="w", pady=2)
        if self.config.get('virustotal'): self.vt_var.select()

        api_frame = ctk.CTkFrame(engine_frame)
        api_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(api_frame, text="API Key:").pack(side="left", padx=(0,5))
        self.api_key_var = ctk.CTkEntry(api_frame, width=300, show="*")
        self.api_key_var.pack(side="left", padx=5)
        self.api_key_var.insert(0, self.config.get('apikey', ''))
        self.api_show_hide_btn = ctk.CTkButton(api_frame, text="显示", width=60, command=self.toggle_api_visibility)
        self.api_show_hide_btn.pack(side="left", padx=5)
        ctk.CTkButton(api_frame, text="保存API", width=60, command=self.save_api_key).pack(side="left", padx=5)

        wd_frame = ctk.CTkFrame(engine_frame)
        wd_frame.pack(fill="x", pady=5)
        self.wd_var = ctk.CTkCheckBox(wd_frame, text="Windows Defender本地全盘查杀")
        self.wd_var.pack(side="left", padx=5)
        if self.config.get('windows_defender'): self.wd_var.select()
        self.wd_offline_var = ctk.CTkCheckBox(wd_frame, text="只在离线时使用")
        self.wd_force_var = ctk.CTkCheckBox(wd_frame, text="强制使用(即使有第三方杀软)")
        self.wd_force_var.pack(side="left", padx=5)
        if self.config.get('windows_defender_force'): 
            self.wd_force_var.select()
        if self.config.get('windows_defender_offline_only'): self.wd_offline_var.select()
        self.wd_status = ctk.CTkLabel(wd_frame, text="检查中...")
        self.wd_status.pack(side="left", padx=10)
        self.after(500, self.check_defender)

        ctk.CTkButton(engine_frame, text="保存引擎设置", command=self.save_engine).pack(pady=10)

        ad_frame = ctk.CTkFrame(frame)
        ad_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(ad_frame, text="主动防御设置", font=("Arial", 13, "bold")).pack(anchor="w", pady=(0,5))
        self.ad_enabled_var = ctk.CTkCheckBox(ad_frame, text="启用主动防御")
        self.ad_enabled_var.pack(anchor="w", pady=2)
        if self.config.get('ad_enabled'): self.ad_enabled_var.select()

        dir_frame = ctk.CTkFrame(ad_frame)
        dir_frame.pack(fill="x", pady=5)
        self.dir_listbox = tk.Listbox(dir_frame, height=4, font=("Arial", 12))
        self.dir_listbox.pack(side="left", fill="x", expand=True, padx=(0,5))
        for d in self.config.get('monitor_dirs', []): self.dir_listbox.insert("end", d)
        btn_col = ctk.CTkFrame(dir_frame)
        btn_col.pack(side="right", padx=5)
        ctk.CTkButton(btn_col, text="+", width=30, command=self.add_dir).pack(pady=2)
        ctk.CTkButton(btn_col, text="-", width=30, command=self.remove_dir).pack(pady=2)

        protection_row = ctk.CTkFrame(ad_frame)
        protection_row.pack(fill="x", pady=5)
        self.delete_var = ctk.CTkCheckBox(protection_row, text="删除保护")
        self.delete_var.pack(side="left", padx=5)
        if self.config.get('delete_protection'): self.delete_var.select()
        
        thresh_frame = ctk.CTkFrame(protection_row)
        thresh_frame.pack(side="left", padx=5)
        ctk.CTkLabel(thresh_frame, text="批量删除阈值:").pack(side="left", padx=(0,5))
        self.threshold_var = ctk.CTkEntry(thresh_frame, width=50)
        self.threshold_var.pack(side="left", padx=5)
        self.threshold_var.insert(0, str(self.config.get('batch_delete_threshold', 5)))
        
        self.modify_var = ctk.CTkCheckBox(protection_row, text="修改保护")
        self.modify_var.pack(side="left", padx=5)
        if self.config.get('modify_protection'): self.modify_var.select()
        
        ad_btn_row = ctk.CTkFrame(ad_frame)
        ad_btn_row.pack(fill="x", pady=10)
        ctk.CTkButton(ad_btn_row, text="保存主动防御设置", command=self.save_ad).pack(side="left", padx=5)

        wl_frame = ctk.CTkFrame(frame)
        wl_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(wl_frame, text="白名单放行策略", font=("Arial", 13, "bold")).pack(anchor="w", pady=(0,5))
        self.wl_name_var = ctk.CTkCheckBox(wl_frame, text="文件名相同放行",
                                          command=lambda: self.save_config_key('wl_by_name', self.wl_name_var.get()))
        self.wl_name_var.pack(anchor="w", pady=2)
        if self.config.get('wl_by_name'): self.wl_name_var.select()
        self.wl_hash_var = ctk.CTkCheckBox(wl_frame, text="文件哈希相同放行",
                                          command=lambda: self.save_config_key('wl_by_hash', self.wl_hash_var.get()))
        self.wl_hash_var.pack(anchor="w", pady=2)
        if self.config.get('wl_by_hash'): self.wl_hash_var.select()

        theme_frame = ctk.CTkFrame(frame)
        theme_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(theme_frame, text="界面主题 (重启生效)", font=("Arial", 13, "bold")).pack(anchor="w", pady=(0,5))
        self.theme_var = ctk.CTkComboBox(theme_frame, values=list(THEME_PRESETS.keys()))
        self.theme_var.set(self.config.get('theme', 'default'))
        self.theme_var.pack(anchor="w", pady=5)
        ctk.CTkButton(theme_frame, text="保存主题 (需重启)", command=self.save_theme).pack(anchor="w", pady=5)

        btn_row = ctk.CTkFrame(frame)
        btn_row.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(btn_row, text="开始30秒白名单记录", command=record_processes_for_30_seconds).pack(side="left", padx=5)

        return frame

    def _build_tools_page(self):
        frame = ctk.CTkFrame(self.content_frame)
        ctk.CTkLabel(frame, text="小工具", font=("Arial", 14, "bold")).pack(pady=10)

        grp1 = ctk.CTkFrame(frame)
        grp1.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(grp1, text="通用工具", font=("Arial", 12, "bold")).pack(anchor="w", padx=5, pady=(5,0))
        ctk.CTkButton(grp1, text="创建桌面快捷方式", command=self.create_shortcut).pack(pady=5, padx=10, anchor="w")
        ctk.CTkButton(grp1, text="打开隔离区文件夹", command=self.open_quarantine).pack(pady=5, padx=10, anchor="w")

        grp2 = ctk.CTkFrame(frame)
        grp2.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(grp2, text="彩蛋 & 娱乐", font=("Arial", 12, "bold")).pack(anchor="w", padx=5, pady=(5,0))
        ctk.CTkButton(grp2, text="打开mc1.8.8", command=self.open_mc188, fg_color="green").pack(pady=5, padx=10, anchor="w")
        ctk.CTkButton(grp2, text="千万别点", command=self.play_rickroll, fg_color="red").pack(pady=5, padx=10, anchor="w")

        grp3 = ctk.CTkFrame(frame)
        grp3.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(grp3, text="高级工具", font=("Arial", 12, "bold")).pack(anchor="w", padx=5, pady=(5,0))
        ctk.CTkButton(grp3, text="管理自启动", command=self.manage_autoruns).pack(pady=5, padx=10, anchor="w")

        return frame

    def _build_whitelist_page(self):
        frame = ctk.CTkFrame(self.content_frame)
        ctk.CTkLabel(frame, text="进程白名单", font=("Arial", 14, "bold")).pack(pady=10)
        search_frame = ctk.CTkFrame(frame)
        search_frame.pack(fill="x", padx=10, pady=5)
        self.search_entry = ctk.CTkEntry(search_frame, width=200)
        self.search_entry.pack(side="left", padx=5)
        ctk.CTkButton(search_frame, text="搜索", width=60,
                      command=lambda: self.refresh_whitelist_display(self.search_entry.get())).pack(side="left", padx=5)
        ctk.CTkButton(search_frame, text="重置", width=60,
                      command=lambda: self.refresh_whitelist_display("")).pack(side="left", padx=5)
        self.wl_listbox = tk.Listbox(frame, font=("Arial", 12))
        self.wl_listbox.pack(expand=True, fill="both", padx=10, pady=10)
        btn_row = ctk.CTkFrame(frame)
        btn_row.pack(fill="x", padx=10)
        ctk.CTkButton(btn_row, text="移除选中", fg_color="red", command=self.remove_whitelist_item).pack(side="left", padx=5)
        ctk.CTkButton(btn_row, text="返回设置", command=self.show_settings).pack(side="left", padx=5)
        return frame

    def _build_suspended_page(self):
        frame = ctk.CTkFrame(self.content_frame)
        ctk.CTkLabel(frame, text="已挂起的进程", font=("Arial", 14, "bold")).pack(pady=10)
        act_frame = ctk.CTkFrame(frame)
        act_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(act_frame, text="放行(选中)", font=("Arial", 11), command=self.suspended_resume).pack(side="left", padx=2)
        ctk.CTkButton(act_frame, text="加入白名单", font=("Arial", 11), command=self.suspended_add_white).pack(side="left", padx=2)
        ctk.CTkButton(act_frame, text="结束进程", font=("Arial", 11), fg_color="red", command=self.suspended_kill).pack(side="left", padx=2)
        ctk.CTkButton(act_frame, text="打开位置", font=("Arial", 11), command=self.suspended_open_loc).pack(side="left", padx=2)
        ctk.CTkButton(act_frame, text="手动刷新", font=("Arial", 11), command=self.refresh_suspended_table).pack(side="right", padx=2)

        # 配置 Treeview 样式
        style = ttk.Style()
        style.configure("Treeview", font=("Arial", 12), rowheight=25)
        style.configure("Treeview.Heading", font=("Arial", 12, "bold"))
        
        self.susp_tree = ttk.Treeview(frame, columns=("name","pid","reason","path"), show="headings", selectmode="extended", style="Treeview")
        self.susp_tree.heading("name", text="进程名"); self.susp_tree.column("name", width=120)
        self.susp_tree.heading("pid", text="PID"); self.susp_tree.column("pid", width=80)
        self.susp_tree.heading("reason", text="拦截原因"); self.susp_tree.column("reason", width=200)
        self.susp_tree.heading("path", text="文件路径"); self.susp_tree.column("path", width=300)
        self.susp_tree.pack(expand=True, fill="both", padx=10, pady=5)
        return frame

    def _delayed_start_active_defense(self):
        """延迟启动主动防御，避免阻塞UI初始化"""
        try:
            if not self.ad or not self.ad.running:
                whitelist = load_whitelist()
                if not whitelist:
                    # 改为后台提示，不阻塞
                    def check_whitelist():
                        if messagebox.askyesno("白名单记录", "白名单为空，是否开始30秒进程记录？"):
                            record_processes_for_30_seconds()
                        else:
                            main_log("跳过白名单记录")
                    threading.Thread(target=check_whitelist, daemon=True).start()
                else:
                    self.ad = ActiveDefense()
                    self.ad.start(MONITOR_DIRS)
            else:
                self.ad = ActiveDefense()
                self.ad.start(MONITOR_DIRS)
        except Exception as e:
            main_log(f"延迟启动主动防御失败: {e}")

    def _start_timers(self):
        self._check_ad_queue()
        self._start_suspended_refresh()

    def _check_ad_queue(self):
        while not ad_queue.empty():
            try:
                msg = ad_queue.get_nowait()
                if msg[0] == 'alert': self.show_suspicious_alert(msg[1])
                elif msg[0] == 'scoring_alert': self.show_scoring_alert(msg[1])
                elif msg[0] == 'viral_alert': self.show_viral_alert(msg[1])
                elif msg[0] == 'protection_alert': self.show_protection_alert(msg[1])
            except queue.Empty: break
        self.ad_check_timer = self.after(100, self._check_ad_queue)

    def _start_suspended_refresh(self):
        self.refresh_suspended_table()
        self.suspended_timer_id = self.after(5000, self._start_suspended_refresh)

    def _set_progress(self, value, text):
        self.prog_bar.set(value / 100.0)
        self.prog_label.configure(text=text)

    def save_config_key(self, key, val):
        self.config[key] = val
        save_config(self.config)

    def save_api_key(self):
        self.config['apikey'] = self.api_key_var.get().strip()
        save_config(self.config)
        global API_KEY; API_KEY = self.config['apikey']
        main_log("API Key已保存")
        messagebox.showinfo("成功", "API Key已保存")

    def toggle_api_visibility(self):
        current_show = self.api_key_var.cget("show")
        if current_show == "*":
            self.api_key_var.configure(show="")
            self.api_show_hide_btn.configure(text="隐藏")
        else:
            self.api_key_var.configure(show="*")
            self.api_show_hide_btn.configure(text="显示")

    def _init_defender_check(self):
        def init_check():
            try:
                offline_only = self.config.get('windows_defender_offline_only', True)
                self.defender = DefenderScanner(offline_only=offline_only)
                if self.defender.available:
                    main_log("✅ Windows Defender已初始化并可用")
                else:
                    main_log("⚠️ Windows Defender不可用或未启用")
            except Exception as e:
                main_log(f"初始化Defender检测失败: {e}")
        threading.Thread(target=init_check, daemon=True).start()

    def check_defender(self):
        def check():
            try:
                r = subprocess.run(['powershell', 'Get-MpComputerStatus | Select AntivirusEnabled'],
                                  capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
                status = "✔️可用" if "True" in r.stdout else "❌不可用"
            except: 
                status = "❌不可用"
            try:
                self.after(0, lambda: self.wd_status.configure(text=status))
            except RuntimeError:
                pass
        threading.Thread(target=check, daemon=True).start()

    def save_engine(self):
        self.config['virustotal'] = self.vt_var.get()
        self.config['windows_defender'] = self.wd_var.get()
        self.config['windows_defender_offline_only'] = self.wd_offline_var.get()
        self.config['windows_defender_force'] = self.wd_force_var.get()
        save_config(self.config)
        main_log("引擎设置已保存")
        messagebox.showinfo("成功", "引擎设置已保存")

    def add_dir(self):
        d = filedialog.askdirectory()
        if d:
            d = os.path.normpath(d)
            if not any(d == self.dir_listbox.get(i) for i in range(self.dir_listbox.size())):
                self.dir_listbox.insert("end", d)

    def remove_dir(self):
        sel = self.dir_listbox.curselection()
        if sel: self.dir_listbox.delete(sel[0])

    def save_ad(self):
        if self.ad_restarting:
            messagebox.showinfo("提示", "主动防御正在重启中，请稍后...")
            return
        self.config['ad_enabled'] = self.ad_enabled_var.get()
        self.config['delete_protection'] = self.delete_var.get()
        try: self.config['batch_delete_threshold'] = int(self.threshold_var.get())
        except: pass
        self.config['modify_protection'] = self.modify_var.get()
        self.config['monitor_dirs'] = [self.dir_listbox.get(i) for i in range(self.dir_listbox.size())]
        self.config['wl_by_name'] = self.wl_name_var.get()
        self.config['wl_by_hash'] = self.wl_hash_var.get()
        if self.config['ad_enabled'] and not self.config.get('ad_warned_on_enable', False):
            self.config['ad_warned_on_enable'] = True
            save_config(self.config)
            messagebox.showinfo("提示", "最好先进行白名单记录，否则会出现奇奇怪怪的误报")
        else:
            save_config(self.config)
            messagebox.showinfo("成功", "主动防御设置已保存")

        global ACTIVE_DEFENSE_ENABLED, MONITOR_DIRS
        ACTIVE_DEFENSE_ENABLED = self.config['ad_enabled']
        MONITOR_DIRS = self.config['monitor_dirs'].copy()

        old_ad = self.ad
        self.ad = None
        self.ad_restarting = True

        def restart():
            if old_ad and old_ad.running: old_ad.stop()
            try:
                self.after(0, self._start_new_ad)
            except RuntimeError:
                pass
        threading.Thread(target=restart, daemon=True).start()

    def _start_new_ad(self):
        try:
            if ACTIVE_DEFENSE_ENABLED and WATCHDOG_AVAILABLE:
                self.ad = ActiveDefense(); self.ad.start(MONITOR_DIRS)
                main_log("主动防御已更新并启动")
            else:
                self.ad = None; main_log("主动防御已停止")
            if self.ad: self.ad.refresh_whitelist()
        except Exception as e:
            main_log(f"主动防御启动失败: {e}")
            self.ad = None
        self.ad_restarting = False
        messagebox.showinfo("成功", "主动防御设置已保存")

    def save_theme(self):
        selected = self.theme_var.get()
        self.config['theme'] = selected
        save_config(self.config)
        messagebox.showinfo("主题已保存", f"主题“{selected}”将在下次启动程序时生效。")

    def _clear_scan_results(self):
        for widget in self.file_scroll_frame.winfo_children(): widget.destroy()
        self.file_checkbuttons.clear()
        self.danger_files.clear()
        self.proc_btn.configure(state="disabled")
        self.scan_log_box.delete("1.0", "end")
        self._set_progress(0, "准备就绪")

    def prepare_scan_ui(self):
        self.after(0, self._clear_scan_results)

    def toggle_all(self):
        if not self.danger_files: return
        new_state = not all(cb.get() for cb in self.file_checkbuttons)
        for cb in self.file_checkbuttons:
            if new_state: cb.select()
            else: cb.deselect()
        self.update_btn_text()

    def update_btn_text(self):
        self.proc_btn.configure(state="normal" if self.danger_files else "disabled")

    def process_selected(self):
        count = 0; remaining = []
        for i, cb in enumerate(self.file_checkbuttons):
            if cb.get():
                if quarantine(self.danger_files[i]['path']): count += 1
                else: remaining.append(self.danger_files[i])
        self.danger_files = remaining
        self.refresh_list()
        if count: scan_log(f"已隔离 {count} 个文件")

    def refresh_list(self):
        for widget in self.file_scroll_frame.winfo_children(): widget.destroy()
        self.file_checkbuttons.clear()
        self._remaining_to_add = list(enumerate(self.danger_files))
        self.after(10, self._add_batch)

    def _add_batch(self):
        batch_size = 20
        for _ in range(batch_size):
            if not self._remaining_to_add:
                self.update_btn_text()
                threading.Thread(target=self._update_signatures, daemon=True).start()
                return
            i, f = self._remaining_to_add.pop(0)
            cb = ctk.CTkCheckBox(self.file_scroll_frame, text=f"扫描 {os.path.basename(f['path'])} ...")
            cb.pack(anchor="w", padx=5)
            cb.select()
            cb.configure(command=self.update_btn_text)
            self.file_checkbuttons.append(cb)
        if self._remaining_to_add:
            self.after(10, self._add_batch)
        else:
            self.update_btn_text()
            threading.Thread(target=self._update_signatures, daemon=True).start()

    def _update_signatures(self):
        updates = []
        for i, f in enumerate(self.danger_files):
            sig = ""
            if self.sig_var.get():
                if not check_digital_signature(f['path']): sig = "无签名，"
            text = f"{os.path.basename(f['path'])} {sig}{f.get('type','')} 恶意({f.get('malicious',0)})"
            updates.append((i, text))
        def apply():
            for idx, text in updates:
                if idx < len(self.file_checkbuttons): self.file_checkbuttons[idx].configure(text=text)
        try:
            self.after(0, apply)
        except RuntimeError:
            pass

    def start_scan_thread(self):
        if self.scanning:
            messagebox.showinfo("提示", "已有扫描任务正在运行"); return
        self.scanning = True; self.exec_btn.configure(state="disabled")
        mode = self.scan_mode.get()
        if mode == "单文件查杀":
            if not self.config['virustotal']:
                messagebox.showinfo("提示", "请开启virustotal云查杀引擎"); self.scanning = False; self.exec_btn.configure(state="normal"); return
            target = filedialog.askopenfilename()
            if not target: self.scanning = False; self.exec_btn.configure(state="normal"); return
            self.prepare_scan_ui()
            threading.Thread(target=lambda: self._safe_scan(self.single_file_scan, target), daemon=True).start()
        elif mode == "文件夹查杀":
            if not self.config['virustotal']:
                messagebox.showinfo("提示", "请开启virustotal云查杀引擎"); self.scanning = False; self.exec_btn.configure(state="normal"); return
            target = filedialog.askdirectory()
            if not target: self.scanning = False; self.exec_btn.configure(state="normal"); return
            self.prepare_scan_ui()
            threading.Thread(target=lambda: self._safe_scan(self.folder_scan, target), daemon=True).start()
        else:
            self.prepare_scan_ui()
            threading.Thread(target=lambda: self._safe_scan(self.full_scan), daemon=True).start()

    def _safe_scan(self, scan_func, *args):
        try: scan_func(*args)
        except Exception as e: scan_log(f"扫描过程发生错误: {e}")
        finally:
            self.scanning = False
            try:
                self.after(0, lambda: self.exec_btn.configure(state="normal"))
            except RuntimeError:
                pass

    def single_file_scan(self, target):
        api_key = self.config.get('apikey','').strip()
        if not api_key:
            scan_log("API Key为空")
            update_progress(0, "扫描已终止")
            return
        global API_KEY
        API_KEY = api_key
        self.danger_files = []
        update_progress(0, "准备扫描...")
        scan_log("="*50)
        scan_log(f"开始单文件扫描: {target}")
        if not os.path.exists(target):
            scan_log("文件不存在")
            update_progress(0, "扫描已终止")
            return

        size = os.path.getsize(target)
        update_progress(10, "计算哈希...")
        whitelist = load_whitelist()
        whitelist_hashes = {item['hash'] for item in whitelist if item.get('hash')}
        h = get_file_hash(target)
        if not h:
            scan_log("无法计算哈希")
            update_progress(0, "扫描已终止")
            return
        if h in whitelist_hashes:
            scan_log("文件在白名单中")
            update_progress(100, "扫描完成")
            return

        update_progress(30, "查询VT...")
        url = f"{BASE_URL}/files/{h}"
        headers = {"x-apikey": api_key}
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 404:
                scan_log("文件未被收录")
                if size > MAX_UPLOAD_SIZE:
                    scan_log(f"文件超过30MB ({size//(1024*1024)}MB)，仅使用SHA256查询VT，不上传文件")
                    update_progress(100, "扫描完成")
                    return
                scan_log("正在上传到 VT 分析...")
                update_progress(50, "上传文件中...")
                upload_url = "https://www.virustotal.com/api/v3/files"
                with open(target, 'rb') as f:
                    files = {'file': (os.path.basename(target), f)}
                    upload_r = requests.post(upload_url, headers={"x-apikey": api_key}, files=files, timeout=60)
                if upload_r.status_code == 200:
                    upload_data = upload_r.json()
                    analysis_id = upload_data.get('data', {}).get('id', '')
                    scan_log(f"文件已上传，分析ID: {analysis_id}")
                    scan_log("等待分析完成...")
                    update_progress(70, "等待VT分析...")
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    for _ in range(20):
                        time.sleep(5)
                        analysis_r = requests.get(analysis_url, headers={"x-apikey": api_key}, timeout=30)
                        if analysis_r.status_code == 200:
                            analysis_data = analysis_r.json()
                            status = analysis_data.get('data', {}).get('attributes', {}).get('status', '')
                            if status == 'completed':
                                stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                                malicious = stats.get('malicious', 0)
                                suspicious = stats.get('suspicious', 0)
                                if self.config.get('sensitive'):
                                    if malicious >= 1:
                                        self.danger_files.append({'path':target, 'type':"恶意(上传分析)", 'malicious':malicious, 'suspicious':suspicious, 'mode':'single'})
                                else:
                                    if malicious >= 6:
                                        self.danger_files.append({'path':target, 'type':"恶意(上传分析)", 'malicious':malicious, 'suspicious':suspicious, 'mode':'single'})
                                scan_log(f"分析完成 - 恶意:{malicious}, 可疑:{suspicious}")
                                break
                        time.sleep(5)
                else:
                    scan_log(f"上传失败 HTTP {upload_r.status_code}")
                update_progress(100, "扫描完成")
                return
            if r.status_code != 200:
                scan_log(f"VT异常 HTTP {r.status_code}")
                update_progress(100, "扫描完成")
                return
            data = r.json()
            stats = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            malicious = stats.get("malicious",0)
            suspicious = stats.get("suspicious",0)
            if self.config.get('sensitive'):
                if malicious >= 1:
                    self.danger_files.append({'path':target, 'type':"恶意", 'malicious':malicious, 'suspicious':suspicious, 'mode':'single'})
            else:
                if malicious >= 6:
                    self.danger_files.append({'path':target, 'type':"恶意", 'malicious':malicious, 'suspicious':suspicious, 'mode':'single'})
        except Exception as e:
            scan_log(f"请求失败: {e}")
        update_progress(100, "扫描完成")
        scan_log(f"发现 {len(self.danger_files)} 个危险项")
        self.after(0, self.refresh_list)

    def full_scan(self):
        self.danger_files = []
        scan_log("="*50)
        scan_log("全盘查杀 (Windows Defender)")
        update_progress(0, "初始化...")
        
        defender = DefenderScanner(
            offline_only=self.config.get('windows_defender_offline_only', True),
            force_use=self.config.get('windows_defender_force', False)
        )
        
        if not defender.available:
            scan_log("Defender 不可用")
            self.after(0, lambda: messagebox.showerror("错误", "Defender 不可用"))
            return
        
        update_progress(10, "全盘扫描中，请耐心等待...")
        scan_log("全盘扫描中，这可能需要较长时间...")
        
        threats = defender.full_scan()
        
        self.danger_files = [
            {
                'path': t.get('path', '未知'),
                'type': f"Defender: {t.get('name', '未知威胁')}",
                'malicious': 'Defender'
            }
            for t in threats
        ]
        
        update_progress(100, "扫描完成")
        scan_log(f"发现 {len(self.danger_files)} 个威胁")
        self.after(0, self.refresh_list)

    def _alert_popup(self, title, info, score_bar=False, color="#ff6600", critical=False, suspicious=False, protection=False):
        key = f"{info.get('pid','')}_{info.get('name','')}_{title}"
        now = time.time()
        if key in self.alert_cooldown and now - self.alert_cooldown[key] < 5: return
        self.alert_cooldown[key] = now

        top = ctk.CTkToplevel(self)
        top.title(title)
        top.geometry("700x600")
        top.attributes("-topmost", True)
        top.grab_set()

        frame = ctk.CTkFrame(top)
        frame.pack(expand=True, fill="both", padx=10, pady=10)

        if critical: ctk.CTkLabel(frame, text="发现恶意软件 - 已自动隔离", font=("Arial",16,"bold"), text_color="red").pack()
        else: ctk.CTkLabel(frame, text=title, font=("Arial",14,"bold"), text_color=color).pack()

        if score_bar and 'score' in info:
            pbar = ctk.CTkProgressBar(frame, width=300)
            pbar.set(info['score'] / 120); pbar.pack(pady=5)
            ctk.CTkLabel(frame, text=f"威胁评分: {info['score']:.0f} / 120").pack()

        details = f"进程: {info.get('name','')}  PID: {info.get('pid','')}\n路径: {info.get('exe','')}"
        ctk.CTkLabel(frame, text=details, justify="left").pack(anchor="w", pady=5)

        if info.get('rules'):
            ctk.CTkLabel(frame, text="触发规则:", font=("Arial",11,"bold")).pack(anchor="w")
            rules_box = ctk.CTkTextbox(frame, height=100)
            rules_box.insert("1.0", '\n'.join(info['rules']))
            rules_box.configure(state="disabled")
            rules_box.pack(fill="x", padx=5)

        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="加入白名单", command=lambda: self.alert_add_white(info, top)).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="终止进程", fg_color="red", command=lambda: self.alert_term(info, top)).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="隔离病毒", fg_color="purple", command=lambda: self.alert_quarantine(info, top)).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="允许本次操作", command=lambda: self.allow_this_operation(info, top)).pack(side="left", padx=5)

    def show_scoring_alert(self, info): self._alert_popup("主动防御告警 - 可疑进程", info, score_bar=True, color="#ff6600")
    def show_viral_alert(self, info): self._alert_popup("主动防御 - 发现恶意软件", info, critical=True)
    def show_suspicious_alert(self, info): self._alert_popup("主动防御告警 - 发现可疑操作", info, suspicious=True)
    def show_protection_alert(self, info): self._alert_popup("主动防御 - 文件保护触发", info, protection=True)

    def allow_this_operation(self, info, top):
        pid = info['pid']
        try: psutil.Process(pid).resume()
        except: pass
        with suspended_lock:
            if pid in SUSPENDED_PROCS: del SUSPENDED_PROCS[pid]
        with alert_lock: alerted_processes.discard(pid)
        TEMPORARY_ALLOWED.add(pid)
        top.destroy()

    def alert_add_white(self, info, top):
        wl = load_whitelist()
        h = None
        if info['exe'] and os.path.exists(info['exe']):
            with open(info['exe'],'rb') as f: h = hashlib.sha256(f.read()).hexdigest()
        wl.append({'name':info['name'], 'pid':info['pid'], 'path':info['exe'], 'hash':h, 'time':time.time()})
        save_whitelist(wl)
        try: psutil.Process(info['pid']).resume()
        except: pass
        with suspended_lock:
            if info['pid'] in SUSPENDED_PROCS: del SUSPENDED_PROCS[info['pid']]
        with alert_lock: alerted_processes.discard(info['pid'])
        if self.ad: self.ad.refresh_whitelist()
        top.destroy()

    def alert_term(self, info, top):
        pid = info['pid']
        try: proc = psutil.Process(pid); proc.terminate(); proc.wait(timeout=5)
        except: pass
        with suspended_lock:
            if pid in SUSPENDED_PROCS: del SUSPENDED_PROCS[pid]
        with alert_lock: alerted_processes.discard(pid)
        top.destroy()

    def alert_quarantine(self, info, top):
        pid = info['pid']
        try: proc = psutil.Process(pid); proc.terminate(); proc.wait(timeout=5)
        except: pass
        with suspended_lock:
            if pid in SUSPENDED_PROCS: del SUSPENDED_PROCS[pid]
        with alert_lock: alerted_processes.discard(pid)
        if quarantine(info['exe']): messagebox.showinfo("成功", "已隔离病毒")
        else: messagebox.showerror("失败", "隔离失败")
        top.destroy()

    def alert_online(self, info):
        if not self.config.get('virustotal'): messagebox.showinfo("提示","VirusTotal已禁用"); return
        h = None
        if info.get('exe') and os.path.exists(info['exe']):
            try:
                with open(info['exe'],'rb') as f: h = hashlib.sha256(f.read()).hexdigest()
            except: pass
        if not h: messagebox.showerror("错误","无法计算哈希"); return
        api_key = self.config.get('apikey','').strip()
        if not api_key: messagebox.showerror("错误","请先设置API Key"); return
        def analyze():
            try:
                r = requests.get(f"{BASE_URL}/files/{h}", headers={"x-apikey":api_key}, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    stats = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                    msg = f"恶意: {stats.get('malicious',0)}\n可疑: {stats.get('suspicious',0)}"
                    try:
                        self.after(0, lambda: messagebox.showinfo("在线分析结果", msg))
                    except RuntimeError:
                        pass
                else: 
                    try:
                        self.after(0, lambda: messagebox.showwarning("提示","文件尚未被分析"))
                    except RuntimeError:
                        pass
            except Exception as e: 
                try:
                    self.after(0, lambda: messagebox.showerror("错误",str(e)))
                except RuntimeError:
                    pass
        threading.Thread(target=analyze, daemon=True).start()

    def refresh_suspended_table(self):
        for row in self.susp_tree.get_children(): self.susp_tree.delete(row)
        with suspended_lock:
            to_remove = [pid for pid in SUSPENDED_PROCS if not psutil.pid_exists(pid)]
            for pid in to_remove: del SUSPENDED_PROCS[pid]
        for pid, p in SUSPENDED_PROCS.items():
            self.susp_tree.insert("", "end", values=(p['name'], pid, p['reason'], p['exe']))

    def get_selected_suspended(self):
        sel = self.susp_tree.selection()
        if not sel: messagebox.showwarning("提示","请先选择进程"); return []
        result = []
        for item in sel:
            vals = self.susp_tree.item(item, 'values')
            result.append({'pid':int(vals[1]), 'exe':vals[3], 'name':vals[0]})
        return result

    def suspended_resume(self):
        for p in self.get_selected_suspended():
            try: psutil.Process(p['pid']).resume()
            except: pass
            with suspended_lock:
                if p['pid'] in SUSPENDED_PROCS: del SUSPENDED_PROCS[p['pid']]
        self.refresh_suspended_table()

    def suspended_add_white(self):
        for p in self.get_selected_suspended():
            wl = load_whitelist()
            h = None
            if p['exe'] and os.path.exists(p['exe']):
                with open(p['exe'],'rb') as f: h = hashlib.sha256(f.read()).hexdigest()
            wl.append({'name':p['name'], 'pid':p['pid'], 'path':p['exe'], 'hash':h, 'time':time.time()})
            save_whitelist(wl)
            try: psutil.Process(p['pid']).resume()
            except: pass
            with suspended_lock:
                if p['pid'] in SUSPENDED_PROCS: del SUSPENDED_PROCS[p['pid']]
        self.refresh_suspended_table()

    def suspended_kill(self):
        for p in self.get_selected_suspended():
            try: proc = psutil.Process(p['pid']); proc.terminate(); proc.wait(timeout=5)
            except: pass
            with suspended_lock:
                if p['pid'] in SUSPENDED_PROCS: del SUSPENDED_PROCS[p['pid']]
        self.refresh_suspended_table()

    def suspended_open_loc(self):
        for p in self.get_selected_suspended():
            if p['exe'] and os.path.exists(p['exe']):
                os.startfile(os.path.dirname(p['exe']))

    def refresh_whitelist_display(self, filter_text=""):
        self.wl_listbox.delete(0, "end")
        whitelist = load_whitelist()
        for item in whitelist:
            name = item.get('name') or '未知'
            path = item.get('path') or '未知'
            if not filter_text or filter_text.lower() in name.lower() or filter_text.lower() in path.lower():
                self.wl_listbox.insert("end", f"{name} - {path}")

    def remove_whitelist_item(self):
        sel = self.wl_listbox.curselection()
        if not sel: return
        idx = sel[0]
        text = self.wl_listbox.get(idx)
        name, _, path = text.partition(" - ")
        wl = load_whitelist()
        new_wl = [w for w in wl if not (w.get('name')==name and w.get('path')==path)]
        save_whitelist(new_wl)
        self.refresh_whitelist_display(self.search_entry.get())
        if self.ad: self.ad.refresh_whitelist()

    def create_shortcut(self):
        try:
            desktop = os.path.join(os.environ["USERPROFILE"], "Desktop")
            bat_path = os.path.join(desktop, "VirusTotalSecurity.bat")
            target = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
            with open(bat_path, "w", encoding="gbk") as f:
                f.write(f'@echo off\ncd /d "{BASE_DIR}"\nstart "" "{target}"')
            messagebox.showinfo("提示", "桌面启动脚本已创建")
            main_log("已创建桌面快捷方式")
        except Exception as e: messagebox.showerror("错误", str(e))

    def open_quarantine(self): os.startfile(QUARANTINE_DIR)

    def open_mc188(self):
        html_path = os.path.join(DATA_DIR, "Mc1.8.8.html")
        if os.path.exists(html_path): os.startfile(html_path)
        else: messagebox.showerror("错误", f"文件不存在: {html_path}")

    def manage_autoruns(self):
        if not self.config.get('autoruns_prompted', False):
            if not messagebox.askyesno("提示", "该功能由Microsoft提供，将下载Autoruns(2.8MB)。是否继续？"): return
            self.config['autoruns_prompted'] = True; save_config(self.config)
        autoruns_zip = os.path.join(DATA_DIR, "Autoruns.zip")
        try:
            exe = self._find_autoruns_executable()
            if not exe:
                if not os.path.exists(autoruns_zip): self._download_autoruns(autoruns_zip)
                self._extract_autoruns(autoruns_zip, DATA_DIR)
                exe = self._find_autoruns_executable()
            if exe: os.startfile(exe)
            else: os.startfile(DATA_DIR)
        except Exception as e: messagebox.showerror("错误", str(e))

    def _download_autoruns(self, dest):
        r = requests.get("https://download.sysinternals.com/files/Autoruns.zip", stream=True, timeout=60)
        if r.status_code != 200: raise RuntimeError("下载失败")
        with open(dest, "wb") as f:
            for chunk in r.iter_content(8192): f.write(chunk)

    def _extract_autoruns(self, zip_path, to):
        with zipfile.ZipFile(zip_path, "r") as z: z.extractall(to)

    def _find_autoruns_executable(self):
        for name in ["Autoruns64.exe", "Autoruns.exe"]:
            cand = os.path.join(DATA_DIR, name)
            if os.path.exists(cand): return cand
        for f in os.listdir(DATA_DIR):
            if f.lower().startswith("autoruns") and f.lower().endswith(".exe"):
                return os.path.join(DATA_DIR, f)
        return None

    def play_rickroll(self):
        self._cleanup_all_rick_popups()
        try:
            VK_VOLUME_UP = 0xAF
            for _ in range(50):
                try:
                    ctypes.windll.user32.keybd_event(VK_VOLUME_UP, 0, 0, 0)
                    ctypes.windll.user32.keybd_event(VK_VOLUME_UP, 0, 0x2, 0)
                except: pass
                time.sleep(0.015)
        except: pass
        mp3_path = os.path.join(DATA_DIR, "resources", "never_gonna_give_you_up.mp3")
        if os.path.exists(mp3_path):
            try: os.startfile(mp3_path)
            except: pass
        alien_path = os.path.join(DATA_DIR, "resources", "alien.png")
        self._rick_popups = []; self._rick_cleanup_done = False; self._rick_timer_id = None

        def spawn():
            try:
                if self._rick_cleanup_done: return
                if len(self._rick_popups) >= 20:
                    try:
                        old = self._rick_popups.pop(0)
                        old.destroy()
                    except: pass
                popup = ctk.CTkToplevel(self)
                popup.title("千万别点"); popup.attributes("-topmost", True); popup.overrideredirect(True)
                try:
                    from PIL import Image
                    if os.path.exists(alien_path):
                        img = ctk.CTkImage(Image.open(alien_path), size=(200,200))
                        ctk.CTkLabel(popup, image=img, text="").pack()
                    else:
                        ctk.CTkLabel(popup, text="👽").pack()
                except: ctk.CTkLabel(popup, text="👽").pack()
                ctk.CTkLabel(popup, text="你被骗了，你已急哭", font=("Arial",14,"bold"), text_color="red").pack()
                sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
                x = random.randint(0, max(0, sw-250)); y = random.randint(0, max(0, sh-200))
                popup.geometry(f"250x200+{x}+{y}"); popup.lift()
                self._rick_popups.append(popup)
                if not self._rick_cleanup_done:
                    self._rick_timer_id = self.after(1000, spawn)
            except Exception as e:
                main_log(f"rickroll生成失败: {e}")

        spawn()
        self.after(220*1000, self._cleanup_all_rick_popups)

    def _cleanup_all_rick_popups(self):
        try:
            if self._rick_cleanup_done: return
            self._rick_cleanup_done = True
            if self._rick_timer_id:
                try: self.after_cancel(self._rick_timer_id)
                except: pass
            for p in list(self._rick_popups):
                try: p.destroy()
                except: pass
            self._rick_popups.clear()
        except Exception as e:
            main_log(f"清理rickroll弹窗失败: {e}")

    def destroy(self):
        try:
            self._cleanup_all_rick_popups()
        except: pass
        try:
            if self.ad_check_timer: self.after_cancel(self.ad_check_timer)
        except: pass
        try:
            if self.suspended_timer_id: self.after_cancel(self.suspended_timer_id)
        except: pass
        try:
            if self.ad and self.ad.running:
                threading.Thread(target=self.ad.stop, daemon=True).start()
        except: pass
        super().destroy()

if __name__ == '__main__':
    app = VirusWiseApp()
    app.mainloop()