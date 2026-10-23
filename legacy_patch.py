from ui.app import VirusWiseApp
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
from core.defender import DefenderScanner
from core.scoring import TrustedPublishers, ProcessBehavior, ScoringEngine, ProcessScoreTracker
from core.active_defense import ActiveDefense, ActiveDefenseHandler, SystemMonitorHandler
from ui.theme import WARM_YELLOW_THEME_JSON, THEME_PRESETS, apply_startup_theme

CRASH_LOG = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "crash.log")
from core.active_defense import (
    alerted_processes, alert_lock, TEMPORARY_ALLOWED, ad_queue,
    SUSPENDED_PROCS, suspended_lock, ACTIVE_DEFENSE_ENABLED, MONITOR_DIRS,
)

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

API_KEY = ""
BASE_URL = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_SIZE = 30 * 1024 * 1024

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

def collect_files(path):
    if os.path.isfile(path): return [path]
    result = []
    for r, _, fs in os.walk(path):
        for f in fs:
            result.append(os.path.join(r, f))
    return result

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

for _name, _obj in list(globals().items()):
    if callable(_obj) and not hasattr(VirusWiseApp, _name):
        setattr(VirusWiseApp, _name, _obj)