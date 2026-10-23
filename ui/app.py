import os, sys, time, threading, queue, hashlib, random, ctypes, subprocess, zipfile
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from types import SimpleNamespace
import customtkinter as ctk
import psutil
import requests
from utils.paths import BASE_DIR, DATA_DIR, QUARANTINE_DIR, WHITELIST_FILE, THEME_WARM_YELLOW
from utils.config import load_config, save_config
from utils.whitelist import load_whitelist, save_whitelist
from utils.hash import get_file_hash
from utils.quarantine import quarantine
from utils.risk import get_risk_level
from utils.signature import check_digital_signature
from utils.network import is_offline
from utils.fake_log import is_fake_log
from utils.logging import main_log, scan_log, update_progress
from core.notifier import notifier
from core.defender import DefenderScanner
from core.scoring import ProcessAnalyzer, ProcessScoreTracker
from core.active_defense import ActiveDefense
from ui.theme import THEME_PRESETS, apply_startup_theme
from core.active_defense import TEMPORARY_ALLOWED, SUSPENDED_PROCS, suspended_lock, alerted_processes, alert_lock
from core.active_defense import ad_queue


BASE_URL = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_SIZE = 30 * 1024 * 1024
API_KEY = ""

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

        watchdog_available = getattr(sys.modules.get('legacy_patch'), 'WATCHDOG_AVAILABLE', False)
        if ACTIVE_DEFENSE_ENABLED and watchdog_available:
            self.after(1000, self._delayed_start_active_defense)
        elif ACTIVE_DEFENSE_ENABLED and not watchdog_available:
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
        ctk.CTkButton(
            btn_row,
            text="开始30秒白名单记录",
            command=self.record_processes_for_30_seconds,
        ).pack(side="left", padx=5)

        return frame

    def record_processes_for_30_seconds(self):
        from legacy_patch import record_processes_for_30_seconds
        record_processes_for_30_seconds()

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
