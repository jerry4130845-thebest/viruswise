import os, sys, time, threading, queue, hashlib, random, ctypes, subprocess, zipfile
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
