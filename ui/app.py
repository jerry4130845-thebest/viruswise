import os, sys, time, threading, queue, hashlib, random, ctypes, subprocess, zipfile
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from types import SimpleNamespace, MappingProxyType
from collections import deque
from uuid import uuid4
import customtkinter as ctk
import psutil
import requests
from utils.paths import BASE_DIR, DATA_DIR, QUARANTINE_DIR, WHITELIST_FILE, THEME_WARM_YELLOW
from utils.config import load_config, save_config
from utils.whitelist import load_whitelist, save_whitelist
from utils.hash import get_file_hash
from utils.quarantine import quarantine
from utils.risk import get_risk_level, SYSTEM_PROCESSES
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
import core.active_defense as admod


BASE_URL = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_SIZE = 30 * 1024 * 1024
API_KEY = ""


def record_processes_for_30_seconds():
    from core.whitelist_recording import record_whitelist
    from core.defense_control import require_service_stopped

    def recording_guard():
        require_service_stopped(allow_not_installed=True)
    app = getattr(sys, 'app', None)
    if app is None or getattr(app, '_closing', False):
        return
    if getattr(app, '_record_cancel', None) is not None:
        main_log('白名单记录已在进行中')
        return
    try:
        recording_guard()
    except Exception as exc:
        main_log(f"无法确认 Windows 防御服务已停止，拒绝记录白名单: {exc}")
        messagebox.showwarning("无法记录白名单", "请先停止 Windows 防御服务；服务状态未知或无查询权限时不能学习白名单。")
        return
    cancel = threading.Event()
    app._record_cancel = cancel
    ad_was_running = bool(app.ad and app.ad.running)
    if app.ad is not None:
        try:
            # A previous stop may have timed out with running=False but live workers.
            app.ad.stop()
        except Exception:
            app._record_cancel = None
            main_log('GUI主动防御未能暂停，拒绝开始白名单记录')
            return
    main_log("开始30秒白名单记录；记录期间不要启动测试程序")
    popup = ctk.CTkToplevel(app)
    popup.title("白名单记录中")
    popup.geometry("300x150")
    popup.attributes("-topmost", True)
    popup.protocol("WM_DELETE_WINDOW", cancel.set)
    ctk.CTkLabel(popup, text="正在记录进程到白名单\n持续时间: 至少30秒\n本次GUI主动防御已暂停", font=("Arial", 12)).pack(pady=20)
    popup.update()

    def finish(result):
        try:
            if result['ok']:
                main_log(f"白名单记录成功，新增 {result['added']} 项，已更新成功时间")
                if result.get('error_count'):
                    main_log(f"其中 {result['error_count']} 项无法记录，不代表这些进程安全")
                if hasattr(app, 'refresh_whitelist_display'):
                    app.refresh_whitelist_display()
                if (ad_was_running and not getattr(app, '_closing', False)
                        and admod.ACTIVE_DEFENSE_ENABLED and admod.WATCHDOG_AVAILABLE):
                    try:
                        app.ad = admod.ActiveDefense()
                        app.ad.start(admod.MONITOR_DIRS)
                        main_log("GUI主动防御已恢复")
                    except Exception as exc:
                        main_log(f"主动防御恢复失败: {exc}")
            else:
                main_log(f"白名单记录失败，未更新成功时间，防御不自动恢复: {result.get('code')}")
        finally:
            if getattr(app, '_record_cancel', None) is cancel:
                app._record_cancel = None
            if popup.winfo_exists():
                popup.destroy()

    def record():
        # GUI manual recording updates the shared timestamp but has no hourly gate.
        result = record_whitelist(cancel_event=cancel, guard=recording_guard)
        try:
            app.after(0, lambda: finish(result))
        except (RuntimeError, tk.TclError):
            pass  # GUI closed; do not restart defense from this worker.

    threading.Thread(target=record, daemon=True).start()


class VirusWiseApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        sys.app = self
        self.title("VirusWise 2.6.6+")
        self.geometry("900x650")
        self.minsize(900, 650)

        self.config = load_config()
        global API_KEY
        API_KEY = self.config.get('apikey', '').strip()

        theme = self.config.get('theme', 'default')
        apply_startup_theme(theme)

        self.danger_files = []
        self.file_checkbuttons = []
        self.scan_results = []
        self._checkboxes = {}
        self._selection = {}
        self._scan_id = 0
        self._render_generation = 0
        self._render_timer = None
        self._scan_ui_timer = None
        self._service_ui_timer = None
        self._service_busy = False
        self._scan_events = queue.Queue(maxsize=256)
        self._scan_cancel = threading.Event()
        self._signature_cancel = threading.Event()
        self._scan_workers = set()
        self._closing = False
        self.ad = None
        self.scanning = False
        self.ad_restarting = False
        self.alert_cooldown = {}
        self._rick_cleanup_done = False
        self._rick_popups = []
        self.defender = None
        admod.ACTIVE_DEFENSE_ENABLED = self.config['ad_enabled']
        admod.MONITOR_DIRS = self.config['monitor_dirs'].copy()

        self._build_ui()
        self._init_defender_check()
        self._start_timers()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        watchdog_available = admod.WATCHDOG_AVAILABLE
        if admod.ACTIVE_DEFENSE_ENABLED and watchdog_available:
            self.after(1000, self._delayed_start_active_defense)
        elif admod.ACTIVE_DEFENSE_ENABLED and not watchdog_available:
            main_log("警告: 当前防御核心尚未实现 GUI 目录监控，GUI 主动防御未启动")
            messagebox.showwarning("主动防御未启动", "当前防御核心尚未实现 GUI 目录监控。\n这不是 watchdog 安装检测结果；安装依赖不能解除此限制。")

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
        ctk.CTkButton(frame, text="退出程序", command=self.destroy).pack(pady=10)
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
        self.cancel_btn = ctk.CTkButton(btn_frame, text="取消扫描", width=90, command=self.cancel_scan, state="disabled")
        self.cancel_btn.pack(side="left", padx=5)
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

        service_frame = ctk.CTkFrame(frame)
        service_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(service_frame, text="Windows 防御服务", font=("Arial", 13, "bold")).pack(anchor="w", pady=(0,5))
        self.service_status = ctk.CTkLabel(
            service_frame, text="安装仅注册服务，不自动启动，也不代表防御已就绪；卸载要求服务已停止。",
            wraplength=660, justify="left")
        self.service_status.pack(anchor="w", padx=5, pady=5)
        service_buttons = ctk.CTkFrame(service_frame)
        service_buttons.pack(fill="x", pady=5)
        self.install_service_btn = ctk.CTkButton(
            service_buttons, text="安装服务", command=lambda: self._manage_windows_service("install"))
        self.install_service_btn.pack(side="left", padx=5)
        self.uninstall_service_btn = ctk.CTkButton(
            service_buttons, text="卸载服务", command=lambda: self._manage_windows_service("uninstall"))
        self.uninstall_service_btn.pack(side="left", padx=5)

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
        record_processes_for_30_seconds()

    def _manage_windows_service(self, action):
        if action not in ("install", "uninstall") or self._closing or self._service_busy:
            return
        label = "安装" if action == "install" else "卸载"
        prompt = ("是否安装当前程序的 Windows 防御服务？\n仅注册服务，不会自动启动或确认防御就绪。"
                  if action == "install" else
                  "是否卸载当前程序的 Windows 防御服务？\n服务必须已停止；本操作不会替你停止服务。")
        # Reserve before the modal dialog: nested events must not open another request.
        self._service_busy = True
        self.install_service_btn.configure(state="disabled")
        self.uninstall_service_btn.configure(state="disabled")
        confirmed = False
        try:
            confirmed = messagebox.askyesno(f"确认{label}服务", prompt, parent=self)
        finally:
            if not confirmed or self._closing:
                self._service_busy = False
                if not self._closing:
                    self.install_service_btn.configure(state="normal")
                    self.uninstall_service_btn.configure(state="normal")
        if not confirmed or self._closing:
            return
        self.service_status.configure(text=f"正在{label}服务，请等待；不会自动启动或停止服务。")
        results = queue.Queue(maxsize=1)

        def work():
            # Workers only publish data; all Tk calls stay on the UI thread.
            try:
                from core import defense_control
                operation = defense_control.install if action == "install" else defense_control.uninstall
                result = operation(allow_system_effects=True)
                if not isinstance(result, dict):
                    raise ValueError("Invalid service controller result")
            except Exception as exc:
                result = {"ok": False, "code": "service_error", "error": str(exc)}
            results.put_nowait(result)

        try:
            threading.Thread(target=work, daemon=True).start()
        except Exception as exc:
            self._finish_service_action(action, {"ok": False, "code": "worker_start_failed", "error": str(exc)})
            return
        self._service_ui_timer = self.after(100, self._poll_service_action, action, results)

    def _poll_service_action(self, action, results):
        self._service_ui_timer = None
        if self._closing:
            return
        try:
            result = results.get_nowait()
        except queue.Empty:
            self._service_ui_timer = self.after(100, self._poll_service_action, action, results)
            return
        self._finish_service_action(action, result)

    def _finish_service_action(self, action, result):
        self._service_busy = False
        if self._closing:
            return
        self.install_service_btn.configure(state="normal")
        self.uninstall_service_btn.configure(state="normal")
        label = "安装" if action == "install" else "卸载"
        code = str(result.get("code", "unknown"))
        successes = {
            "install": {"installed": "服务已安装，未自动启动；这不代表防御已就绪。",
                        "already_installed": "当前程序的服务已经安装，本次未修改或启动服务。"},
            "uninstall": {"uninstalled": "服务已卸载；本次没有自动停止任何服务。"},
        }
        failures = {
            "not_installed": "未找到已安装的防御服务，无需卸载。",
            "authorization_required": "服务操作未获得明确授权，未执行。",
            "invalid_deployment": "当前程序路径或部署形式不适合注册服务，请检查程序安装位置。",
            "access_denied": "权限不足，无法完成操作。请以管理员身份重新打开 VirusWise。",
            "service_busy": "服务尚未停止，拒绝卸载。请先明确停止服务后再试；本次未请求停止。",
            "deployment_mismatch": "同名服务不属于当前程序路径或配置，未擅自修改。请先核对已有服务。",
            "pending_delete": "服务处于等待删除状态，尚未确认卸载完成。请等待占用句柄释放后再检查。",
            "dependency_missing": "缺少 Windows 服务运行依赖（pywin32），操作未完成。",
            "unsupported_platform": "此功能仅支持 Windows。",
            "cancelled": "操作被中断，结果未确认；已提交的请求不一定撤回，请检查服务状态。",
            "worker_start_failed": "后台任务未能启动，未发送服务操作请求。",
        }
        message = successes[action].get(code) if result.get("ok") is True else None
        confirmed = message is not None
        if not confirmed:
            message = failures.get(code, f"未能确认{label}完成（代码：{code}）。请检查服务状态，不要把它视为成功。")
            if result.get("install_requested") or result.get("uninstall_requested"):
                message += "\n请求可能已经提交；失败提示不代表系统完全没有变化。"
        self.service_status.configure(text=message)
        main_log(f"服务{label}结果 [{code}]: {message}; {result.get('error', '')}")
        dialog = messagebox.showinfo if confirmed else messagebox.showwarning
        dialog(f"服务{label}结果", message, parent=self)

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

        admod.ACTIVE_DEFENSE_ENABLED = self.config['ad_enabled']
        admod.MONITOR_DIRS = self.config['monitor_dirs'].copy()

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
            if admod.ACTIVE_DEFENSE_ENABLED and admod.WATCHDOG_AVAILABLE:
                self.ad = ActiveDefense(); self.ad.start(admod.MONITOR_DIRS)
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
        result = quarantine(info['exe'])
        if result["status"] == "isolated":
            messagebox.showinfo("成功", "已隔离病毒")
        else:
            messagebox.showerror("未完成隔离", result.get("error") or "原文件未移除")
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
            bat_path = os.path.join(desktop, "VirusWise.bat")
            target = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
            with open(bat_path, "w", encoding="gbk") as f:
                f.write(f'@echo off\ncd /d "{BASE_DIR}"\nstart "" "{target}"')
            messagebox.showinfo("提示", "桌面启动脚本已创建")
            main_log("已创建桌面快捷方式")
        except Exception as e: messagebox.showerror("错误", str(e))

    def open_quarantine(self): os.startfile(QUARANTINE_DIR)

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
            if exe:
                # 下载后必须验证数字签名，防止中间人篡改
                if not check_digital_signature(exe):
                    messagebox.showerror("错误", "Autoruns 数字签名验证失败，已放弃执行，可能是文件被篡改")
                    return
                os.startfile(exe)
            else:
                os.startfile(DATA_DIR)
        except Exception as e: messagebox.showerror("错误", str(e))

    def _download_autoruns(self, dest):
        r = requests.get("https://download.sysinternals.com/files/Autoruns.zip", stream=True, timeout=60)
        if r.status_code != 200: raise RuntimeError("下载失败")
        # 校验 Content-Type 与大小（2.8MB 左右）
        ctype = r.headers.get('Content-Type', '')
        if 'zip' not in ctype.lower() and 'octet-stream' not in ctype.lower():
            raise RuntimeError(f"下载内容类型异常: {ctype}")
        with open(dest, "wb") as f:
            for chunk in r.iter_content(8192): f.write(chunk)
        return dest

    def _extract_autoruns(self, zip_path, to):
        import zipfile as _zf
        with _zf.ZipFile(zip_path, "r") as z:
            for member in z.infolist():
                # 防止 Zip Slip（路径遍历）
                target = os.path.normpath(os.path.join(to, member.filename))
                if not target.startswith(os.path.abspath(to) + os.sep) and target != os.path.abspath(to):
                    raise RuntimeError(f"ZIP 条目路径不安全: {member.filename}")
            z.extractall(to)

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
        self._drain_scan_events()
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
                    self.ad.start(admod.MONITOR_DIRS)
            else:
                self.ad = ActiveDefense()
                self.ad.start(admod.MONITOR_DIRS)
        except Exception as e:
            main_log(f"延迟启动主动防御失败: {e}")

    def _post_scan_event(self, scan_id, kind, payload, cancel=None):
        # Workers only touch this bounded Python queue, never Tk or the result model.
        while not self._closing and scan_id == self._scan_id:
            if cancel is not None and cancel.is_set():
                return
            try:
                self._scan_events.put((scan_id, kind, payload), timeout=0.1)
                return
            except queue.Full:
                continue

    def _drain_scan_events(self):
        if self._closing:
            return
        for _ in range(100):
            try:
                scan_id, kind, payload = self._scan_events.get_nowait()
            except queue.Empty:
                break
            if scan_id != self._scan_id:
                continue
            if kind == "log":
                self.scan_log_box.insert("end", str(payload) + "\n")
            elif kind == "progress":
                self._set_progress(*payload)
            elif kind == "done":
                self._finish_scan(payload)
            elif kind == "signatures":
                generation, updates = payload
                if generation == self._render_generation:
                    for item_id, text in updates:
                        cb = self._checkboxes.get(item_id)
                        if cb is not None:
                            cb.configure(text=text)
        self._scan_workers = {t for t in self._scan_workers if t.is_alive()}
        self._scan_ui_timer = self.after(50, self._drain_scan_events)

    def _start_scan_worker(self, target, *args):
        worker = threading.Thread(target=target, args=args, daemon=True)
        self._scan_workers.add(worker)
        try:
            worker.start()
        except Exception:
            self._scan_workers.discard(worker)
            raise

    def _cancel_render(self):
        self._render_generation += 1
        self._signature_cancel.set()
        if self._render_timer is not None:
            self.after_cancel(self._render_timer)
            self._render_timer = None

    def _clear_scan_results(self):
        self._cancel_render()
        for widget in self.file_scroll_frame.winfo_children():
            widget.destroy()
        self.file_checkbuttons.clear()
        self._checkboxes.clear()
        self._selection.clear()
        self.danger_files.clear()
        self.scan_results.clear()
        self.proc_btn.configure(state="disabled")
        self.scan_log_box.delete("1.0", "end")
        self._set_progress(0, "准备就绪")

    def prepare_scan_ui(self):
        # Called by the UI thread before a worker can publish anything.
        self._clear_scan_results()

    def _remember_selection(self):
        for item_id, cb in self._checkboxes.items():
            self._selection[item_id] = bool(cb.get())

    def toggle_all(self):
        self._remember_selection()
        eligible = [f['item_id'] for f in self.danger_files if f.get('can_quarantine')]
        new_state = not all(self._selection.get(item_id, False) for item_id in eligible)
        for item_id in eligible:
            self._selection[item_id] = new_state
            cb = self._checkboxes.get(item_id)
            if cb is not None:
                cb.select() if new_state else cb.deselect()
        self.update_btn_text()

    def update_btn_text(self):
        self._remember_selection()
        enabled = any(f.get('can_quarantine') and self._selection.get(f['item_id'], False)
                      for f in self.danger_files)
        self.proc_btn.configure(state="normal" if enabled and not self.scanning else "disabled")

    def process_selected(self):
        if self.scanning or self._closing:
            return
        self._remember_selection()
        removed = set()
        for item in self.danger_files:
            item_id = item['item_id']
            if not item.get('can_quarantine') or not self._selection.get(item_id, False):
                continue
            try:
                expected_hash = item.get('sha256')
                if not expected_hash:
                    raise ValueError("缺少扫描时的文件摘要，请重新扫描后再隔离")
                result = quarantine(item['path'], expected_sha256=expected_hash)
            except Exception as exc:
                result = {'status': 'failed', 'error': str(exc)}
            item['quarantine_result'] = dict(result)
            item['remediation_state'] = result['status']
            item['error'] = result.get('error') or ''
            archive = result.get('archive_path') or '无已发布归档'
            if result['status'] == 'isolated':
                removed.add(item_id)
                self.scan_log_box.insert("end", f"已隔离 {item['path']} -> {archive}\n")
                if item['error']:
                    self.scan_log_box.insert("end", f"隔离清理提示: {item['error']}\n")
            else:
                state = '已保存副本，但原文件未确认移除' if result['status'] == 'copied_not_removed' else '隔离失败，未确认移除原文件'
                self.scan_log_box.insert("end", f"{state} {item['path']} -> {archive}: {item['error']}\n")
        # Keep unchecked, failed and not-yet-rendered items; never rebuild by checkbox index.
        self.danger_files = [f for f in self.danger_files if f['item_id'] not in removed]
        for item_id in removed:
            self._selection.pop(item_id, None)
        self.refresh_list()
        if removed:
            self.scan_log_box.insert("end", f"已隔离 {len(removed)} 个文件\n")

    @staticmethod
    def _result_text(item):
        label = os.path.basename(item.get('path') or '') or item.get('engine', '扫描结果')
        detail = ' '.join(str(part) for part in (item.get('type'), item.get('error')) if part)
        remediation = {'copied_not_removed': '仅保存副本，原文件未确认移除',
                       'failed': '隔离失败', 'isolated': '已隔离'}.get(item.get('remediation_state'), '')
        return f"{label} [{item['status']}] {remediation} {detail} 恶意({item.get('malicious', '-')})"

    def refresh_list(self):
        self._remember_selection()
        self._cancel_render()
        for widget in self.file_scroll_frame.winfo_children():
            widget.destroy()
        self.file_checkbuttons.clear()
        self._checkboxes.clear()
        self._remaining_to_add = deque(dict(f) for f in self.danger_files)
        self._render_timer = self.after(10, lambda g=self._render_generation: self._add_batch(g))

    def _add_batch(self, generation):
        if self._closing or generation != self._render_generation:
            return
        self._render_timer = None
        for _ in range(20):
            if not self._remaining_to_add:
                break
            item = self._remaining_to_add.popleft()
            item_id = item['item_id']
            cb = ctk.CTkCheckBox(self.file_scroll_frame, text=self._result_text(item),
                               command=self.update_btn_text)
            cb.pack(anchor="w", padx=5)
            if item.get('can_quarantine'):
                if self._selection.setdefault(item_id, True):
                    cb.select()
            else:
                self._selection[item_id] = False
                cb.configure(state="disabled")
            self.file_checkbuttons.append(cb)
            self._checkboxes[item_id] = cb
        self.update_btn_text()
        if self._remaining_to_add:
            self._render_timer = self.after(10, lambda: self._add_batch(generation))
        elif self.sig_var.get():
            # Capture IDs, paths and option on the UI thread, not in the worker.
            snapshot = tuple((f['item_id'], f.get('path'), self._result_text(f))
                             for f in self.danger_files if f.get('can_quarantine'))
            self._signature_cancel = threading.Event()
            self._start_scan_worker(self._update_signatures, self._scan_id, generation,
                                    snapshot, self._signature_cancel)

    def _update_signatures(self, scan_id, generation, snapshot, cancel):
        updates = []
        for item_id, path, text in snapshot:
            if cancel.is_set() or self._closing:
                return
            valid = check_digital_signature(path)
            updates.append((item_id, text + (" 签名有效" if valid else " 签名无效或无法验证")))
        self._post_scan_event(scan_id, "signatures", (generation, updates), cancel)

    def start_scan_thread(self):
        if self.scanning or self._closing:
            messagebox.showinfo("提示", "已有扫描任务正在运行或程序正在关闭")
            return
        mode = self.scan_mode.get()
        target = None
        allow_upload = False
        if mode in ("单文件查杀", "文件夹查杀"):
            if not self.config.get('virustotal'):
                messagebox.showinfo("提示", "请开启virustotal云查杀引擎")
                return
            if not self.config.get('apikey', '').strip():
                messagebox.showerror("提示", "API Key为空")
                return
            target = filedialog.askopenfilename() if mode == "单文件查杀" else filedialog.askdirectory()
            if not target:
                return
            allow_upload = messagebox.askyesno(
                "本次任务的文件上传授权",
                f"默认仅向VirusTotal发送文件SHA256进行查询。\n目标: {target}\n\n"
                "是否允许本次任务将未收录且不超过30MB的文件完整上传？"
                "文件夹模式包含其子目录。文件内容可能与第三方安全研究人员共享，"
                "请勿上传敏感文件。选择‘否’仍会进行哈希查询。",
                default="no")
            scan_func = self.single_file_scan if mode == "单文件查杀" else self.folder_scan
        else:
            scan_func = self.full_scan
        self._scan_cancel.set()
        self._scan_id += 1
        self._scan_cancel = threading.Event()
        task = MappingProxyType({'scan_id': self._scan_id, 'cancel': self._scan_cancel,
                                 'allow_network': mode in ('单文件查杀', '文件夹查杀'),
                                 'allow_upload': bool(allow_upload),
                                 'config': MappingProxyType(dict(self.config))})
        self.prepare_scan_ui()
        self.scanning = True
        self.exec_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        try:
            self._start_scan_worker(self._safe_scan, scan_func, target, task)
        except Exception as exc:
            self._finish_scan({'results': [], 'status': 'failed', 'message': f"无法启动扫描: {exc}"})

    def cancel_scan(self):
        if self.scanning:
            self._scan_cancel.set()
            self.cancel_btn.configure(state="disabled")
            self._set_progress(0, "正在取消；等待当前请求返回，不会继续上传或查询")

    def _safe_scan(self, scan_func, target, task):
        try:
            outcome = scan_func(target, task)
        except Exception as exc:
            outcome = {'results': [], 'status': 'failed', 'message': f"扫描失败: {exc}"}
        if task['cancel'].is_set():
            message = outcome.get('message', '')
            outcome = dict(outcome, status='cancelled', message=(message + " 扫描已取消；保留已取得结果，未检查部分不代表安全").strip())
        self._post_scan_event(task['scan_id'], "done", outcome)

    def _finish_scan(self, outcome):
        self.scanning = False
        self.exec_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.scan_results = outcome['results']
        self.danger_files = [f for f in self.scan_results
                             if f['verdict'] not in ('not_flagged', 'whitelisted')]
        unresolved = sum(f['status'] != 'completed' for f in self.scan_results)
        malicious = sum(f['verdict'] == 'malicious' for f in self.scan_results)
        message = outcome.get('message') or f"任务结束：危险 {malicious} 项，未判定/失败 {unresolved} 项（不代表其余文件绝对安全）"
        self.scan_log_box.insert("end", message + "\n")
        self._set_progress(100 if outcome['status'] == 'completed' else 0, message)
        self.refresh_list()

    @staticmethod
    def _scan_result(task, path, status='unknown', verdict='unknown', engine='VirusTotal', **extra):
        return dict(scan_id=task['scan_id'], item_id=uuid4().hex, path=path,
                    status=status, verdict=verdict, engine=engine, error='',
                    remediation_state='not_attempted', can_quarantine=False, **extra)

    def _scan_vt_file(self, path, task, whitelist_hashes, poll_attempts):
        from core.scanning import scan_vt_file
        return scan_vt_file(path, task, whitelist_hashes, poll_attempts)

    def _scan_vt_path(self, target, task, poll_attempts):
        from core.scanning import scan_path
        whitelist = load_whitelist()
        hashes = {item.get('hash') for item in whitelist if item.get('hash')}
        completed = 0

        def on_event(event):
            nonlocal completed
            if event['type'] == 'result':
                completed += 1
                event['result']['scan_id'] = task['scan_id']
                self._post_scan_event(task['scan_id'], "progress", (
                    0, f"扫描中，已完成 {completed} 项: {os.path.basename(event['result']['path'])}"))

        outcome = scan_path(
            target, 'virustotal', allow_network=task.get('allow_network', False),
            allow_upload=task['allow_upload'], api_key=task['config'].get('apikey', ''),
            sensitive=task['config'].get('sensitive', False), whitelist_hashes=hashes,
            cancel_event=task['cancel'], timeout=task.get('timeout', 7200),
            poll_attempts=poll_attempts, on_event=on_event)
        outcome['scan_id'] = task['scan_id']
        for item in outcome['results']:
            item['scan_id'] = task['scan_id']
        return outcome

    def single_file_scan(self, target, task):
        if not os.path.isfile(target):
            return {'results': [], 'status': 'failed', 'message': '目标不是有效文件'}
        return self._scan_vt_path(target, task, 20)

    def full_scan(self, target, task):
        scan_id = task['scan_id']
        self._post_scan_event(scan_id, "progress", (10, "Defender全盘扫描中，请耐心等待"))
        defender = DefenderScanner(
            offline_only=task['config'].get('windows_defender_offline_only', True),
            force_use=task['config'].get('windows_defender_force', False),
            logger=lambda msg: self._post_scan_event(scan_id, "log", msg))
        report = defender.full_scan(cancel_event=task['cancel'])
        items = []
        for threat in report['threats']:
            item = self._scan_result(task, threat.get('path'), report['status'], 'unknown', 'Defender')
            item.update(type=threat.get('name', 'Defender记录'), can_quarantine=False,
                        remediation_state=threat.get('remediation_state', report['remediation_state']))
            items.append(item)
        message = report.get('message') or report.get('error') or '请到Windows安全中心确认扫描及处置结果'
        if not items:
            item = self._scan_result(task, None, report['status'], 'unknown', 'Defender')
            item.update(type=message, error=report.get('error') or '',
                        remediation_state=report['remediation_state'])
            items.append(item)
        return {'results': items, 'status': report['status'], 'message': message}

    def folder_scan(self, target, task):
        if not os.path.isdir(target):
            return {'results': [], 'status': 'failed', 'message': '目标不是有效文件夹'}
        return self._scan_vt_path(target, task, 6)

    def destroy(self):
        if self._closing:
            return
        if self._service_busy and not messagebox.askyesno(
                "服务操作尚未确认", "后台服务操作尚未返回。关闭窗口不会撤回已提交的请求，结果可能无法显示。\n仍要关闭吗？",
                parent=self):
            return
        self._closing = True
        recording_cancel = getattr(self, '_record_cancel', None)
        if recording_cancel is not None:
            recording_cancel.set()
        self._shutdown_during_scan = self.scanning
        self._scan_cancel.set()
        self._signature_cancel.set()
        self._cancel_render()
        self.exec_btn.configure(state="disabled")
        self.cancel_btn.configure(state="disabled")
        self.proc_btn.configure(state="disabled")
        self._cleanup_all_rick_popups()
        for timer in (getattr(self, 'ad_check_timer', None),
                      getattr(self, 'suspended_timer_id', None), self._scan_ui_timer, self._service_ui_timer):
            if timer is not None:
                self.after_cancel(timer)
        if self.ad and self.ad.running:
            # Active-defense lifecycle is a separate repair batch; do not enable it here.
            threading.Thread(target=self.ad.stop, daemon=True).start()
        self._wait_for_scan_workers(time.monotonic() + 5)

    def _wait_for_scan_workers(self, deadline):
        alive = [worker for worker in self._scan_workers if worker.is_alive()]
        if alive and time.monotonic() < deadline:
            self._set_progress(0, "正在关闭，等待扫描工作线程退出...")
            self.after(50, lambda: self._wait_for_scan_workers(deadline))
            return
        # A requests call cannot be force-cancelled safely. Late workers cannot touch Tk.
        if alive or self._shutdown_during_scan:
            messagebox.showwarning(
                "关闭时的扫描状态",
                "已请求取消扫描，但关闭窗口不代表所有请求或处置都已完成。"
                "若使用了Defender，结束MpCmdRun客户端也不代表服务扫描停止，"
                "请到Windows安全中心确认检测与处置状态。"
                + (" 仍有后台请求尚未返回。" if alive else ""))
        if getattr(sys, 'app', None) is self:
            sys.app = None
        super().destroy()
