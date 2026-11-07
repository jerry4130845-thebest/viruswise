import os
import subprocess
import time

from utils.logging import main_log
from utils.network import is_offline


class DefenderScanner:
    name = "Windows Defender"
    SCAN_TIMEOUT = 7200
    WAIT_INTERVAL = 0.25
    CLIENT_STOP_TIMEOUT = 2

    def __init__(self, offline_only=True, force_use=False, logger=None):
        self._log = main_log if logger is None else logger
        self.available = False
        self.offline_only = offline_only
        self.force_use = force_use
        self.mpcmdrun_path = os.path.join(
            os.environ.get('ProgramFiles', r'C:\Program Files'),
            'Windows Defender', 'MpCmdRun.exe'
        )
        self._check_available()

    def _check_available(self):
        if os.path.exists(self.mpcmdrun_path):
            self.available = True
            self._log("Windows Defender (MpCmdRun) 可用")
        else:
            self.available = False
            self._log(f"找不到 MpCmdRun.exe: {self.mpcmdrun_path}")

    def should_use(self):
        if not self.available:
            return False
        if self.force_use:
            return True
        if self.offline_only:
            return is_offline()
        return True

    @staticmethod
    def _result(status, returncode=None, error=None, message=""):
        """Return execution state, never infer a clean verdict from empty threats.

        A future trusted structured provider may populate threats with dictionaries
        containing name/path/remediation_state/can_quarantine. MpCmdRun's localized
        text is not such a provider: neither a scan target nor a text fragment is
        evidence of an infected file. No quarantine paths are exposed here.
        """
        return {
            'status': status,
            'returncode': returncode,
            'threats': [],
            'error': error,
            'remediation_state': 'unknown',
            'can_quarantine': False,
            'message': message + " 需到 Windows 安全中心确认检测及处置结果。",
        }

    def _stop_client(self, process):
        """Bounded cleanup of our client only, not the Defender service scan."""
        for action in (process.terminate, process.kill):
            try:
                if process.poll() is not None:
                    return ""
                action()
                process.wait(timeout=self.CLIENT_STOP_TIMEOUT)
                return ""
            except (OSError, subprocess.TimeoutExpired):
                # Terminate may race with normal exit; still try a bounded reap.
                continue
        return " 无法确认 MpCmdRun 客户端已退出。"

    def _run_scan(self, arguments, cancel_event=None):
        """Wait cooperatively; cancellation never claims the service has stopped."""
        if cancel_event is not None and cancel_event.is_set():
            return self._result('cancelled', message="已取消，未启动扫描客户端。")
        if not self.available:
            return self._result(
                'unavailable', error="MpCmdRun.exe 不可用",
                message="无法启动 Windows Defender 扫描。",
            )

        process = None
        try:
            deadline = time.monotonic() + self.SCAN_TIMEOUT
            # Do not parse localized console output or leave unread PIPEs that
            # can deadlock a long scan. Return code is execution evidence only.
            process = subprocess.Popen(
                [self.mpcmdrun_path] + arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            while True:
                cancelled = cancel_event is not None and cancel_event.is_set()
                remaining = deadline - time.monotonic()
                if cancelled or remaining <= 0:
                    cleanup = self._stop_client(process)
                    status = 'cancelled' if cancelled else 'timeout'
                    reason = "用户取消等待" if cancelled else "扫描等待超时"
                    message = (
                        reason + "；已请求结束 MpCmdRun 客户端，"
                        "不代表 Defender 服务扫描已停止。" + cleanup
                    )
                    self._log(message)
                    return self._result(
                        status, returncode=process.returncode,
                        error=None if cancelled else reason, message=message,
                    )
                try:
                    returncode = process.wait(
                        timeout=min(self.WAIT_INTERVAL, remaining)
                    )
                    break
                except subprocess.TimeoutExpired:
                    continue

            self._log(f"Defender 扫描客户端退出，返回码: {returncode}")
            if returncode == 0:
                return self._result(
                    'completed', returncode=returncode,
                    message=("Defender 返回成功：可能未发现威胁，也可能已修复威胁；"
                             "没有可信结构化资源，不能据此断言无毒或提供隔离路径。"),
                )
            # Code 2 can mean unremediated threats OR execution errors. Other
            # nonzero codes also must not be represented as a clean scan.
            return self._result(
                'failed', returncode=returncode,
                error=f"MpCmdRun 返回非零代码: {returncode}",
                message="扫描未能确认成功，可能存在未处置威胁或执行错误。",
            )
        except Exception as exc:
            cleanup = self._stop_client(process) if process is not None else ""
            status = 'unavailable' if isinstance(exc, FileNotFoundError) else 'failed'
            message = "扫描执行失败，不能判断是否存在威胁。" + cleanup
            if process is not None:
                message += " 结束客户端不代表 Defender 服务扫描已停止。"
            self._log(f"{message} {exc}")
            return self._result(
                status,
                returncode=process.returncode if process is not None else None,
                error=str(exc), message=message,
            )

    def full_scan(self, cancel_event=None):
        """Return a structured result; optionally observe a threading.Event."""
        self._log("正在请求 Windows Defender 全盘扫描，请耐心等待...")
        return self._run_scan(['-Scan', '-ScanType', '2'], cancel_event)

    def scan_drive(self, drive, cancel_event=None):
        """Scan a target without ever treating that target as an infected file."""
        if cancel_event is not None and cancel_event.is_set():
            return self._result('cancelled', message="已取消，未启动扫描客户端。")
        try:
            # Reject empty targets instead of silently turning them into cwd.
            target = os.fspath(drive)
            if not isinstance(target, str) or not target.strip():
                raise ValueError("扫描目标必须是非空路径")
            norm_drive = os.path.normpath(target)
            if not os.path.exists(norm_drive):
                raise FileNotFoundError(f"扫描目标不存在: {drive}")
        except (TypeError, ValueError, OSError) as exc:
            self._log(str(exc))
            return self._result(
                'failed', error=str(exc), message="扫描目标无效，未启动扫描。",
            )
        self._log(f"正在请求扫描 {norm_drive} ...")
        return self._run_scan(
            ['-Scan', '-ScanType', '3', '-File', norm_drive], cancel_event
        )
