import os, subprocess
from utils.logging import main_log
from utils.network import is_offline

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
