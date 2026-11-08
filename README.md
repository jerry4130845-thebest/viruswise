VirusWise - Active Defense Security Platform

## English Version

### Overview
VirusWise is a Python-based Active Defense security platform designed to detect, analyze, and respond to potentially malicious process behavior in real-time. It combines multiple protection layers including process monitoring, behavioral scoring, Windows Defender integration, and cloud-based VirusTotal scanning.

### Features
- Active Defense Engine (P0-P5):
  - P0: Service integration, self-protection, and directory ACL protection
  - P1: WMI process creation monitoring with polling fallback
  - P2: Restart Manager attribution and handle snapshot caching
  - P3: Behavioral scoring with sliding window and action ladder
  - P4: Two-tier priority queue with backpressure
  - P5: Configuration integrity with HMAC verification
- Windows Service: Runs as LocalSystem service (VirusWiseActiveDefense)
- Windows Defender Integration: Full system scans via MpCmdRun.exe
- VirusTotal Cloud Scanning: Optional API-integrated malware analysis
- Process Whitelist: Name and hash-based allowlisting
- Quarantine: Isolate detected threats
- Digital Signature Verification: Check file legitimacy
- Behavioral Scoring: Score-based threat assessment (0-80+)
- Auto-Startupl Management: Autoruns tool integration
- Customizable Themes: Interface personalization

### Building

#### Prerequisites
- Python 3.8 or higher
- Windows operating system (service features require Windows)
- Administrator privileges for service installation

#### Installation
1. Clone or download the project
2. Prepare an environment with `pywin32`, `psutil`, `requests`, `customtkinter`, `Pillow` and `win10toast`. There is currently no dependency manifest. `win10toast` needs setuptools with `pkg_resources` (development environment: setuptools 65.5.0). EXE builds additionally need PyInstaller.

3. Configure the application:
   - Use the GUI settings page; do not edit Python source to configure preferences
   - Set your VirusTotal API key (optional but recommended for cloud scanning)
   - Configure monitored directories in settings

4. Run the application:
   python main.py

#### Source and EXE deployment

[main.py](<main.py>) now separates GUI, service management, CLI and SCM hosting. No arguments open the GUI; other modes are dispatched before GUI imports, data-directory initialization or GUI elevation.

**Build the Windows onedir distribution** using [viruswise.spec](<viruswise.spec>) in an environment with PyInstaller and the runtime dependencies:

~~~powershell
python -B -m PyInstaller viruswise.spec
# Read-only checks, no service installation or startup:
.\dist\VirusWise\VirusWise.exe --help
.\dist\VirusWise\VirusWise.exe --cli doctor --json
~~~

Deploy the **entire generated directory** to its final location, not just the EXE. This is onedir with a console, not onefile or windowed mode; the GUI may also show a console. The executable manifest does not require elevation. Only the existing no-argument GUI path may request UAC. The bundle includes Python runtime libraries; target-system compatibility still needs verification.

The spec uses standard hooks, explicit native/service imports, toast icon/metadata and a theme extracted from [ui/theme.py](<ui/theme.py>). It never collects existing user configuration, keys, whitelists, logs or quarantine data. Build-tool support is separate from the source Python minimum: the development build uses Python 3.11 and PyInstaller 6.20.0. The spec does not install dependencies.

**Install** from an administrator PowerShell. Choose source OR EXE deployment, not both:

~~~powershell
# Source, from the project root:
python -B main.py --install
# OR EXE, from its final deployment directory:
.\VirusWise.exe --install
~~~

Installation only registers `VirusWiseActiveDefense` as LocalSystem / manual start / own process. It does **not** start protection, record a whitelist, modify directory ACLs or enable boot-time startup. Source ImagePath uses the absolute Python interpreter plus [main.py](<main.py>) and `--service`; EXE ImagePath uses the absolute deployed executable plus `--service`, never a temporary extraction path. Keep that deployment and its dependencies in place and accessible to LocalSystem. Use an administrator-protected production directory: user-writable service code is unsafe.

An identical registration returns `already_installed`; a same-name service with a different command/account/startup/type returns `deployment_mismatch` without modification. Before moving or switching source/EXE deployment, stop and uninstall using the original deployment, then install at the new location. Legacy registrations may require administrator review; they are never silently adopted or overwritten.

**Query/start** via the controller. Choose the commands matching your deployment; start only when intended:

~~~powershell
# Source; python -B cli.py ... remains supported:
python -B main.py --cli defense status --json
python -B main.py --cli defense start --allow-system-effects --timeout 120 --json
# EXE equivalents:
.\VirusWise.exe --cli defense status --json
.\VirusWise.exe --cli defense start --allow-system-effects --timeout 120 --json
~~~

Non-GUI startup retains the one-hour baseline freshness and snapshot-identity checks and may record/persist a fresh 30-second baseline. The controller passes the snapshot through SCM start arguments. Do not use no-argument `net start` or the Services app: missing-snapshot startup is refused. `--service` is the internal SCM dispatcher, not a manual defense-start command; interactive dispatch fails. Installation success and SCM RUNNING are not protection readiness. Startup still returns `ready=false` / exit `6` until readiness acknowledgement is implemented.

**Stop, then uninstall** only when removal is intended. Choose one deployment and verify stop succeeded before uninstalling:

~~~powershell
# Source:
python -B main.py --cli defense stop --allow-system-effects --timeout 120 --json
python -B main.py --uninstall
# OR EXE:
.\VirusWise.exe --cli defense stop --allow-system-effects --timeout 120 --json
.\VirusWise.exe --uninstall
~~~

Uninstall verifies the deployment and requires a stopped service; it never implicitly stops it. Only registration is removed; program files, configuration, whitelist and logs are preserved. Open service handles can defer Windows deletion: `pending_delete` / exit `6` means unconfirmed. Only a follow-up SCM query confirming absence yields `uninstalled` / exit `0`. Uninstalling an absent service returns `not_installed` / exit `3`.

**Management output:** `--install` / `--uninstall` are mutually exclusive and accept no extra parameters (do not append `--json`). They output a controller-result JSON object with `ok`, `ready`, `code`, `exit_code`, and the corresponding `install_requested` / `uninstall_requested` flag, **not** the CLI envelope. Invalid-argument/platform errors can occur before the controller runs. Codes: `2` invalid arguments, `3` unavailable/not installed, `4` denied, `5` failure, `6` deletion unconfirmed, `130` interrupted. Requested flags preserve possible effects after failure/interruption; query before retrying. No automatic elevation occurs. `--cli ...` retains the CLI JSON/JSONL schema and consent flags; its capabilities describe the CLI, not the separate installer.

Python subprocess callers can use `[r"C:\Apps\VirusWise\VirusWise.exe", "--cli", "doctor", "--json"]` in place of the source argument list shown below, preserving JSON parsing, timeouts and exit-code checks. Build/read-only smoke tests do not validate the SCM lifecycle or protection effectiveness; perform real lifecycle tests only on an explicitly authorized Windows test system.

### Usage

#### Graphical User Interface (GUI)
Run python main.py to launch the graphical interface:

1. Main Page: Overview of system status and recent logs
2. Scan Page: 
   - Select scan mode: Single file, Folder, or Full system (Defender)
   - Choose scan engines: VirusTotal, Windows Defender, or both
   - Start scanning and view results
   - Isolate detected threats to quarantine
3. Settings Page:
   - Configure scan engines and API keys
   - Set up monitored directories for active defense
   - Adjust behavioral scoring thresholds
   - Manage whitelist rules (name/hash based)
   - Select UI themes
   - Enable/disable active defense
4. Tools Page:
   - Manage auto-startup entries
   - Create desktop shortcuts
   - Open quarantine folder
   - Rickroll easter egg (Ctrl+Shift+R or click 千万别点)
5. Suspended Processes: View and manage processes currently on hold
6. Whitelist: View and manage allowed processes

#### Command-Line Usage

The GUI still starts with `python main.py`. Automation uses the independent [CLI entry point](<cli.py>), [shared scanner](<core/scanning.py>), and [installed-service controller](<core/defense_control.py>). Help, `capabilities`, and `doctor` remain standard-library-only, without GUI startup, elevation, configuration reads, network access, or application-directory creation.

Run from the project root:

~~~text
python -B cli.py --help
python -B cli.py capabilities --json
python -B cli.py doctor --json
python -B cli.py defense status --json

# Examples below explicitly authorize side effects; do not run against sensitive/test data casually.
python -B cli.py scan "C:\Samples\sample.exe" --engine defender --allow-system-effects --timeout 120 --json
python -B cli.py scan "C:\Samples" --engine virustotal --allow-network --timeout 120 --json
python -B cli.py scan "C:\Samples\sample.exe" --engine virustotal --allow-network --allow-upload --timeout 120 --json
python -B cli.py defense start --allow-system-effects --timeout 120 --json
python -B cli.py defense stop --allow-system-effects --timeout 120 --json
~~~

**Scanning and consent**

- Supply the VT key through the process environment variable `VIRUSWISE_VT_API_KEY`. CLI scanning does not read the GUI key/configuration or silently change engines. Do not place secrets in command arguments or shared logs.
- `--allow-network` permits VT SHA256 lookup. Upload of an unlisted file additionally needs `--allow-upload` and is limited to 30 MB. Directory targets include their files and subdirectories. Uploaded content may be shared with third parties; hash lookup also discloses a file identifier.
- Defender requires `--allow-system-effects` because Windows Defender may remediate files and use its own cloud/network policy. No network probe is used to silently choose an engine. Client exit zero is execution evidence, **not proof that files are clean**; verify detections/remediation in Windows Security.
- GUI file/folder scanning reuses the same scanner, preserving per-task upload consent, sensitivity and scan IDs. GUI supplies its existing whitelist; CLI does not silently load it for scanning. Whitelist-skipped files remain unscanned, not certified safe. GUI VT task budget defaults to 7200 seconds; CLI defaults to 120.

**Active defense and the one-hour whitelist rule**

- Only the already-installed `VirusWiseActiveDefense` Windows service can be queried/started/stopped. There is no implicit installation, elevation, restart, or communication with an existing GUI. `defense status` is read-only, but unlike `doctor` it reads local baseline metadata. Stop does not record a new whitelist.
- Before **non-GUI `defense start`**, reuse a readable valid whitelist only when `0 <= now - last_whitelist_recorded_at <= 3600` seconds. A missing/corrupt baseline, absent/malformed/future/expired timestamp, or mismatched saved snapshot requires a new recording lasting **at least 30 seconds**. Exactly one hour is still valid.
- The recorder enumerates and hashes real running executables. Keep the machine in a known-clean state and do not launch test programs during recording. Individual inaccessible processes are reported, not silently declared safe; failure to enumerate or hash any executable blocks completion. Successful whitelist persistence and readback precede recording the success timestamp and snapshot identity in config.
- Failed/cancelled/timed-out recording or save does not advance the success timestamp and does not permit service startup/tests. A whitelist write can already have occurred before a later config save fails; it is not treated as a successful recording. Ordinary GUI settings saves preserve recording metadata. GUI manual recording updates it but **does not enforce hourly freshness**.
- If the service is already active with a stale baseline, startup refuses to learn under active enforcement; explicitly stop it first. There is no automatic stop/restart. A bounded snapshot is handed through SCM startup arguments, not the LocalSystem profile; an oversized snapshot is refused.
- **SCM RUNNING is not a whitelist-loaded acknowledgement.** Start currently returns `ready=false` / `readiness_unconfirmed` (exit 6) even when Windows accepted startup. Status likewise never certifies protection. Do not use these results to authorize destructive tests. The updated service requires a valid startup snapshot; legacy/no-argument service startup is refused rather than silently using another account's whitelist. Older installed service code may ignore startup arguments and must not be assumed compatible.
- Current active defense has no enabled directory watcher (`WATCHDOG_AVAILABLE=False`); `monitor_dirs` does not implement file monitoring. Process enforcement consults the loaded whitelist before block-rule termination or scoring/suspension. This is not a promise of comprehensive file protection.

**Output, deadlines, and limitations**

- Default output / `--json`: one final JSON object. `--jsonl`: currently only one final event with `"event":"result"`, not streaming progress. The flags are mutually exclusive. Plain help is text; machine-format help uses the response envelope.
- Envelope: `schema_version` (`"1.0"`), `request_id`, `command`, `status`, `result`, `errors`. Errors include `code`, `message`, `next_action`. Inspect per-file verdicts, service state and `ready`, not just the outer status or exit code. Unknown/pending/partial/unscanned is never equivalent to clean.
- `--timeout` is a positive finite **cooperative operation budget**, not a hard wall-clock deadline. VT requests have connect/read inactivity bounds; hashing, filesystem/SCM calls and in-flight requests may exceed the budget before the next check. Expired baseline recording needs more than 30 seconds of available budget. Cancellation/timeout does not roll back saved data, uploads, remediation or a requested service transition. Stopping the Defender client does not prove its system service stopped scanning.
- `doctor` performs local-only dependency discovery, not dependency imports or runtime health tests. Network/reparse/archive/unverifiable search locations are skipped. `discoverable` and executable `present` are not readiness findings. Unsupported/unverified checks remain explicit.
- No test execution, cleanup command or GUI IPC is implemented; `test` returns unavailable. Initialization/output interruption can leave no complete response. The [plan](<plan.md>) includes future work, not guaranteed implemented capabilities.

| Exit code | Meaning |
| --- | --- |
| 0 | Command completed; not a clean-file or protection certificate |
| 2 | Missing, invalid or conflicting arguments |
| 3 | Capability, platform, installed service or dependency unavailable |
| 4 | Explicit authorization or operating-system permission missing |
| 5 | Execution, persistence or output failure |
| 6 | Partial or unconfirmed result, including unacknowledged service readiness |
| 124 | Cooperative operation budget expired, not a hard I/O timeout guarantee |
| 130 | Cancelled/interrupted |

#### Calling VirusWise from a terminal or another program

**Choose the entry point:** use [main.py](<main.py>) for the GUI (it may request UAC and initialize application data); use [cli.py](<cli.py>) for automation without GUI startup. Run commands from the project root after installing the dependencies above. The directory-built EXE accepts the same CLI arguments after `--cli`: replace `python -B cli.py` with `VirusWise.exe --cli`. Separate install/uninstall modes are documented above.

**1. Windows PowerShell: launch, configure a session key, and capture the exit code**

The VT command below performs a real network hash lookup, but does not authorize upload. Upload additionally requires `--allow-upload`. Keep the key out of shared terminal history/logs; remove it from the session when finished.

~~~powershell
# Replace this with your checkout path, then use its Python environment.
Set-Location 'C:\path\to\viruswise'
python -B main.py
# The GUI command above blocks until the GUI exits; run CLI calls in another terminal.
python -B cli.py doctor --json

# Set only in this PowerShell session. Substitute your own key; do not commit it.
$env:VIRUSWISE_VT_API_KEY = '<your-api-key>'
python -B cli.py scan 'C:\Samples\sample.exe' --engine virustotal --allow-network --timeout 120 --json
$scanExitCode = $LASTEXITCODE
Write-Host "Scan exit code: $scanExitCode"
Remove-Item Env:VIRUSWISE_VT_API_KEY
~~~

**2. Recommended integration: invoke the CLI as a subprocess**

The following complete example runs the read-only `doctor` command. The commented replacement shows how to invoke a scan. Keep each argument separate and do not use `shell=True`; use an absolute checkout path so the caller can run from another working directory. If using a different Python environment, replace `sys.executable` with that interpreter’s absolute path.

~~~python
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"C:\path\to\viruswise")  # Change to your checkout.
# Use the interpreter/environment in which VirusWise dependencies are installed.
args = [sys.executable, "-B", str(ROOT / "cli.py"), "doctor", "--json"]
# To scan with explicit consent, replace the command tail after cli.py with:
# ["scan", r"C:\Samples\sample.exe", "--engine", "virustotal",
#  "--allow-network", "--timeout", "120", "--json"]
# VIRUSWISE_VT_API_KEY is inherited from this process environment, not argv.
try:
    completed = subprocess.run(
        args, cwd=str(ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False, timeout=180,
    )
except subprocess.TimeoutExpired:
    raise RuntimeError("Caller wait expired; external effects may still be active")

try:
    response = json.loads(completed.stdout)
except json.JSONDecodeError:
    raise RuntimeError("No complete JSON response; inspect stderr locally")

print("exit_code:", completed.returncode)
print("status:", response["status"])
print("result:", response["result"])
print("errors:", response["errors"])
# Nonzero responses can contain useful evidence; do not discard them via check=True.
# Exit 0 is not a clean-file certificate; exit 6 / ready=False must not unlock tests.
~~~

The subprocess timeout above only bounds the caller’s wait and may terminate the CLI. It is separate from the CLI’s cooperative `--timeout` budget and cannot undo an upload, Defender remediation, saved whitelist, or SCM request. On a missing/truncated response, do not infer success.

**3. Direct Python API: scan a file or directory**

Run these snippets from the project root, or explicitly include that directory in your host process’s Python import path. This call performs a real lookup. Set `VIRUSWISE_VT_API_KEY` first; unlike the CLI wrapper, the scanner requires `api_key` to be passed explicitly.

~~~python
import os
import threading
from core.scanning import ScanError, scan_path

cancel = threading.Event()
try:
    result = scan_path(
        r"C:\Samples\sample.exe", engine="virustotal",
        api_key=os.environ["VIRUSWISE_VT_API_KEY"],
        allow_network=True, allow_upload=False, timeout=120,
        cancel_event=cancel,
    )
except ScanError as exc:
    print({"code": exc.code, "exit_code": exc.exit_code})
else:
    print(result["status"], result["verdict"])
    for item in result["results"]:
        print(item)
# Another thread can call cancel.set(); cancellation is cooperative.
# For Defender, replace the call arguments with:
# scan_path(r"C:\Samples", engine="defender", allow_system_effects=True, timeout=120)
~~~

`scan_path()` returns a scan dictionary, **not** the CLI JSON envelope. Preflight failures raise `ScanError`; operational failures/partial results are normally returned through `status` and per-file results. A directory path scans recursively. Optional `on_event` receives scan dictionaries with `type` and `scan_id`; callbacks run synchronously and should not block or raise.

**4. Direct Python API: query/start/stop installed active defense**

The `start()` below is a real authorized operation: it can record/save the whitelist and request service startup. It enforces the hourly policy internally; callers do not need to record first. Keep the machine known-clean while recording. No service installation or automatic elevation is performed.

~~~python
from core.defense_control import start, status, stop

print(status())  # Read-only query of the installed service and baseline metadata.
result = start(allow_system_effects=True, timeout=120)
print(result)
if not result["ready"]:
    print("Protection readiness is not confirmed; do not run dependent tests.")

# Separate, deliberate stop operation; never implicit cleanup after an uncertain start:
# result = stop(allow_system_effects=True, timeout=120)
~~~

These APIs return `{ok, ready, code, exit_code, ...}` dictionaries, not the CLI envelope. `status()` succeeding only confirms the query. All current results have `ready=False`; even SCM `RUNNING` after `start()` returns `readiness_unconfirmed` / exit code `6`. `start()` and `stop()` also accept `cancel_event` and `on_event`; service/recording events use `event` rather than the scanner’s `type` field. Do not confuse these callback formats.

**5. Optional explicit whitelist recording**

Only use this when you deliberately want to learn and persist a new baseline. It enumerates/hashes running executables for at least 30 seconds and writes whitelist/configuration data; it is not a read-only probe and does not start defense. Normally `start()` handles this automatically. GUI manual recording also handles pausing its own defense; a direct recorder call does not pause GUI/service enforcement for you.

~~~python
from core.whitelist_recording import record_whitelist

result = record_whitelist(duration=30, timeout=120)
print(result["ok"], result["code"])
# ok=True means recording was committed, not that defense is ready.
~~~

#### Configuration
Prefer the GUI for preferences. The [configuration loader](<utils/config.py>) resolves the data directory lazily. Boolean values in the text format are `1`/`0`; monitored paths are separated by `|`. CLI scans do not read this GUI API key. The final two fields below are maintained together by successful recording; leave them empty before the first recording, and do not fabricate or manually advance them. A missing or mismatched snapshot identity also requires re-recording.

~~~ini
apikey=
sensitive=0
auto_process=0
virustotal=1
windows_defender=0
windows_defender_offline_only=1
windows_defender_force=0
ad_enabled=0
delete_protection=1
batch_delete_threshold=5
modify_protection=1
monitor_dirs=C:/example/one|D:/example/two
wl_by_name=0
wl_by_hash=1
ad_warned_on_enable=0
theme=default
last_whitelist_recorded_at=
last_whitelist_snapshot_id=
~~~

### Protection Levels
The system uses a multi-tiered scoring approach:

| Score Range | Action |
|------------|--------|
| 0-20 | Logging only |
| 20-50 | Alert notification |
| 50-80 | High-priority alert + process marking |
| 80+ | Top-tier blocking: suspend/terminate process, persist block rules |

### Logging
All operations are logged with timestamps. View logs in the GUI or check:
- crash.log - Exception crash logs
- Console output for real-time monitoring

### Notes
- First run may require white-list recording (30-second process capture)
- Active defense works best with a populated whitelist
- Some features require administrator privileges
- Windows service requires LocalSystem account for optimal protection

---

# VirusWise - 主动防御安全平台

## 中文版本

### 概述
VirusWise 是一个基于 Python 的主动防御安全平台，旨在实时检测、分析和响应潜在的恶意进程行为。它结合了多层保护机制，包括进程监控、行为评分、Windows Defender 集成和 VirusTotal 云端扫描。

### 功能
- 主动防御引擎 (P0-P5):
  - P0: 服务集成、自保护和目录 ACL 保护
  - P1: WMI 进程创建监控，带轮询兜底
  - P2: Restart Manager 归因和句柄快照缓存
  - P3: 行为评分、滑动窗口和动作阶梯
  - P4: 两级优先队列与背压
  - P5: 配置完整性与 HMAC 持久化
- Windows 服务: 作为 LocalSystem 服务运行 (VirusWiseActiveDefense)
- Windows Defender 集成: 通过 MpCmdRun.exe 进行全系统扫描
- VirusTotal 云端扫描: 可选 API 集成的恶意软件分析
- 进程白名单: 名称和哈希值基础的放行
- 隔离功能: 检测到威胁时隔离
- 数字签名验证: 检查文件合法性
- 行为评分: 基于评分的威胁评估 (0-80+)
- 自动启动管理: Autoruns 工具集成
- 自定义主题: 界面个性化

### 构建

#### 先决条件
- Python 3.8 或更高版本
- Windows 操作系统 (服务功能需要 Windows)
- 管理员权限以安装服务

#### 安装
1. 下载或克隆项目
2. 准备包含 `pywin32`、`psutil`、`requests`、`customtkinter`、`Pillow` 和 `win10toast` 的环境。仓库当前没有依赖清单；`win10toast` 需要提供 `pkg_resources` 的 setuptools（开发环境为 65.5.0）。打包 EXE 另需 PyInstaller。

3. 配置应用程序:
   - 使用 GUI 设置页面配置偏好，不要通过修改 Python 源码配置程序
   - 设置你的 VirusTotal API key (可选，但强烈推荐用于云端扫描)
   - 在设置中配置监控目录

4. 运行应用程序:
   python main.py

#### 源码与 EXE 部署

[main.py](<main.py>) 现在区分 GUI、服务管理、CLI 和 SCM 托管。不带参数才打开 GUI；其他模式在 GUI 导入、数据目录初始化和 GUI 提权之前分流。

**构建 Windows onedir 目录式发行包**：在准备好 PyInstaller 和运行依赖的环境中，使用 [viruswise.spec](<viruswise.spec>)：

~~~powershell
python -B -m PyInstaller viruswise.spec
# 只读检查，不安装或启动服务：
.\dist\VirusWise\VirusWise.exe --help
.\dist\VirusWise\VirusWise.exe --cli doctor --json
~~~

必须把**生成的整个目录**部署到最终位置，不能只拷走 EXE。本次为保留控制台的 onedir，不是 onefile 或 windowed 模式，GUI 也可能伴随控制台。EXE 清单不要求全局提权，只有原有无参数 GUI 路径可能弹出 UAC。发行包包含 Python 运行库，目标机器原则上无需另装 Python，但仍需验证目标环境兼容性。

打包配置采用标准 hooks、显式原生／服务模块入口、通知图标及元数据，以及从 [ui/theme.py](<ui/theme.py>) 常量提取的主题；不收集现存用户配置、密钥、白名单、日志或隔离数据。构建工具的支持范围与源码最低 Python 版本不同：开发构建环境为 Python 3.11、PyInstaller 6.20.0。打包配置不会自动安装依赖。

**安装服务**：在管理员 PowerShell 中按部署方式二选一，不要同时安装源码与 EXE 版本：

~~~powershell
# 源码：在项目根目录
python -B main.py --install
# 或 EXE：在最终部署目录
.\VirusWise.exe --install
~~~

安装仅将 `VirusWiseActiveDefense` 注册为 LocalSystem／手动启动／独立进程服务，**不启动防御、不记录白名单、不修改目录 ACL、不设置开机自启**。源码 ImagePath 使用绝对 Python 解释器路径、[main.py](<main.py>) 和 `--service`；EXE ImagePath 使用最终部署 EXE 的绝对路径和 `--service`，不使用临时解压路径。注册后不要移动部署文件及依赖，须确保 LocalSystem 可访问。正式部署使用管理员保护的目录，让普通用户可替换服务代码是不安全的。

完全相同的注册返回 `already_installed`；同名服务命令、账户、启动类型或服务类型不同，则返回 `deployment_mismatch`，不修改原注册。移动位置或切换源码／EXE 前，应使用原部署停止并卸载，再在新位置安装。旧式注册可能需要管理员人工检查，不会被静默接管或覆盖。

**查询／启动**仍由控制器完成。只选择适合自己部署的命令，确实要启动时才执行 start：

~~~powershell
# 源码；原有 python -B cli.py ... 仍可用：
python -B main.py --cli defense status --json
python -B main.py --cli defense start --allow-system-effects --timeout 120 --json
# EXE 对应命令：
.\VirusWise.exe --cli defense status --json
.\VirusWise.exe --cli defense start --allow-system-effects --timeout 120 --json
~~~

非 GUI 启动仍执行一小时时效和快照身份检查，必要时重新记录并保存 30 秒白名单；控制器通过 SCM 启动参数传入快照。不要用不带快照的 `net start` 或服务管理器启动，缺少快照的启动会被拒绝。`--service` 只是内部 SCM 调度入口，不是人工启动防御命令，直接交互调用会失败。安装成功和 SCM RUNNING 都不代表防护就绪；实现就绪确认协议之前，启动仍返回 `ready=false`／退出码 `6`。

**先停止，再卸载**：仅在确实要移除注册时执行。按部署方式二选一，并确认停止成功后再卸载：

~~~powershell
# 源码：
python -B main.py --cli defense stop --allow-system-effects --timeout 120 --json
python -B main.py --uninstall
# 或 EXE：
.\VirusWise.exe --cli defense stop --allow-system-effects --timeout 120 --json
.\VirusWise.exe --uninstall
~~~

卸载先核对部署身份，并要求服务已停止，不会隐式停止服务。只移除注册，保留程序文件、配置、白名单和日志。其他服务句柄未关闭时，Windows 可能延迟删除：`pending_delete`／退出码 `6` 表示未确认；只有后续 SCM 查询确认不存在才返回 `uninstalled`／退出码 `0`。卸载不存在的服务返回 `not_installed`／退出码 `3`。

**管理命令输出：** `--install`／`--uninstall` 互斥且不接受额外参数（不要追加 `--json`），返回控制器结果 JSON，含 `ok`、`ready`、`code`、`exit_code` 和对应的 `install_requested`／`uninstall_requested`，**不是** CLI 响应信封。参数／平台错误可能在进入控制器前返回。退出码：`2` 参数错误、`3` 不可用／未安装、`4` 拒绝访问、`5` 失败、`6` 删除未确认、`130` 中断。requested 标志在失败／中断后保留可能已提交操作的证据，重试前先查状态；不会自动提权。`--cli ...` 保持原有 JSON／JSONL 协议及授权参数，它的 capabilities 描述 CLI 本身，不是独立安装器。

Python subprocess 调用 EXE 时，可将下文源码示例的参数列表换成 `[r"C:\Apps\VirusWise\VirusWise.exe", "--cli", "doctor", "--json"]`，保留 JSON 解析、超时及退出码检查。构建和只读冒烟测试不等于 SCM 生命周期或防护有效性验证；真实安装／启停／卸载仅在明确授权的 Windows 测试环境执行。

### 使用方法

#### 图形用户界面 (GUI)
运行 python main.py 启动图形界面：

1. 主页: 系统状态概览和最近日志
2. 扫描页:
   - 选择扫描模式: 单文件、文件夹或全系统 (Defender)
   - 选择扫描引擎: VirusTotal、Windows Defender 或 都一样
   - 开始扫描并查看结果
   - 将检测到的威胟隔离到隔离区
3. 设置页:
   - 配置扫描引擎和 API key
   - 设置主动防御监控目录
   - 调整行为评分阈值
   - 管理白名单规则 (基于名称/哈希)
   - 选择 UI 主题
   - 启用/禁用主动防御
4. 工具页:
   - 管理自动启动条目
   - 创建桌面快捷方式
   - 打开隔离区文件夹
   - 彩蛋: 麻花藤 (Ctrl+Shift+R 或点击 千万别点)
5. 已挂起进程: 查看和管理当前处于暂停状态的进程
6. 白名单: 查看和管理允许的进程

#### 命令行使用

GUI 仍通过 `python main.py` 启动。自动化使用独立的 [CLI 入口](<cli.py>)、[共享扫描器](<core/scanning.py>)和[已安装服务控制器](<core/defense_control.py>)。帮助、`capabilities` 和 `doctor` 仍仅依赖标准库，不启动 GUI、不提权、不读配置、不联网，也不创建应用数据目录。

在项目根目录执行：

~~~text
python -B cli.py --help
python -B cli.py capabilities --json
python -B cli.py doctor --json
python -B cli.py defense status --json

# 以下示例明确授权副作用，请勿随意针对敏感数据或测试样本执行。
python -B cli.py scan "C:\Samples\sample.exe" --engine defender --allow-system-effects --timeout 120 --json
python -B cli.py scan "C:\Samples" --engine virustotal --allow-network --timeout 120 --json
python -B cli.py scan "C:\Samples\sample.exe" --engine virustotal --allow-network --allow-upload --timeout 120 --json
python -B cli.py defense start --allow-system-effects --timeout 120 --json
python -B cli.py defense stop --allow-system-effects --timeout 120 --json
~~~

**扫描与授权**

- VT 密钥通过进程环境变量 `VIRUSWISE_VT_API_KEY` 提供。CLI 不读取 GUI 密钥／配置，不自动切换引擎；不要把密钥放进命令行参数或共享日志。
- `--allow-network` 允许向 VT 查询 SHA256；未收录文件的完整上传还必须有 `--allow-upload`，大小限制 30 MB。目录目标包括其文件和子目录。上传内容可能与第三方共享，哈希查询也会披露文件标识。
- Defender 必须显式传入 `--allow-system-effects`：Windows Defender 自身可能处置文件并按系统策略使用云端／网络。显式选择引擎不会触发自动联网探测。客户端返回 0 **不等于无毒**，检测和处置结果应到 Windows 安全中心确认。
- GUI 单文件／文件夹扫描复用同一实现，保留任务级上传授权、敏感模式与扫描编号。GUI 仍提供已有白名单；CLI 扫描不暗中加载它。白名单跳过是“未扫描”，不是安全认证。GUI VT 任务默认预算 7200 秒；CLI 默认 120 秒。

**主动防御与一小时白名单规则**

- 仅控制已安装的 `VirusWiseActiveDefense` Windows 服务；不自动安装、提权、重启，也不控制正在运行的 GUI。`defense status` 只读，但与 `doctor` 不同，它会读取本地基线元数据。停止服务不需要重新记录白名单。
- **非 GUI 的 `defense start` 调用前**，只有白名单可正常读取且 `0 <= 当前时间 - last_whitelist_recorded_at <= 3600` 秒时才复用。白名单缺失／损坏、时间缺失／格式错误／在未来／过期，或已保存快照不匹配，必须重新记录**至少 30 秒**。恰好一小时仍有效。
- 记录器真实枚举运行进程并计算可执行文件哈希。请在已知干净的环境记录，期间不要启动测试程序。个别进程无法读取会报告，不能当作安全；枚举失败或一个可执行文件也无法计算哈希时不算完成。白名单保存并回读验证成功后，才向配置提交成功时间与快照标识。
- 失败、取消、超时或保存失败不推进成功时间，也不放行服务启动／测试。后续配置保存失败前，白名单文件可能已经写入，但仍不算成功记录。普通 GUI 设置保存会保留记录元数据。GUI 手动记录同样更新成功时间，**不强制执行一小时时效检查**。
- 服务已经运行但基线过期时，拒绝在防御执行期间学习；需要显式停止后重试，不自动停启。有大小上限的快照通过 SCM 启动参数交付，而不是让 LocalSystem 读取自己的用户目录；超大快照会拒绝启动。
- **SCM 的 RUNNING 不证明已加载本次白名单。** 即使 Windows 接受启动，目前仍返回 `ready=false`／`readiness_unconfirmed`（退出码 6）；状态查询同样不认证防护就绪，不能据此执行破坏性测试。更新后的服务要求有效启动快照，旧式／不带参数的启动会被拒绝，而非悄悄使用另一账户的白名单。旧版已安装服务可能忽略参数，不能假定兼容。
- 当前主动防御没有启用目录监听（`WATCHDOG_AVAILABLE=False`）；`monitor_dirs` 并未实现文件监控。进程阻止规则终止以及评分／挂起前会检查已加载的白名单；这不代表具备完整文件防护。

**输出、超时与边界**

- 默认／`--json` 输出一个最终 JSON 对象；`--jsonl` 当前也只输出最终的 `"event":"result"` 事件，并非实时进度流。两者互斥。普通帮助是文本，机器格式帮助使用统一信封。
- 信封包含 `schema_version`（`"1.0"`）、`request_id`、`command`、`status`、`result`、`errors`；错误包含 `code`、`message`、`next_action`。必须检查逐文件判定、服务状态和 `ready`，不能仅看外层状态或退出码。未知／待定／部分完成／未扫描均不等于安全。
- `--timeout` 是正有限数，表示**协作式任务预算，不是硬墙钟截止时间**。VT 单次请求有连接／读取空闲超时；哈希、文件系统、SCM 和正在进行的请求可能超过预算后才能检查。过期基线记录需要超过 30 秒的剩余预算。取消／超时不回滚已保存数据、上传、处置或已发出的服务状态变更；结束 Defender 客户端也不证明系统服务已停止扫描。
- `doctor` 只做本地依赖发现，不导入依赖，也不验证实际运行健康；跳过网络、重解析、归档和不可确认的搜索位置。`discoverable` 与可执行文件 `present` 不代表就绪。不支持／无法确认的检查会明确标记。
- 未实现测试执行、清理命令或 GUI IPC；`test` 返回不可用。初始化／输出期间中断可能没有完整响应。[实施计划](<plan.md>)还包含未来工作，不代表全部接口已实现。

| 退出码 | 含义 |
| --- | --- |
| 0 | 命令完成，不是无毒／防护有效证明 |
| 2 | 参数缺失、无效或冲突 |
| 3 | 能力、平台、已安装服务或依赖不可用 |
| 4 | 缺少显式授权或操作系统权限 |
| 5 | 执行、持久化或输出失败 |
| 6 | 部分完成或结果未确认，包括未得到服务就绪确认 |
| 124 | 协作式任务预算耗尽，不是硬 I/O 超时保证 |
| 130 | 取消／中断 |

#### 如何从终端或其他程序调用 VirusWise

**先选入口：**人工操作使用 [main.py](<main.py>) 启动 GUI（可能弹出 UAC，并初始化应用数据）；脚本集成使用不启动 GUI 的 [cli.py](<cli.py>)。先按上面的安装步骤准备依赖，再在项目根目录执行命令。目录式 EXE 通过 `--cli` 接受相同参数：将 `python -B cli.py` 换成 `VirusWise.exe --cli`。独立的安装／卸载模式见上方部署说明。

**1. Windows PowerShell：启动程序、设置临时密钥、获取退出码**

将下面项目路径和密钥占位符替换为自己的值。GUI 命令会阻塞终端直到窗口退出，可在另一个终端运行 CLI。扫描命令会实际联网查询哈希，但不允许上传；上传还需显式增加 `--allow-upload`。密钥只设置在当前 PowerShell 会话中，不要提交到仓库或写入共享终端历史／日志。

~~~powershell
# Replace this with your checkout path, then use its Python environment.
Set-Location 'C:\path\to\viruswise'
python -B main.py
# The GUI command above blocks until the GUI exits; run CLI calls in another terminal.
python -B cli.py doctor --json

# Set only in this PowerShell session. Substitute your own key; do not commit it.
$env:VIRUSWISE_VT_API_KEY = '<your-api-key>'
python -B cli.py scan 'C:\Samples\sample.exe' --engine virustotal --allow-network --timeout 120 --json
$scanExitCode = $LASTEXITCODE
Write-Host "Scan exit code: $scanExitCode"
Remove-Item Env:VIRUSWISE_VT_API_KEY
~~~

**2. 推荐集成方式：其他 Python 程序通过子进程调用 CLI**

下面是完整的只读 `doctor` 调用示例；注释给出了改成扫描命令时的参数。每个参数单独放在列表里，不使用 `shell=True`。项目路径使用绝对路径，调用方不必位于项目目录。`sys.executable` 必须对应已经安装 VirusWise 依赖的 Python 环境；否则换成该解释器的绝对路径。VT 密钥由父进程环境继承，不放进命令行参数。

~~~python
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"C:\path\to\viruswise")  # Change to your checkout.
# Use the interpreter/environment in which VirusWise dependencies are installed.
args = [sys.executable, "-B", str(ROOT / "cli.py"), "doctor", "--json"]
# To scan with explicit consent, replace the command tail after cli.py with:
# ["scan", r"C:\Samples\sample.exe", "--engine", "virustotal",
#  "--allow-network", "--timeout", "120", "--json"]
# VIRUSWISE_VT_API_KEY is inherited from this process environment, not argv.
try:
    completed = subprocess.run(
        args, cwd=str(ROOT), capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False, timeout=180,
    )
except subprocess.TimeoutExpired:
    raise RuntimeError("Caller wait expired; external effects may still be active")

try:
    response = json.loads(completed.stdout)
except json.JSONDecodeError:
    raise RuntimeError("No complete JSON response; inspect stderr locally")

print("exit_code:", completed.returncode)
print("status:", response["status"])
print("result:", response["result"])
print("errors:", response["errors"])
# Nonzero responses can contain useful evidence; do not discard them via check=True.
# Exit 0 is not a clean-file certificate; exit 6 / ready=False must not unlock tests.
~~~

上面的子进程 `timeout=180` 是调用方等待上限，可能终止 CLI；它不同于 CLI 的协作式 `--timeout 120`，也不能撤销上传、Defender 处置、已保存白名单或已发出的 SCM 请求。非零退出码仍可能包含有用结果，所以使用 `check=False` 并解析返回 JSON；响应缺失或截断时不能当作成功。

**3. 直接导入 Python API：扫描文件或文件夹**

从项目根目录运行以下代码，或明确把项目根目录加入宿主程序的 Python 导入路径。此示例会实际联网查询。先设置 `VIRUSWISE_VT_API_KEY`；与 CLI 包装层不同，直接调用扫描器必须通过 `api_key` 参数传入密钥。

~~~python
import os
import threading
from core.scanning import ScanError, scan_path

cancel = threading.Event()
try:
    result = scan_path(
        r"C:\Samples\sample.exe", engine="virustotal",
        api_key=os.environ["VIRUSWISE_VT_API_KEY"],
        allow_network=True, allow_upload=False, timeout=120,
        cancel_event=cancel,
    )
except ScanError as exc:
    print({"code": exc.code, "exit_code": exc.exit_code})
else:
    print(result["status"], result["verdict"])
    for item in result["results"]:
        print(item)
# Another thread can call cancel.set(); cancellation is cooperative.
# For Defender, replace the call arguments with:
# scan_path(r"C:\Samples", engine="defender", allow_system_effects=True, timeout=120)
~~~

`scan_path()` 返回扫描结果字典，**不是** CLI 的 JSON 外层结构。前置参数／授权错误抛出 `ScanError`，运行中的失败或部分结果通常通过 `status` 和逐文件结果返回。传入目录会递归扫描。可选 `on_event` 接收包含 `type`、`scan_id` 的扫描事件；回调同步执行，不应阻塞或抛异常。`cancel.set()` 需由其他线程在需要时调用，不会撤销已经发生的副作用。

**4. 直接导入 Python API：查询、启动和停止已安装的主动防御服务**

下面的 `start()` 是真实授权操作，可能记录并保存白名单，然后请求启动服务。它内部执行一小时时效检查，无需调用方先手动记录。记录期间保持机器处于已知干净状态，不启动测试程序；接口不会自动安装服务或提权。

~~~python
from core.defense_control import start, status, stop

print(status())  # Read-only query of the installed service and baseline metadata.
result = start(allow_system_effects=True, timeout=120)
print(result)
if not result["ready"]:
    print("Protection readiness is not confirmed; do not run dependent tests.")

# Separate, deliberate stop operation; never implicit cleanup after an uncertain start:
# result = stop(allow_system_effects=True, timeout=120)
~~~

这些函数返回 `{ok, ready, code, exit_code, ...}` 字典，而不是 CLI 外层结构。`status()` 成功只表示查询成功。目前所有结果均为 `ready=False`；即使启动后 SCM 为 `RUNNING`，也返回 `readiness_unconfirmed`／退出码 `6`，不能继续防护依赖测试。`start()`、`stop()` 还支持 `cancel_event` 和 `on_event`；服务／记录事件字段为 `event`，不同于扫描事件的 `type`，调用方不要混用。停止示例故意保持注释，避免把停止服务作为启动结果未确认后的自动清理。

**5. 可选：显式调用白名单记录器**

仅在明确要学习并保存新基线时调用。它至少花费 30 秒枚举、散列当前运行的可执行文件，并写入白名单／配置；不是只读检查，也不会启动防御。通常交给 `start()` 自动处理即可。GUI 手动记录会处理自身防御的暂停；直接调用下面的记录器不会替你暂停 GUI 或服务。

~~~python
from core.whitelist_recording import record_whitelist

result = record_whitelist(duration=30, timeout=120)
print(result["ok"], result["code"])
# ok=True means recording was committed, not that defense is ready.
~~~

#### 配置
建议通过 GUI 修改偏好。[配置模块](<utils/config.py>) 按运行方式延迟定位数据目录。文本格式的布尔值使用 `1`/`0`，监控路径以 `|` 分隔。CLI 扫描不读取这里的 GUI API 密钥。下面最后两个字段由成功记录一并维护；首次记录前留空，不要伪造或手动推进时间。快照标识缺失或不匹配也会要求重新记录。

~~~ini
apikey=
sensitive=0
auto_process=0
virustotal=1
windows_defender=0
windows_defender_offline_only=1
windows_defender_force=0
ad_enabled=0
delete_protection=1
batch_delete_threshold=5
modify_protection=1
monitor_dirs=C:/example/one|D:/example/two
wl_by_name=0
wl_by_hash=1
ad_warned_on_enable=0
theme=default
last_whitelist_recorded_at=
last_whitelist_snapshot_id=
~~~

### 保护级别
系统使用多层评分方法：

| 分数范围 | 行动 |
|---------|------|
| 0-20 | 仅记录日志 |
| 20-50 | 警告通知 |
| 50-80 | 高优先级警告 + 进程标记 |
| 80+ | 顶级阻断: 挂起/终止进程，持久化阻断规则 |

### 日志记录
所有操作都带有时间戳记录。在 GUI 中查看或检查：
- crash.log - 异常崩溃日志
- 控制台输出用于实时监控

### 注意事项
- 首次运行可能需要进行白名单记录 (30秒进程捕获)
- 主动防御配合已填充的白名单效果最好
- 一些功能需要管理员权限
- Windows 服务需要 LocalSystem 账户以获得最佳保护

---

## Quick Start

1. First run: python main.py
2. Record whitelist: Click "开始30秒白名单记录" on the Settings page (30 seconds, captures all process hashes)
3. Enable active defense: Check "启用主动防御" in Settings
4. Start monitoring: The system will begin monitoring processes
5. Scan files: Use the Scan page to scan individual files or folders
6. Full system scan: Use "全盘查杀 (Defender)" mode for comprehensive scanning

## 快速开始

1. 首次运行: python main.py
2. 记录白名单: 在设置页面点击 "开始30秒白名单记录" (30秒，捕获所有进程哈希)
3. 启用主动防御: 在设置中勾选 "启用主动防御"
4. 开始监控: 系统将开始监控进程
5. 扫描文件: 使用扫描页扫描单个文件或文件夹
6. 全系统扫描: 使用 "全盘查杀 (Defender)" 模式进行全面扫描

