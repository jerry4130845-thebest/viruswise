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
2. Install dependencies:
   pip install -r requirements.txt
   Note: Some UI components require customtkinter and PIL

3. Configure the application:
   - Edit utils/config.py or use the GUI settings page
   - Set your VirusTotal API key (optional but recommended for cloud scanning)
   - Configure monitored directories in settings

4. Run the application:
   python main.py

#### Running as Windows Service
1. Install the service:
   python main.py install
   or use the built-in service command

2. Start the service:
   net start VirusWiseActiveDefense

3. Stop the service:
   net stop VirusWiseActiveDefense

4. Uninstall the service:
   python main.py remove

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
2. 安装依赖:
   pip install -r requirements.txt
   注意: 部分 UI 组件需要 customtkinter 和 PIL

3. 配置应用程序:
   - 编辑 utils/config.py 或使用 GUI 设置页面
   - 设置你的 VirusTotal API key (可选，但强烈推荐用于云端扫描)
   - 在设置中配置监控目录

4. 运行应用程序:
   python main.py

#### 作为 Windows 服务运行
1. 安装服务:
   python main.py install
   或使用内置服务命令

2. 启动服务:
   net start VirusWiseActiveDefense

3. 停止服务:
   net stop VirusWiseActiveDefense

4. 卸载服务:
   python main.py remove

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

