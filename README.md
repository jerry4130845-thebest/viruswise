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

The GUI still starts with `python main.py`; active defense is controlled in its settings. For AI or subprocess automation, use the separate [CLI entry point](<cli.py>) with [read-only diagnostics](<core/diagnostics.py>). Phase one implements only `capabilities` and `doctor`, using the Python standard library; GUI dependencies and administrator privileges are not required for these commands.

Run from the project root:

~~~text
python -B cli.py --help
python -B cli.py capabilities --json
python -B cli.py doctor --json
python -B cli.py capabilities --jsonl
~~~

- `capabilities` lists implemented commands, output formats, exit codes, and limitations. It does not claim that planned scanning or testing interfaces exist.
- `doctor` checks Python/platform information, current administrator status, dependency discoverability, and the Defender executable at the location used by the existing scanner. It does not launch the GUI, request elevation, start scans, access network services, read configuration or credentials, install dependencies, or create application directories.
- Dependency discovery inspects only verified-local Windows directories without importing dependencies or invoking custom import hooks. Network paths, reparse paths, archives, and unverifiable locations are skipped. Windows-only checks return `unsupported` or `unchecked` on other platforms.

**Output contract**

- The default output and `--json` produce one final JSON object. `--jsonl` produces JSON events; phase one emits only the final event with `"event":"result"`. The two flags are mutually exclusive.
- Responses contain `schema_version` (currently `"1.0"`), `request_id`, `command`, `status`, `result`, and `errors`. Each error includes `code`, `message`, and `next_action`. Parse the structured fields rather than matching human-readable messages.
- Plain `--help` prints text; adding `--json` or `--jsonl` wraps help in the corresponding response format. Machine output is not mixed with human logs.

| Exit code | Meaning |
| --- | --- |
| 0 | Command completed; inspect diagnostic findings, not just the exit code |
| 2 | Missing, unknown, or conflicting arguments |
| 3 | Requested capability or required CLI module unavailable |
| 5 | Execution or output failure |
| 130 | Cancelled by interruption |
| 4 / 6 / 124 | Reserved for authorization failure / partial or unconfirmed execution / timeout; not implemented in phase one |

**Interpretation and limits**

`discoverable` means a dependency candidate was found, not that it imports or works correctly. `present` means the Defender executable exists, not that its service is ready. Missing or unverified observations are reported as `unavailable`, `unchecked`, or `unsupported`. An optional dependency finding does not itself make `doctor` fail; exit `0` and `status=completed` do not certify engine health, file safety, or effective protection.

Scanning, test execution, cleanup, and communication with a running GUI are not implemented. There is **no hard timeout** (`timeout_supported=false`); `124` is reserved, not an implemented timeout guarantee. Ctrl+C during diagnostics is handled as cancellation, but interruption during initialization or output may leave no complete JSON response. The broader [implementation plan](<plan.md>) describes future work, not currently available commands.

#### Configuration
Edit utils/config.txt or use the GUI:
apikey=Your_VirusTotal_Key
sensitive=False
auto_process=False
virustotal=True
windows_defender=False
windows_defender_offline_only=True
windows_defender_force=False
ad_enabled=False
delete_protection=True
batch_delete_threshold=5
modify_protection=True
monitor_dirs=C|/path/to/monitor
wl_by_name=False
wl_by_hash=True
ad_warned_on_enable=False
theme=default

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

GUI 仍通过 `python main.py` 启动，主动防御在 GUI 设置中控制。AI 或子进程自动化请使用独立的 [CLI 入口](<cli.py>)及[只读诊断模块](<core/diagnostics.py>)。阶段一仅实现 `capabilities` 和 `doctor`，使用 Python 标准库；执行这些命令不要求安装 GUI 依赖或拥有管理员权限。

在项目根目录运行：

~~~text
python -B cli.py --help
python -B cli.py capabilities --json
python -B cli.py doctor --json
python -B cli.py capabilities --jsonl
~~~

- `capabilities`：列出已实现命令、输出格式、退出码和限制，不将计划中的扫描或测试接口标为可用。
- `doctor`：检查 Python/系统信息、当前管理员状态、依赖可发现性，以及现有扫描器所用位置的 Defender 程序文件。不会启动 GUI、请求提权、执行扫描、访问网络服务、读取配置或密钥、安装依赖或创建业务目录。
- 依赖检查仅查看已确认的 Windows 本地目录，不导入依赖模块、不调用自定义导入钩子；跳过网络路径、重解析路径、归档文件及无法确认的位置。在其他平台上，Windows 专属检查返回 `unsupported` 或 `unchecked`。

**输出契约**

- 默认输出及 `--json` 均为一个最终 JSON 对象。`--jsonl` 输出 JSON 事件，阶段一仅输出带 `"event":"result"` 的最终事件；两个选项互斥。
- 响应固定包含 `schema_version`（当前为 `"1.0"`）、`request_id`、`command`、`status`、`result` 和 `errors`。每个错误包含 `code`、`message` 和 `next_action`；调用方应解析结构化字段，不匹配人类可读提示文本。
- 单独使用 `--help` 输出文本；搭配 `--json` 或 `--jsonl` 则将帮助放入对应格式的响应中。机器输出不混入人类日志。

| 退出码 | 含义 |
| --- | --- |
| 0 | 命令执行完成；仍须检查诊断结果，不能只看退出码 |
| 2 | 参数缺失、未知或冲突 |
| 3 | 请求的能力或 CLI 必需模块不可用 |
| 5 | 执行或输出故障 |
| 130 | 因中断而取消 |
| 4 / 6 / 124 | 分别预留给授权不足、部分完成或待确认、超时；阶段一尚未实现 |

**结果解释与限制**

`discoverable` 仅表示发现了依赖候选，不证明它能导入或正常工作；`present` 仅表示 Defender 程序文件存在，不证明服务已就绪。缺失或无法确认的检查项返回 `unavailable`、`unchecked` 或 `unsupported`。可选依赖的诊断发现本身不会让 `doctor` 执行失败；退出码 `0` 和 `status=completed` 不代表引擎健康、文件安全或防护有效。

扫描、测试执行、清理及与运行中 GUI 的通信均未实现。当前**没有硬超时**（`timeout_supported=false`），`124` 只是预留退出码，不是已实现的超时保证。诊断过程中的 Ctrl+C 会按取消处理，但初始化或输出期间中断可能无法得到完整 JSON 响应。[实施计划](<plan.md>)描述的是后续工作，不代表相关命令已经可用。

#### 配置
编辑 utils/config.txt 或使用 GUI:
apikey=你的_VirusTotal_Key
sensitive=False
auto_process=False
virustotal=True
windows_defender=False
windows_defender_offline_only=True
windows_defender_force=False
ad_enabled=False
delete_protection=True
batch_delete_threshold=5
modify_protection=True
monitor_dirs=C|/path/to/monitor
wl_by_name=False
wl_by_hash=True
ad_warned_on_enable=False
theme=default

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

