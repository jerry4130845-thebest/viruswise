# VirusWise 自动更新与发布指南

## 1. 目标与边界

- 当前本地版本基线为 **2.6.6**。
- 在左侧导航栏最底部放“检查更新”按钮，所有页面均可使用。
- 启动约 1.5 秒后，后台读取上次检查时间：从未检查或已满 24 小时才联网。
- 持续运行时按“最近一次检查尝试时间 + 24 小时”继续安排自动检查。
- 手动按钮不受 24 小时限制；手动检查也重新计算下次自动检查时间。
- 成功、断网、超时、限流、不规范标签等**已经发起的检查尝试都计时**。
- Windows 新布局打包版：有可用资产时，征得确认后下载，由独立更新器安装。源码模式、旧平铺版或无合规资产仅提供发布页。
- 不修改查杀、主动防御、服务管理、依赖或现有用户配置数据。

## 2. 文件范围

| 文件 | 职责 |
| --- | --- |
| [ui/app.py](<ui/app.py>) | 左下角按钮、后台线程、结果队列、主线程提示、周期调度与退出清理 |
| [utils/config.py](<utils/config.py>)（本轮未改） | 时间解析、磁盘权威元数据保护、跨进程原子检查预约 |
| [utils/update_checker.py](<utils/update_checker.py>) | 版本常量、版本比较、GitHub 查询、结构化结果与错误处理 |
| [main.py](<main.py>) | 打包版启动门禁和新版就绪确认 |
| [updater.py](<updater.py>)、[updater.spec](<updater.spec>) | 独立 Windows 更新器、安装与恢复协议 |
| [utils/updater.py](<utils/updater.py>) | 下载、ZIP/PE 验证、Windows 安装锁与覆盖回滚 |
| [viruswise.spec](<viruswise.spec>) | 构建 Windows onedir、收集更新器和内置版本清单 |
| [plan.md](<plan.md>) | 实现方案、发布要求与验证清单 |

## 3. 版本与 GitHub Release 约定

仓库：[jerry4130845-thebest/viruswise](https://github.com/jerry4130845-thebest/viruswise)。

查询地址：

~~~text
https://api.github.com/repos/jerry4130845-thebest/viruswise/releases/latest
~~~

- 使用 GitHub 的 **Latest 正式 Release**，不是仓库 tag 列表，也不遍历所有历史版本。
- 新 tag 必须为大写 V 加三段非负整数、两个英文句点，例如 V2.6.7、V3.0.1、V3.5.6。
- “三段”不是固定三字符：也支持 V3.10.0，按整数元组比较，不按文本或小数比较。
- 不接受缺段、多段、后缀、前后空白或小写前缀，例如 V3.0、V3.0.1-beta、v3.0.1。
- 只有远端版本严格大于本地版本才提示更新。相等或更旧不提示升级，不提供降级。
- 旧版不规范 tag 无须改写：遇到时提示“暂时无法判断更新”，不崩溃，也不谎报“已最新”。
- 不把 Release 标题当成版本号；不接受草稿或预发布版本。
- 浏览器链接由固定仓库和验证过的 tag 构造，不采用响应中的任意链接。

> 本方案依赖 GitHub 的 Latest 指向你要推广的版本；它不保证是所有历史 Release 中数值最大的版本。发布新正式版时请确认其被设为 Latest。

## 4. 时间持久化与并发

配置使用程序既有位置，由 [utils/config.py](<utils/config.py>) 的路径逻辑决定。新增字段示例：

~~~ini
last_update_check_at=1794873600.0
~~~

- 时间为 Unix 秒，可跨重启、跨时区比较；24 小时等于 86400 秒。
- 缺失、空值、无效、非有限数、非正数视作需要检查；未来时间视为时钟回拨，重新检查并修正。
- 在现有稳定 sidecar 文件锁内，重读磁盘、判定到期、记录本次尝试，再释放锁做网络请求。
- 默认在获得锁后取当前时间，避免排队线程把另一线程稍新的时间误判为时钟回拨。
- 多个程序实例同时自动检查时，只有首个到期预约成功者联网；手动操作仍可强制检查。
- 普通设置保存不能回退磁盘上的检查时间；窄事务也不会覆盖主题、API Key 或白名单元数据。
- 复用已有同目录临时文件、fsync、原子替换和跨进程锁，不引入第二套配置机制。
- 无法保存检查时间时不发请求：手动显示原因、自动记日志，本进程 24 小时后重试；手动仍可立即重试。因为未成功写盘，重启后会再次尝试预约。

## 5. UI 与错误策略

- 按钮固定在左侧导航底部；检查期间禁用并显示“正在检查…”，避免重复任务。
- 配置锁、磁盘及网络均在独立 daemon 线程执行，不阻塞主线程。
- 后台只投递结果，不调用 Tk，包括不从后台调用 after。
- 主线程每 100 毫秒轮询结果，恢复按钮并重排下次检查。
- 有更新且可自动安装：显示版本、大小和退出提示，由用户明确确认；下载可取消。否则提供固定仓库的发布页。
- 无更新：只在手动检查时弹提示。
- 失败、无 Release 或标签不规范：手动提示，自动只记录日志。
- HTTP 连接超时 5 秒，读取超时 15 秒；这是请求阶段超时，不是整个流程的硬性总时限。
- 403/429 限流、404、HTTP 错误、无效 JSON、TLS/网络失败均不能当作“已最新”。
- 退出时取消自动检查/启动回调及结果轮询；迟到结果不会访问已销毁的界面。
- 检查请求不会阻塞关闭。下载中关窗会请求取消，网络调用返回后完成清理再结束进程；下载不被算作扫描。

## 6. 自动安装与恢复（协议 2）

1. 固定使用 `VirusWise-Vx.y.z.zip`（对应 Release tag），要求唯一同名上传资产、上传完成、大小有效、GitHub 提供 SHA-256、下载 URL 指向固定仓库。其他附件不会被选中。仅接受 GitHub 和允许的资产 CDN HTTPS 跳转。
2. 后台下载到受管理员保护的独占目录；流式检查长度和 SHA-256，代理/TLS 错误或取消时不覆盖。确认更新后，再从固定 tag `updater` 下载 `updater.zip`，按客户端内置的大小和 SHA-256 校验，解压到安装目录之外的受保护事务目录。只启动该事务中的更新器，它会重验主程序 ZIP。主程序 ZIP 的同源 SHA-256 不是独立的发布签名。
3. 更新器核实旧进程路径和创建时间，再发就绪信号。界面必须提交，更新器等待 Windows 进程句柄变为已退出，不能只等窗口销毁或固定睡眠。如果服务已运行、正在启动/停止，或者无法确认状态，拒绝安装，不会操作服务。
4. 独占安装锁内安全解压到同卷的受控目录并重新检查服务；拒绝越界路径、重复/冲突、链接、重解析点、非托管文件、错误版本/协议/PE 架构。先移开旧主 EXE，备份并替换运行时，最后放入新主 EXE。只更新主程序 EXE 和整个 `_internal`；不要把用户数据放在这个运行时子目录内。安装根的 `data`、配置、白名单、配置档、隔离区和其他文件原样保留。
5. 用明确的安装路径启动新版。在界面完成初始化后，新版必须确认 PID 和内置目标版本。确认后才释放门禁、清理包及备份，新版负责在独立进程退出后删除其临时副本；被占用时下次启动重试。无确认或覆盖失败时，更新器尝试还原原版，无法确认回滚时保留备份和日志。

如果机器在替换过程中断电或更新器被终止：**先保留安装根和更新事务目录，不要删除门禁或备份**。在管理员 PowerShell 中，确认其他 VirusWise 实例已退出、服务已手动停止；找到失败提示给出的受保护事务目录（系统 Program Files 下的 `VirusWise-update-<事务编号>`，编号可从安装根的 `.viruswise-update.pending` 查看）。保留该目录的 `runner` 子目录及其依赖，从该子目录运行 `VirusWiseUpdater.exe --recover <事务编号>`。恢复只处理同一事务；如果已持久记录新版确认，则仅收尾，否则尝试回滚。有占用或异常时不要强行覆盖，先保留 `error.json` 与备份。

## 7. 发布步骤

1. 修改 [CURRENT_VERSION](<versions.py#L3>) 为实际发布的三段数字版本，例如 `3.0.1`。使用与已发布更新器匹配的 Windows Python 架构，仅构建主程序（不需要本地更新器，也不会下载它）：

~~~powershell
python -m PyInstaller --noconfirm viruswise.spec
~~~

2. 从**从未运行过的干净构建产物**中归档；不要压缩外层 `VirusWise` 文件夹，也不要从已含运行数据的安装目录制作包。可在仓库根运行：

~~~powershell
python -m zipfile -c VirusWise-V3.0.1.zip dist/VirusWise/VirusWise.exe dist/VirusWise/_internal
~~~

3. ZIP 根目录只有 `VirusWise.exe` 和 `_internal/`；内含打包生成的版本/协议清单和运行时。发布正式 tag `V3.0.1` 并设为 Latest；确认 API 的 asset `digest` 字段已生成。
4. **首次切换到协议 2 需手动安装一次**。使用干净目录并按需迁移 `data` 和 `quarantine`。已有服务若指向旧路径，需单独迁移，不会自动重注册。后续更新由协议 2 客户端从 GitHub 自动下载独立更新器。

> 建议安装在本地 NTFS 上、仅受信人员可写的专用目录。不要使用网络共享、联接点或多人可写的安装目录；和原有管理员启动要求一样，安装目录的可执行文件必须可信。

## 8. 第一阶段检查更新验证（历史）

自动验证只用临时配置、模拟 HTTP 与 AST 提取的 UI 方法，不导入或启动完整 GUI，不触发查杀/主动防御，不修改用户运行数据，不安装包。

- [x] 三个 Python 模块语法通过。
- [x] 大版本、小版本、补丁版本及多位数字比较正确；严格拒绝非三段版本。
- [x] 首次检查、24 小时前一秒、恰好 24 小时、手动覆盖、失败记时与重新读取持久时间。
- [x] 无效/未来时间恢复；旧设置缓存不会回退新时间，白名单元数据及其他设置不丢失。
- [x] 8 个进程同时预约只有一个获准，未实际联网；原子替换失败保留旧配置并清理临时文件。
- [x] 模拟正式新版本、相等/较旧版本、不规范 tag、草稿/预发布、404/403/429/500、无效 JSON、超时、断网和 TLS 错误。
- [x] 模拟 UI 忙碌防重入、手动重排、主线程结果处理、关闭后不再调度或弹窗；真实后台线程执行提取的 worker 时没有调用 UI。
- [ ] 人工打开真实程序，检查左下角位置、点击反馈及浏览器跳转。
- [ ] 实际打包后复测检查和重启后的时间读取。

### 已执行验证的部分真实输出

~~~text
PASS: stale-save protection, persistence, automatic boundary, manual override
PASS: 8 concurrent processes reserve exactly one automatic check
PASS: HTTP failure persists, restart-style recheck skips, manual retry bypasses (mocked)
PASS: atomic-write failure leaves old config intact and removes temporary file
PASS: one worker, manual force, old timer cancelled, no worker UI calls (AST)
PASS: shutdown cancels both timers and is idempotent (AST; no application started)
~~~

验证命令使用系统 Python 3.11、-B 禁用字节码写入、临时目录注入配置路径、unittest.mock 模拟网络；UI 方法由 AST 提取，未导入完整应用。没有修改既有测试文件、用户配置或依赖。

真实 GUI、真实 GitHub 链路与打包属于单独的人工/发布验收；不能用模拟通过代替。

## 9. 自动安装验证（原内置更新器，历史）

PyInstaller 6.20 在 Windows 临时目录实际构建主程序和独立更新器。用发布命令生成 ZIP，并在本地磁盘临时安装目录验证。最终输出：

~~~text
PASS: 7 Python/spec files compile
PASS: publisher ZIP has expected layout: 1265 entries
PASS: real Windows replacement + mocked ACK + cleanup
PASS: failed startup restores old files and preserves user data
PASS: packaged --help exits 0 without initializing data
PASS: copied independent helper launches and rejects missing handoff (exit 2)
PASS: live Windows process path, creation time and wait handle
~~~

另验证了 Windows 共享/独占锁、49 种替换与回滚中断组合、重解析点及硬链接拦截，以及下载/服务状态/UI 的模拟分支。未运行真实 GUI，未用正式 Release 下载测试，未执行管理员态完整旧版升新版验收。在 `R:\Temp` 的替换测试遇到 WinError 1；上述通过记录来自本地 C 盘。

## 10. 关于按钮与统一版本号（已实现）

- 在左侧导航栏底部、「检查更新」上方加「关于」按钮。打开小窗口，显示 VirusWise 和当前版本。
- 提供 [GitHub 项目主页](https://github.com/jerry4130845-thebest/viruswise) 和 [B站空间](https://space.bilibili.com/435616692) 两个按钮；只有点击链接按钮才用默认浏览器打开。
- 在项目根目录新增 [versions.py](<versions.py>)，集中维护 `CURRENT_VERSION`，保留当前值 `2.6.6`。界面、更新检查、启动确认和打包清单沿用此值。
- 范围：新增 [versions.py](<versions.py>)，修改 [ui/app.py](<ui/app.py>)、[utils/update_checker.py](<utils/update_checker.py>)、[viruswise.spec](<viruswise.spec>) 和本文。不改更新流程、配置、依赖或既有测试。
- 已通过：5 个 Python/spec 文件语法检查；模拟更新版本比较；关于按钮、版本显示、两个链接、弹窗复用与关闭；打包清单版本生成。未启动完整程序或真实浏览器，本轮未重新打包。

## 11. 独立更新器发布与验证（协议 2，已实现）

- 主程序打包不再查找或收录本地更新器。保留现有无控制台设置，沿用版本清单，正常发布只构建主程序；打包时不联网。
- 仍从正式 Latest Release 选择主程序 ZIP。用户确认更新后，再从同仓库的固定 `updater` tag 下载 `updater.zip`；该 tag 不设为 Latest。更新器只存在于受保护的临时事务目录，不安装到主程序目录。
- 下载的更新器启动前须匹配客户端固定的 SHA-256，并通过路径、文件类型、协议和架构校验。下载、校验或启动失败时不退出旧程序，不回退执行其他来源。若替换这一 ZIP，需要用新摘要构建支持它的主程序。
- 更新安装协议切换为仅替换主程序 EXE 和运行时目录，保留用户数据、回滚和新版就绪确认。旧版在首次迁移到新协议时需手动升级一次；上一轮的备用更新器 ZIP 不能直接作为新协议产物。
- 本次已构建独立的 Windows x64 包。把这份 **原始** `updater.zip` 上传到 GitHub 的 `updater` Release，不能重压缩；该 Release 不设为 Latest。包大小 **12,925,800 字节**，SHA-256 为 `157b7aa148b124020b5c23be27484fb2aecca5cc4af077b9cc1515d4447f97d8`。
- 如确需重建更新器，使用 [updater.spec](<updater.spec>) 单独构建后，在其 `_internal` 中加入 UTF-8 `updater-release.json`，内容为 `{"protocol":2}`；把 `VirusWiseUpdater.exe` 和 `_internal` 放在 ZIP 根目录。重新核对并配置 [viruswise.spec](<viruswise.spec#L13-L15>) 的包大小和 SHA-256。**不要直接覆盖已发布且被旧客户端固定的 ZIP**，否则这些客户端会拒绝下载；需另做兼容发布安排。
- 已在空输出目录实际构建主程序，确认没有包含更新器。验证了模拟下载成功、404、摘要错误和取消；验证了下载后解压的更新器可启动、失败时不启动更新器，以及 Windows 临时目录的文件替换、回滚和用户数据保留。未上传 GitHub，也未通过真实发布地址做完整 GUI 更新。
