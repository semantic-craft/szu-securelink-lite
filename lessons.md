# 项目教训

实现、评审或验收前阅读相关条目；用户纠正、返工或漏验暴露可复用教训后补记。
下方保留记录模板及已核实教训。

## 记录模板

复制下列模板新增条目，已有同类条目则更新原条。未知的提交、原因或验收结果明确写“待核实”。
同一事件的多次修复、测试重跑不增加复发次数；只统计有独立证据的再次发生。
记录保留可复用的原因与证据定位；凭据、私人资料及完整日志留在各自获准的位置。

```markdown
### <教训标题>

**<一句话说明下次应遵守的规则。>**

- 标签：<#验收 #凭据 #交接 这类跨项目归类词，1–3 个；`skills candidates` 按标签找跨项目同类教训。>
- 起因与后果：<触发条件、原因、用户可感知的影响；关联 issue 或引入提交，未知则写待核实。>
- 修复与证据：<修复提交或 PR、回归检查与实际验收证据；区分已验证和未验证的部分。>
- 正确做法（Done right）：<下次的具体做法；链接到防复发代码、检查或所属规范。>
- 验证点：<写明之后怎么核对这条已改到位（看哪个文件、跑什么命令、查什么结果）。>
- 复发记录：Seen <N>x (<YYYY-MM-DD, ...>)；<每次独立发生的证据；修复提交数与重试次数不计入。>
```

### 隧道状态同步必须以真实 `utun` 接口为准，严禁在路由装填窗口内用短超时看门狗杀进程或用乐观代数丢弃激活事件

**隧道激活以 `ifconfig utun<N>` 出现 `1.1.x.x --> 1.1.96.1` 为准，看门狗只做激活接管不做定时强杀，窗口层无条件采信 `TunnelActive` 并拒绝非连接态的迟到 `PHASE:`。**

- 标签：#状态机 #并发 #验收
- 起因与后果：用户两次反馈客户端卡在「正在连接中... 正在建立零信任网络隧道并同步深大内网路由与 DNS...」。取证 `/var/log/szu-executor.log` 与 Unified Log 发现四重叠加原因：① 官方 `helper-executor` 在 `utun4` 配置好 `1.1.105.34 --> 1.1.96.1`（`t = +0.25s`）后，顺序派生 133 次 `/sbin/route -n add` 耗时 `11.4s` 才把 `utun4` fd 交还给 `executor-engine`；② `App.swift` 在 `--headless-tunnel-worker` 模式下先阻塞 `504ms` 拉取 `getApplications`，且 `detail.didSet` 与 `setConnectionPhase` 重复打印 `PHASE:`，触发 3 个并发看门狗线程每秒跑 `ping -c 1 -t 1 1.1.96.1` 阻塞 Actor 队列，并在 `14s` 时调用 `run_auto_repair` 误杀刚建好的隧道；③ 子进程退出时 `setConnectionPhase` 在非 `.connecting` 状态补发 `PHASE:`，且 Rust 侧忽略 `stderr` EOF；④ `WorkbenchWindow` 乐观递增 `self.generation` 后用 `generation < self.generation` 丢弃了 Actor 发回的 `TunnelActive`。
- 修复与证据：[`Sources/SecureLinkApp/App.swift`](Sources/SecureLinkApp/App.swift) 在 `--headless-tunnel-worker` 下跳过前置 `getApplications`、`onActive` 直接写 `FileHandle.standardError`、仅在 `status == .connecting` 时输出单次 `PHASE:`；[`src/tunnel_actor.rs`](src/tunnel_actor.rs) 引入 `ActorTunnelState` 与纯函数 `step_watchdog_tick`、用 `probe_connecting_campus_utun` 在 `utun` 挂载瞬间（`0.25s`）即判定激活、移除看门狗自动强杀并补齐 `stderr` EOF 收尾；[`src/gpui_window.rs`](src/gpui_window.rs) 无条件采信 `TunnelActive` 并限制 `ConnectingPhase` 仅在 `Connecting` 态生效。
- 正确做法（Done right）：跨进程状态机用显式枚举 [`ActorTunnelState`](src/tunnel_actor.rs) 建模，把状态迁移抽成纯函数 [`step_watchdog_tick`](src/tunnel_actor.rs) 并与 [`WorkbenchWindow::apply_session_event`](src/gpui_window.rs) 一起写回归测试（参见 [AGENTS.md](AGENTS.md) 规则表）。
- 验证点：运行 `cargo test --offline test_beginner_auto_connect_tray_pins_and_sparkle` 与 `cargo clippy --offline --all-targets -- -D warnings`，核对 `wc -l src/*.rs` 所有文件不超过 400 行。
- 复发记录：Seen 2x（2026-11-07 17:42、2026-11-07 18:49，均在 CAS 回跳后卡在「正在建立零信任网络隧道」）。

### macOS 26/27 状态栏图标（`NSStatusItem`）必须由 `.app` 主进程直接挂载，且 GPUI Flexbox 双栏必须声明 `min_w_0()` 防横向裁切

**在 macOS 26/27 中必须在 `CFBundleExecutable` 主进程内通过 `tray-icon` 直接挂载 `NSStatusItem`，且 GPUI `flex_1()` 栏必须显式加 `.w_full().min_w_0().overflow_hidden()` 防止 `min-content` 撑破窗口右边界。**

- 标签：#UI #状态栏 #验收
- 起因与后果：① 初版菜单栏图标由 `Contents/MacOS/szu-securelink-diagnostic --menubar-agent` 辅助子进程创建，macOS 26/27 的 `MenuBarAgent` 仅渲染 `.app` 主可执行文件创建的 `NSStatusItem`，导致用户看不到右上角状态栏图标；② 独立设置页右栏 `flex_1()` 未加 `min_w_0()`，底层 `taffy` 引擎按单行长文本固有最小宽度（`min-content`）撑破 740px 窗口右边界，造成按钮与说明文字被视口裁切。
- 修复与证据：[`src/tray_bridge.rs`](src/tray_bridge.rs) 改用 `tray-icon` 在 `szu-securelink` 主线程同进程挂载 36×36 `@2x` 模板图标与 `NSMenu`；[`src/gpui_window.rs`](src/gpui_window.rs) 的 `render_settings_body` 为双栏及全部子行补齐 `.w_full().min_w_0().overflow_hidden()`，经 `screencapture` 实机窗口截图验证零溢出。
- 正确做法（Done right）：macOS 菜单栏状态项一律在主进程主线程挂载并通过 `System Events` -> `menu bar 2` 实测核验；GPUI 弹性双栏布局一律显式声明 `min_w_0()` 并截屏核对右边界。
- 验证点：运行 `./scripts/check` 与 `osascript -e 'tell application "System Events" to tell process "szu-securelink" to get properties of menu bar item 1 of menu bar 2'`。
- 复发记录：Seen 1x（2026-11-08）。

### 验收入口必须先向用户核对真实工作流（协议推断不能替代）

- 标签：#验收 #交接
- 起因与后果：早期验收反复打开协议层推断的登录地址，而非工作台「内部网」资源携带的真实业务入口，且多轮会话在等待浏览器回跳时超出了 5 分钟票据有效期。
- 修复与证据：通过 `/networkApi/gcable/getApplications` 核对工作台资源列表的真实跳转入口，并在 [`src/shortcuts.rs`](src/shortcuts.rs) 固化 13 项校内常用服务与图书馆中外文数据库入口。
- 正确做法（Done right）：① 涉及用户可感知入口的验收，先核对真实业务入口 URL，不以协议层端口推断替代；② 协调式实机验收只在用户就绪后发起，避免 5 分钟 CAS 票据超时。
- 验证点：以工作台服务卡片打开的 URL 与真实业务入口一致为准。
- 复发记录：Seen 1x（2026-11-06）。

### CBC解密不等于完整性验证

- 起因：初版用单字节密文扰动推断解密一定报错，测试反例说明这一假设不成立。
- 修复：显式校验PKCS#7所有填充字节；用确定性破坏填充的合成向量回归。CBC仍无消息认证，绝不将解密成功当作可信消息。
- 验证：`swift test` 的CipherTests；Seen 1x（2026-11-04）。


### 服务标志的实际类型须经实机核对

- 起因与后果：静态消费端把 userInfoCompletion 按真假处理，初版自行收紧为 Bool；真实 szu 应答为数字，导致合法 CAS 回跳停在 unsupported-response。
- 正确做法：将消费语义和服务实际类型分开记录；未知类型停止，通过仅含固定名称/类型的诊断定位，不落盘原始认证响应。整数非零仍走补资料/拒绝分支，不因兼容修复跳过检查。
- 验证：CASPreAuthenticationTests 的数字与拒绝分支，AuthenticationReplyShapeTests 的隐私回归；本轮真实 initialized/connected 回执见 docs/live-testing.md。Seen 1x（2026-11-04）。


### 按传输分派后的数据形态核对契约

- 起因：官方接收层递归 parseJson，把 content 内的 JSON 字符串展开后才交给安全检查 handler；原生只参照 handler 的对象访问，导致真实安全结果被显示为 unknown。
- 修复：在已确认的 content/clientMessage 字段支持对象或一层 JSON 字符串，保留严格标量和错误检查；未知不默认健康，明确 enable=0 单独显示未启用。
- 验证：PolicyObservationTests 包装/直传等价、错误与未知回归；本轮真实 notRequired 证据见 docs/live-testing.md。Seen 1x（2026-11-04）。
