# szu-securelink

先读 [NOTES.md](NOTES.md)、[README.md](README.md)、[lessons.md](lessons.md)。

- 当前技术证据和决策在 `docs/design.md`；未完成工单在 `docs/backlog.md`。
- `scripts/baseline.py` 为只读诊断入口；`scripts/check` 为离线验证入口。
- 静态分析原文和性能快照只放忽略的 `out/`；不要提交厂商二进制、配置、令牌或账户数据。
- 最新用户授权允许本机有界连接/断开、启动/退出测试并尝试恢复；保留原客户端与配置，不重签名。系统安全设置、安装、协议注册和长期凭据使用仍需相应授权。
- 不能把合成数据或服务可达当作校园网/报账大厅验收；测试结果必须标明所证明的层次。

## 架构与防复发门禁（`/correct` Rule Table）

| Rule | Enforced by | Why |
| --- | --- | --- |
| 隧道连接成功事件（`SessionEvent::TunnelActive`）不得被乐观递增的窗口代数（`generation`）或迟到的 `ConnectingPhase` 丢弃/覆盖，且排队打开的快捷入口只触发一次 | [`WorkbenchWindow::apply_session_event`](src/gpui_window.rs) 与 [`test_beginner_auto_connect_tray_pins_and_sparkle`](src/tests.rs) | 防止点击服务自动连接或重连增代后，真实 `utun` 激活回执被丢弃，或子进程退出前的尾部 `PHASE:` 把窗口冻死在「正在连接中」 |
| 隧道监控状态机必须用显式 `ActorTunnelState` 与纯函数 [`step_watchdog_tick`](src/tunnel_actor.rs) 建模，Watchdog 只能把 `Connecting` 推进为 `Connected`，严禁在装填 133 条校内路由期间（约 11.4 秒）自动杀进程重连 | [`ActorTunnelState`](src/tunnel_actor.rs)、[`step_watchdog_tick`](src/tunnel_actor.rs) 与 [`test_beginner_auto_connect_tray_pins_and_sparkle`](src/tests.rs) | `helper-executor` 顺序执行 133 次 `/sbin/route -n add` 耗时 11.4 秒，14 秒自毁定时器会在隧道建好瞬间误杀 `executor-engine` |
| `--headless-tunnel-worker` 认证通过后直接启动隧道，不阻塞等待工作台资源列表拉取；`onActive` 直接写 `stderr` 且 `PHASE:` 仅在 `.connecting` 状态下输出 | [`App.swift`](Sources/SecureLinkApp/App.swift) | 消除 `getApplications` 带来的 500ms 前置阻塞、主线程 `@MainActor` 排队延迟与退出时的伪造 `PHASE:` 行 |
