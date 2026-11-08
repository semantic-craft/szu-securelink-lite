# 技术架构与实证记录

## 1. 背景与基线事实

官方客户端（`com.wangsu.securelink` 3.11.1.1272）基于 Electron + Go `SecureLink_Client` + C++ `SecureLink_Core` + `SecureLink_Agent` + `SecureLink_DP` 构建，应用体积约 438 MiB，常驻 12 个进程，空闲 RSS 约 682 MiB。

本项目通过静态契约恢复与黑盒实证，在不复制任何厂商代码或密钥的前提下，构建了完全独立的原生客户端 **荔连（SZU SecureLink）**，空闲状态仅需单进程常驻，核心数据面峰值 RSS 约 2.09 MiB。

## 2. 三层架构设计

| 层级 | 目录与核心模块 | 职责与安全边界 |
| --- | --- | --- |
| **桌面交互与数据面核心（Rust）** | [`src/gpui_window.rs`](../src/gpui_window.rs)、[`src/tray_bridge.rs`](../src/tray_bridge.rs)、[`src/tunnel_actor.rs`](../src/tunnel_actor.rs)、[`src/agent_control.rs`](../src/agent_control.rs)、[`src/shortcuts.rs`](../src/shortcuts.rs)、[`src/dns.rs`](../src/dns.rs)、[`src/ctrl.rs`](../src/ctrl.rs) | 提供 GPUI Metal 60fps 暖色工作台、菜单栏快捷直达、`ShellPresence` Dock/菜单栏双端显隐状态机、显式 `ActorTunnelState` 监控状态机、本机 AI 代理 CLI 控制面（`status` / `ensure` / `open-sso` / `repair` / `disconnect` / `shortcuts`）与单实例 Unix domain socket（`0600`）合并协调；所有校内跳转 URL 强制校验 `http/https` scheme。 |
| **零信任控制面（Swift）** | [`Sources/SecureLinkApp/App.swift`](../Sources/SecureLinkApp/App.swift)、[`Sources/SecureLinkTransport/`](../Sources/SecureLinkTransport/BackendSessionClient.swift)、[`Sources/SecureLinkCore/`](../Sources/SecureLinkCore/CASConnectionFlow.swift) | 独立实现 Sheeta API 加密封装、深大 CAS 统一身份认证回跳校验（`securelink://`）、设备环境同步与 `--headless-tunnel-worker` 无头隧道工作进程。认证通过后立即拉起数据面，不阻塞于应用列表请求。 |
| **特权隧道与路由执行器（C++17 / ObjC++）** | [`native/openvpn3-handshake/data_engine.mm`](../native/openvpn3-handshake/data_engine.mm)、[`native/network-helper/executor_main.mm`](../native/network-helper/executor_main.mm)、[`native/network-helper/ipc.mm`](../native/network-helper/ipc.mm) | 基于定制 OpenVPN 3 TCP 混淆传输层与系统 LaunchDaemon（`local.szu.securelink.helper-executor`）。通过 `LOCAL_PEERCRED`、内核 `audit_token` 与 `SecCodeCopySigningInformation` 校验证书/CDHash，创建 `utun` 接口、注入 129 条校内静态路由（[`vendor-static-routes.json`](../native/network-helper/vendor-static-routes.json)）与隧道内 DNS 动态 `/32` 主机路由，并在会话结束时按事务日志精确回滚。 |

## 3. 关键工程决策

1. **与另一款联网软件共存分流**：校内部分业务与数据库跳转链在本机同时运行另一款联网软件时容易发生虚拟地址段或 DNS 抢答冲突。客户端通过校内网段静态路由加隧道内 DNS 预解析动态下发 `/32` 主机路由，仅接管校内流量并在断开时按事务日志完整回滚，实现无需关闭另一款联网软件即可直通校内资源。
2. **133 条路由装填期防误杀**：macOS 特权执行器顺序执行 133 次 `/sbin/route -n add` 耗时约 11.4 秒。[`src/tunnel_actor.rs`](../src/tunnel_actor.rs) 的纯函数 `step_watchdog_tick` 仅负向超时或正向探测到 `utun` 时迁移状态，严禁在路由装填窗口内误杀 `executor-engine`。
3. **特权安装与文件安全硬化**：特权守护进程及信任锚点采用临时文件校验后 `rename` 原子替换并设置 `uchg` 不可变标志；IPC 套接字与事务日志严格限制为 `0600` 权限，构建脚本拒绝符号链接跟随（`O_NOFOLLOW`）。

## 4. 验证门禁

在仓库根目录运行 [`./scripts/check`](../scripts/check) 即可离线执行完整验证矩阵：
- Python 离线规划、路由验证器、特权安装器与 C++ 单元回归测试（`unittest discover -s tests`）
- Swift 控制面与协议核心测试（`swift test` 与 `szu-securelink-probe --self-test`）
- Safe Rust 单元测试、文档测试与 Clippy 零警告门禁（`cargo test --all-targets`、`cargo clippy --all-targets -- -D warnings`）
