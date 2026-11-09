状态: active

# szu-securelink

## 目标与授权

为深圳大学师生提供完全脱离官方 Electron 客户端（`com.wangsu.securelink`）的原生零信任客户端 **荔连（SZU SecureLink）**，用极低内存占用（空闲约 2.1–38 MB）替代约 680 MB 的官方进程树，并支持与本机另一款联网软件无冲突共存。

本机已获用户授权执行连接、断开、启动、退出与恢复验证；学校统一身份认证（CAS）由用户在系统默认浏览器完成，客户端不收集或存储明文密码。远端仓库为 `semantic-craft/szu-securelink-lite`。

## 当前事实（2026-11-09 · `v0.2.2`）

1. **三层架构、macOS 原生 AppKit 界面与 AI 控制面已完整落地并发布 `v0.2.2`**：
   - **桌面交互与热路径层（Pure Safe Rust + macOS 原生 AppKit）**：[`src/`](src/lib.rs) 共 18 个模块（全部 `#![forbid(unsafe_code)]`），包含原生工作台控制器 [`src/gpui_window.rs`](src/gpui_window.rs)、版本化 JSON 宿主契约 [`src/host_api.rs`](src/host_api.rs)、C ABI 宿主桥接 [`crates/host-macos`](crates/host-macos/src/lib.rs)、Objective-C++ 原生 AppKit 窗口与液态玻璃卡片 [`platforms/macos/src/SecureLinkNativeApp.mm`](platforms/macos/src/SecureLinkNativeApp.mm)、macOS 状态栏常驻桥接与 Dock 显隐控制 [`src/tray_bridge.rs`](src/tray_bridge.rs)、隧道监督状态机 [`src/tunnel_actor.rs`](src/tunnel_actor.rs)、本机 AI 代理 CLI 控制面与单实例 Unix domain socket 守护 [`src/agent_control.rs`](src/agent_control.rs)、13 项深大常用服务与中外文数据库直达 [`src/shortcuts.rs`](src/shortcuts.rs)，以及经属性测试验证的混淆编解码 [`src/confusion.rs`](src/confusion.rs)、流量整形 [`src/shaper.rs`](src/shaper.rs)、RFC 1035 DNS 解析 [`src/dns.rs`](src/dns.rs) 与控制策略分类器 [`src/ctrl.rs`](src/ctrl.rs)。
   - **控制面与 CAS 认证层（Swift）**：[`Sources/`](Sources/SecureLinkApp/App.swift) 独立完成组织预配置、深大 CAS 浏览器回跳门禁（`securelink://`）、预认证、SDP `initConfig` 隧道配置拉取及 `--headless-tunnel-worker` 子进程编排。
   - **特权隧道与路由执行层（C++17 / Objective-C++）**：[`native/openvpn3-handshake/data_engine.mm`](native/openvpn3-handshake/data_engine.mm) 与 [`native/network-helper/`](native/network-helper/executor_main.mm) 通过 `LOCAL_PEERCRED` + `audit_token` + `CDHash` 校验建立 `utun` 接口、装填 133 条校内静态与动态 `/32` 路由，并在断开或异常退出时原子回滚。
2. **实机业务与跨仓自动化已打通**：报账系统、内部网、OA 及中国知网、HeinOnline、Oxford、Cambridge、北大法宝、Web of Science、Westlaw 全部实测直达；`scholar`（`research-infra`）与 `szu-reimb`（`life-infra`）已接入 `szu-securelink status/ensure/open-sso --json` 控制面，支持校园网内网直连自动切换与并发建连请求合并。

## 下一步

- 跟踪校园网长时间挂机、睡眠唤醒重连与网关策略变更场景。

## 导航

[技术架构与证据](docs/design.md) · [工程经验](lessons.md)
