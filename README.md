<div align="center">
  <img src="assets/app-icon.png" width="120" height="120" alt="荔连 App Icon" />
  <h1>荔连 · SZU SecureLink</h1>
  <p><strong>干净、快速、无后台常驻负担的深圳大学 macOS 校园网客户端</strong></p>
  <p>A clean, native macOS zero-trust campus network client for Shenzhen University</p>

  <p>
    <a href="https://github.com/semantic-craft/szu-securelink-lite/releases/download/v0.2.0/SZU-SecureLink-v0.2.0-macOS-arm64.zip">
      <img src="https://img.shields.io/badge/⬇_立即下载_荔连_v0.2.0-macOS_Apple_Silicon_(8.8_MB)-8C2232?style=for-the-badge" alt="Download 荔连 v0.2.0 for macOS" />
    </a>
    &nbsp;
    <a href="https://github.com/semantic-craft/szu-securelink-lite/releases/tag/v0.2.0">
      <img src="https://img.shields.io/badge/GitHub_Release-v0.2.0-2B2118?style=for-the-badge&logo=github" alt="GitHub Release v0.2.0" />
    </a>
  </p>

  <p>
    <a href="#立即下载与安装">中文说明</a> · <a href="#english">English</a> · <a href="https://github.com/semantic-craft/szu-securelink-lite/releases/download/v0.2.0/SZU-SecureLink-v0.2.0-macOS-arm64.zip">直接下载 ZIP</a> · <a href="NOTES.md">实测记录</a>
  </p>
</div>

---

## 立即下载与安装

> **直接下载安装包（macOS 13.0+ Apple Silicon，已通过 Apple Developer ID 签名与公证）**
>
> - **直接下载（ZIP，8.85 MiB）**：[SZU-SecureLink-v0.2.0-macOS-arm64.zip](https://github.com/semantic-craft/szu-securelink-lite/releases/download/v0.2.0/SZU-SecureLink-v0.2.0-macOS-arm64.zip)
> - **版本发布页**：[GitHub Releases · v0.2.0](https://github.com/semantic-craft/szu-securelink-lite/releases/tag/v0.2.0)
> - **SHA-256 校验值**：`44e664fc4644b2ada6e8f2cc26f5668126aaa7275a9c5f9512c35ef0f3e9089c`

解压后将 **`荔连.app`** 拖入 `/Applications`（应用程序）文件夹，双击即可直接打开使用。

---

## 为什么做「荔连」

在校外查知网、看外文数据库、进报账系统时，我们只需要一个干净好用的校园网客户端，不想为了连一次内网而在电脑里常驻整套 Electron 渲染进程（官方完整进程组实测约 `655 MiB` RSS）和一堆用不上的后台监控服务。

**荔连（SZU SecureLink）** 用 **Rust + GPUI（Metal 硬件加速）** 重写了桌面工作台，直接对接深圳大学 CAS 统一身份认证与 OpenVPN3 零信任数据面，在完全退出官方客户端进程的情况下独立完成校园网接入。

## 核心特性

- **纯净轻量，无后台监控组件**：移除原厂 Electron 外壳及深大未启用的后台组件（EDR、沙箱、DLP、远程协助），不常驻无关后台守护进程。
- **荔枝红视觉与独立设置页**：采用深大荔枝红（`#8C2232`）与暖纸双栏布局，顶栏与左侧卡片实时显示连接状态，支持一键 **自动修复**；独立「偏好设置」页统一管理 **程序坞与菜单栏图标常驻模式**、**开机自动启动**、**中英文与三色主题（深大荔枝红 / 竹院青 / 松烟靛）** 以及 **版本检查更新**。
- **点击服务即自动连网**：内置 13 项深大高频入口（报账系统、办事大厅、内部网、OA、深大图书馆，以及中国知网、HeinOnline、Oxford、Cambridge、北大法宝、Web of Science、Westlaw 机构直达），支持固定 4 项到 macOS 顶部菜单栏。未连接时直接点击任一服务，会自动拉起 CAS 登录并在隧道建好后打开目标页面。
- **不碰校园网密码**：认证全程在系统默认浏览器的深圳大学官方 CAS 页面完成。客户端只校验一次性 `securelink://` 回跳票据（含防重放与 5 分钟时限），不读取、不存储账号密码。

## 从源码构建与验证

如果你想从源码本地编译并替换安装到 `/Applications/荔连.app`，在仓库根目录执行：

```sh
./scripts/build-app "/Applications/荔连.app"
```

首次需要建立真实 `utun` 隧道时，运行一次性特权执行器安装脚本（仅负责受限的 `utun` 接口创建与校内路由及 DNS 事务，按需唤醒，空闲零常驻）：

```sh
	sudo ./scripts/install-executor
	./scripts/health-check
```

仓库内置离线验证套件，无需校园网账号即可运行全部 Python、Swift 与 Rust 测试：

```sh
	./scripts/check
```

## 文档导航

- [当前状态与实测记录](NOTES.md) · [技术架构与实证记录](docs/design.md)
- [后台协议契约](docs/backend-contract.md) · [待办工单与验收标准](docs/backlog.md) · [项目教训](lessons.md)

---

<h2 id="english">English</h2>

**Lilian (荔连 · SZU SecureLink)** is a native macOS zero-trust campus network client for Shenzhen University (SZU), built with Rust and GPUI (Metal hardware acceleration).

### Download for macOS

- **Direct Download (macOS 13.0+ Apple Silicon, Notarized, 8.85 MiB)**: [SZU-SecureLink-v0.2.0-macOS-arm64.zip](https://github.com/semantic-craft/szu-securelink-lite/releases/download/v0.2.0/SZU-SecureLink-v0.2.0-macOS-arm64.zip)
- **Release Page**: [GitHub Releases · v0.2.0](https://github.com/semantic-craft/szu-securelink-lite/releases/tag/v0.2.0)
- **SHA-256**: `44e664fc4644b2ada6e8f2cc26f5668126aaa7275a9c5f9512c35ef0f3e9089c`

Unzip the archive, drag **`荔连.app`** into `/Applications`, and double-click to launch (signed with Apple Developer ID and notarized).

### Why We Built Lilian

Connecting to the campus network to look up a paper or submit a reimbursement should not require keeping an Electron shell (`~655 MiB` RSS across the vendor process tree) and a bundle of idle background daemons running all day. We built **Lilian** to provide a clean, fast, native macOS client that connects to the SZU campus network and opens campus resources without background bloat.

### Highlights

- **Native Metal UI**: Built with Rust and `gpui-kit`, rendering natively on macOS Metal without an Electron browser shell.
- **Collapsible Campus Workbench & Menu Bar Pins**: Groups 13 campus and library services (Reimbursement System, Campus Intranet, OA, Library, CNKI, HeinOnline, Oxford Scholarship, Cambridge Core, PKULaw, Web of Science, and Westlaw) into collapsible sections with 4 customizable menu-bar pins. Clicking any service while disconnected initiates CAS sign-in and opens the target page as soon as `utun` comes up.
- **Built-In Self-Repair & Instant `utun` Adoption**: Adopts the campus `utun` interface as soon as `executor-engine` assigns the virtual IPv4 address (`~0.25s` after handshake) and includes a one-click **Auto-Repair** action to clear stale processes and flush DNS cache.
- **Browser-Only CAS Sign-In**: You sign in only inside your default browser on the official SZU CAS page. The client validates one-time `securelink://` callback tickets and never sees or stores your password.

### Build and Verify from Source

```sh
./scripts/build-app "/Applications/荔连.app"
./scripts/check
```

---

**深圳大学法律人工智能实训实验室**  
Legal AI Lab, Shenzhen University
