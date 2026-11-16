import SwiftUI
import AppKit
import CoreServices
import Darwin
import Security
import SecureLinkCore
import SecureLinkTransport

@MainActor final class MenuBarConnectionState: ObservableObject {
    @Published private(set) var isConnected = false
    func update(_ connected: Bool) {
        if isConnected != connected {
            isConnected = connected
        }
    }
}

@MainActor final class ShortcutCatalogStore: ObservableObject {
    @Published private(set) var shortcuts: [CampusShortcut]
    @Published private(set) var pinnedMenuBarIDs: [String]
    let shortcutsURL: URL
    let menuBarPinsURL: URL

    static var defaultShortcutsFileURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("SZUSecureLink/shortcuts.json")
    }

    static var defaultMenuBarPinsFileURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("SZUSecureLink/menubar-pins.json")
    }

    init(
        shortcutsURL: URL = ShortcutCatalogStore.defaultShortcutsFileURL,
        menuBarPinsURL: URL = ShortcutCatalogStore.defaultMenuBarPinsFileURL
    ) {
        self.shortcutsURL = shortcutsURL
        self.menuBarPinsURL = menuBarPinsURL
        let loaded = CampusShortcuts.load(from: shortcutsURL)
        self.shortcuts = loaded
        self.pinnedMenuBarIDs = MenuBarPinStore.load(from: menuBarPinsURL, available: loaded)
    }

    var menuBarPinnedShortcuts: [CampusShortcut] {
        let normalized = MenuBarPinStore.normalize(pinnedMenuBarIDs, available: shortcuts)
        return normalized.compactMap { id in shortcuts.first(where: { $0.id == id }) }
    }

    func isPinnedToMenuBar(_ id: String) -> Bool {
        MenuBarPinStore.normalize(pinnedMenuBarIDs, available: shortcuts).contains(id)
    }

    func syncWithWorkbench(_ workbenchResources: [BackendUrlResource]) {
        shortcuts = CampusShortcuts.mergeWithDefaults(saved: shortcuts, workbench: workbenchResources)
        CampusShortcuts.save(shortcuts, to: shortcutsURL)
    }

    func toggleFavoriteShortcut(_ id: String) {
        guard let index = shortcuts.firstIndex(where: { $0.id == id }) else { return }
        shortcuts[index].isFavorite.toggle()
        CampusShortcuts.save(shortcuts, to: shortcutsURL)
    }

    @discardableResult func addCustomShortcut(name: String, url: String) -> Bool {
        guard let item = CampusShortcuts.makeCustomShortcut(name: name, url: url),
              shortcuts.count < CampusShortcuts.maximumShortcuts else { return false }
        shortcuts.append(item)
        CampusShortcuts.save(shortcuts, to: shortcutsURL)
        return true
    }

    func removeCustomShortcut(_ id: String) {
        guard shortcuts.contains(where: { $0.id == id && !$0.isBuiltIn }) else { return }
        shortcuts.removeAll { $0.id == id && !$0.isBuiltIn }
        CampusShortcuts.save(shortcuts, to: shortcutsURL)
    }

    func toggleMenuBarPin(_ id: String) {
        let updated = MenuBarPinStore.togglePin(id: id, current: pinnedMenuBarIDs, available: shortcuts)
        guard updated != pinnedMenuBarIDs else { return }
        pinnedMenuBarIDs = updated
        MenuBarPinStore.save(pinnedMenuBarIDs, to: menuBarPinsURL)
    }
}

@MainActor final class WorkbenchChromeStore: ObservableObject {
    @Published var isEnglishLocale = false
    @Published var showAboutSheet = false
    @Published var updateCheckFeedback: String?
    let aboutMetadata = AboutMetadata.current
    static let accentColor = Color(red: 0x8C / 255.0, green: 0x22 / 255.0, blue: 0x32 / 255.0)

    func checkForUpdates() {
        updateCheckFeedback = isEnglishLocale
            ? "Up to date (v\(aboutMetadata.version), Sparkle EdDSA verified)"
            : aboutMetadata.updateStatusText
    }
}

@MainActor final class SessionModel: ObservableObject {
    @Published var status: TunnelStatus = .unavailable {
        didSet {
            connectionState.update(status == .connected)
        }
    }
    @Published var running = false
    var policy = PolicyObservation()
    @Published var detail = "点击『登录深大 CAS 并建立零信任隧道』即可独立接入深圳大学校园网。" {
        didSet {
            if status == .connecting, detail != oldValue { emitWorkerLine("PHASE: \(detail)") }
        }
    }
    let connectionState = MenuBarConnectionState()
    var isConnected: Bool { connectionState.isConnected }
    let catalog: ShortcutCatalogStore?
    let chrome: WorkbenchChromeStore?
    private let shortcutsFallbackURL: URL

    init(
        catalog: ShortcutCatalogStore? = nil,
        chrome: WorkbenchChromeStore? = nil,
        shortcutsFallbackURL: URL = ShortcutCatalogStore.defaultShortcutsFileURL
    ) {
        self.catalog = catalog
        self.chrome = chrome
        self.shortcutsFallbackURL = shortcutsFallbackURL
    }

    let headlessWorkerMode = ProcessInfo.processInfo.arguments.contains("--headless-tunnel-worker")
    private var headlessWorkerStarted = false
    func emitWorkerLine(_ line: String) {
        guard headlessWorkerMode, let data = (line + "\n").data(using: .utf8) else { return }
        try? FileHandle.standardError.write(contentsOf: data)
    }
    var workbenchResources: [BackendUrlResource] = []
    var pendingShortcutAfterConnect: CampusShortcut?
    @Published var activeTunnelInterface: String?
    @Published var activeVirtualIPv4: String?
    private var activeDataSessionStop: (@Sendable () -> Void)?

    static let campusRedirectChainDomains: [String] = [
        "www1.szu.edu.cn",
        "authserver.szu.edu.cn",
        "ehall.szu.edu.cn",
        "cwpt.szu.edu.cn",
        "oa.szu.edu.cn",
        "www.lib.szu.edu.cn",
        "idp.szu.edu.cn",
        "ezproxy.lib.szu.edu.cn",
        "accproxy.lib.szu.edu.cn"
    ]

    func openOrConnectShortcut(_ item: CampusShortcut) {
        guard let url = URL(string: item.url) else { return }
        if status == .connected {
            NSWorkspace.shared.open(url)
            return
        }
        pendingShortcutAfterConnect = item
        let english = chrome?.isEnglishLocale ?? false
        detail = english
            ? "Connecting to campus network; will open \"\(item.name)\" automatically once connected."
            : "正在为您连接校园网，连接成功后将自动打开「\(item.name)」。"
        if !running && !awaitingCallback {
            prepareIndependentCAS()
        }
    }

    private static func cdhashHex(of url: URL) -> String? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode) == errSecSuccess,
              let code = staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let unique = dict[kSecCodeInfoUnique as String] as? Data else { return nil }
        return unique.map { String(format: "%02x", $0) }.joined()
    }

    private var dataSessionEngine: (engine: URL, socket: String, holdMs: Int, pingPeer: String,
                                    pingCount: Int, digServer: String?, digName: String?)? {
        let inAppBundle = Bundle.main.bundleURL.pathExtension == "app"
        let bundleCandidates: [URL] = [
            Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("executor-engine"),
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/szu-securelink/executor-engine"),
            Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("szu-openvpn3-data-engine"),
            Bundle.main.resourceURL?.appendingPathComponent("szu-openvpn3-data-engine"),
        ].compactMap { $0 }
        let cwdCandidates: [URL] = inAppBundle ? [] : [
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("out/executor-build/executor-engine"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("out/openvpn3/build/szu-openvpn3-data-engine"),
        ]
        let candidates = (bundleCandidates + cwdCandidates).filter {
            FileManager.default.isExecutableFile(atPath: $0.path)
        }
        let expectedCDHash = (try? String(contentsOfFile: "/Library/PrivilegedHelperTools/local.szu.securelink.helper-executor-engine.cdhash", encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let matched = candidates.first { url in
            guard let expected = expectedCDHash, !expected.isEmpty else { return false }
            return Self.cdhashHex(of: url) == expected
        }
        guard let bundled = matched ?? candidates.first else {
            return nil
        }
        return (
            engine: bundled,
            socket: "/var/run/local.szu.securelink.helper-executor",
            holdMs: 560_000,
            pingPeer: "1.1.96.1",
            pingCount: 3,
            digServer: "192.168.247.6",
            digName: "cwpt.szu.edu.cn"
        )
    }
    private var backendTask: Task<Void, Never>?
    private let backendSession = BackendAuthenticationSession()
    @Published var awaitingCallback = false
    var connectionPhase = "idle"
    private var callbackGate = CASCallbackGate()
    private var generation = UUID()
    func setConnectionPhase(_ phase: String) {
        connectionPhase = phase
    }
    private func mayStart() -> Bool {
        guard !running else { return false }
        if headlessWorkerMode { return true }
        guard NSRunningApplication.runningApplications(withBundleIdentifier: "com.wangsu.securelink").isEmpty else {
            detail = "官方客户端正在运行，请先正常退出，避免两个界面争用服务。退出原版可能断开校园网。"
            return false
        }
        let otherPreviews = NSRunningApplication.runningApplications(withBundleIdentifier: "local.szu.securelink.preview").filter { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }
        guard otherPreviews.isEmpty else {
            detail = "另一个预览版本仍在运行，请先退出它，再开始监测或 CAS。"
            return false
        }
        return true
    }
    func prepareIndependentCAS() {
        guard !awaitingCallback, mayStart() else { return }
        guard backendSession.state == .idle else {
            detail = "本次独立认证测试已结束，请重新启动测试。"
            return
        }
        callbackGate.begin()
        awaitingCallback = true
        setConnectionPhase("discovering")
        prepareBackendCAS()
    }
    func receiveCallback(_ url: URL) {
        guard awaitingCallback, !running else { return }
        do {
            let credential = try callbackGate.consume(url)
            awaitingCallback = false
            authenticateBackend(credential)
        } catch {
            callbackGate.cancel()
            awaitingCallback = false
            detail = "回跳参数、组织或时限未通过验证；未向服务提交令牌。"
        }
    }
    private func prepareBackendCAS() {
        generation = UUID()
        let id = generation
        running = true
        detail = "正在直接查询学校登录入口；本次不经官方后台。"
        backendTask = Task { [self] in
            do {
                let url = try await BackendDiscovery.loginURL()
                self.finishCAS(id, url: Task.isCancelled ? nil : url)
            } catch { self.finishCAS(id, url: nil) }
        }
    }
    private func authenticateBackend(_ credential: PendingCASCredential) {
        guard mayStart(), backendSession.begin() else { return }
        running = true
        generation = UUID()
        let id = generation
        var backendUserLogout = "not-requested"
        var tunnelVerified = false
        setConnectionPhase("backend-authenticating")
        detail = "正在独立完成学校预认证，设备信用和二次认证仍由服务判断。"
        backendTask = Task { [self] in
            do {
                let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                let reply = try await BackendAuthenticator.authenticate(credential: credential,
                    identityDirectory: support.appendingPathComponent("SZUSecureLink", isDirectory: true))
                try Task.checkCancellation()
                guard self.generation == id else { self.backendSession.cancel(); return }
                reply.apply(to: self.backendSession, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
            } catch is CancellationError { self.backendSession.cancel() }
            catch { self.backendSession.transportFailed() }
            guard self.generation == id else { return }
            let accepted = self.backendSession.state == .ready
            self.setConnectionPhase(accepted ? "backend-authenticated" : "backend-authentication-stopped")
            if accepted {
                self.detail = self.dataSessionEngine != nil
                    ? "认证通过，正在拉取零信任网络配置与工作台资源..."
                    : "认证通过，正在直接取得连接配置；本次不建立隧道。"
                self.setConnectionPhase("backend-configuration-requested")
                do {
                    let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                    let identityDirectory = support.appendingPathComponent("SZUSecureLink", isDirectory: true)
                    let attempt = try BackendNetworkConfigurationAttempt.prepare(
                        from: self.backendSession,
                        nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000),
                        input: BackendNetworkInput(),
                        identityDirectory: identityDirectory
                    )
                    let configuration: BackendNetworkConfiguration
                    if self.headlessWorkerMode {
                        configuration = try await attempt.perform()
                        try Task.checkCancellation()
                    } else {
                        let (fetchedConfig, resourceCollection) = try await attempt.performCollectingResources()
                        try Task.checkCancellation()
                        configuration = fetchedConfig
                        self.workbenchResources = resourceCollection.resources
                        self.catalog?.syncWithWorkbench(self.workbenchResources)
                    }
                    self.setConnectionPhase("backend-configuration-received")
                    if let session = self.dataSessionEngine {
                        self.status = .connecting
                        self.detail = "正在建立零信任网络隧道并同步深大内网路由与 DNS..."
                        self.setConnectionPhase("backend-data-session-preparing")
                        do {
                            var resolveDomains: [String] = []
                            var seenDomains: Set<String> = []
                            let shortcutsForDomains = self.catalog?.shortcuts ?? CampusShortcuts.load(from: self.shortcutsFallbackURL)
                            let candidateHosts = Self.campusRedirectChainDomains
                                + BackendResources.extractHosts(from: self.workbenchResources)
                                + CampusShortcuts.extractHosts(from: shortcutsForDomains)
                            for domain in candidateHosts {
                                if OpenVPNDataSession.validQueryName(domain),
                                   seenDomains.insert(domain).inserted,
                                   resolveDomains.count < 32 {
                                    resolveDomains.append(domain)
                                }
                            }
                            var lastReceipt: OpenVPNDataSession.Receipt?
                            repeat {
                                let input = try BackendHandshakePreparation.prepare(session: self.backendSession, configuration: configuration,
                                    identityDirectory: identityDirectory,
                                    nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
                                let currentReceipt = try await OpenVPNDataSession.perform(
                                    input, engine: session.engine, socket: session.socket,
                                    holdMs: session.holdMs, pingPeer: session.pingPeer, pingCount: session.pingCount,
                                    digServer: session.digServer, digName: session.digName,
                                    resolveDomains: resolveDomains,
                                    onActive: { [weak self] active in
                                        if let lineData = "engine: active on \(active.interface) vip=\(active.virtualIPv4 ?? "192.168.240.1")\n".data(using: .utf8) {
                                            try? FileHandle.standardError.write(contentsOf: lineData)
                                        }
                                        Task { @MainActor in
                                            guard let self, self.generation == id else { return }
                                            self.activeTunnelInterface = active.interface
                                            self.activeVirtualIPv4 = active.virtualIPv4
                                            self.status = .connected
                                            let vipText = active.virtualIPv4.map { "，虚拟IP: \($0)" } ?? ""
                                            self.detail = "校园网已连接（接口 \(active.interface)\(vipText)）。可直接打开下方校内服务或在默认浏览器访问。"
                                            self.setConnectionPhase("standalone-tunnel-connected")
                                            self.emitWorkerLine("engine: active on \(active.interface) vip=\(active.virtualIPv4 ?? "192.168.240.1")")
                                            if let pending = self.pendingShortcutAfterConnect {
                                                self.pendingShortcutAfterConnect = nil
                                                if let pendingURL = URL(string: pending.url) {
                                                    NSWorkspace.shared.open(pendingURL)
                                                }
                                            }
                                            if self.workbenchResources.isEmpty,
                                               let refreshAttempt = try? BackendNetworkConfigurationAttempt.prepare(
                                                   from: self.backendSession,
                                                   nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000),
                                                   input: BackendNetworkInput(),
                                                   identityDirectory: identityDirectory
                                               ) {
                                                let refreshed = await refreshAttempt.collectResources()
                                                guard self.generation == id else { return }
                                                if !refreshed.resources.isEmpty {
                                                    self.workbenchResources = refreshed.resources
                                                    self.catalog?.syncWithWorkbench(self.workbenchResources)
                                                }
                                            }
                                        }
                                    },
                                    onStopHandle: { [weak self] handle in
                                        Task { @MainActor in
                                            guard let self, self.generation == id else { return }
                                            self.activeDataSessionStop = handle
                                        }
                                    }
                                )
                                lastReceipt = currentReceipt
                            } while self.headlessWorkerMode && !Task.isCancelled && self.status == .connected && (lastReceipt?.verified == true)
                            guard let receipt = lastReceipt else { throw OpenVPNEvaluationError.unavailable }
                            self.activeDataSessionStop = nil
                            try Task.checkCancellation()
                            tunnelVerified = receipt.verified
                            self.status = .disconnected
                            self.setConnectionPhase(receipt.verified ? "backend-data-session-verified" : "backend-data-session-ended")
                        } catch {
                            self.activeDataSessionStop = nil
                        }
                    }
                } catch {
                    self.setConnectionPhase("backend-configuration-stopped")
                }
            }
            if accepted {
                self.detail = self.dataSessionEngine != nil
                    ? "正在断开零信任网络隧道并退出本次用户会话..."
                    : "独立预认证通过；正在退出本次用户会话。本次未建立隧道。"
                if self.dataSessionEngine != nil {
                    self.status = .disconnecting
                }
                do {
                    let attempt = try BackendLogoutAttempt.prepare(from: self.backendSession, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
                    self.backendSession.cancel()
                    let receipt = try await attempt.perform()
                    try Task.checkCancellation()
                    backendUserLogout = receipt.userLogoutAccepted ? "accepted" : "rejected"
                } catch is CancellationError { backendUserLogout = "cancelled" }
                catch { backendUserLogout = "failed" }
                self.backendSession.cancel()
                if self.dataSessionEngine != nil {
                    self.status = .disconnected
                }
                self.setConnectionPhase("backend-test-ended")
            }
            self.running = false; self.backendTask = nil
            if self.dataSessionEngine != nil {
                let tunnelSummary = tunnelVerified ? "零信任隧道已验证；" : "零信任隧道未完成验证；"
                self.detail = accepted
                    ? "会话已结束：\(tunnelSummary)退出结果：\(backendUserLogout)。"
                    : "独立预认证尚未完成：\(self.backendSession.state.rawValue)。"
            } else {
                self.detail = accepted ? "独立预认证通过；退出结果：\(backendUserLogout)。本次未建立隧道，校园访问仍未验收。" : "独立预认证尚未完成：\(self.backendSession.state.rawValue)。本次未建立隧道。"
            }
            self.emitWorkerLine("DISCONNECTED: \(self.detail)")
            if self.headlessWorkerMode { Darwin.exit(0) }
        }
    }
    private func finishCAS(_ id: UUID, url: URL?) {
        guard generation == id else { return }
        running = false
        status = .unavailable
        guard let url else {
            callbackGate.cancel(); awaitingCallback = false
            detail = "CAS 地址获取已取消、超时或未通过校验。"
            emitWorkerLine("DISCONNECTED: \(detail)")
            backendSession.cancel()
            if headlessWorkerMode { Darwin.exit(0) }
            return
        }
        detail = awaitingCallback ? "已打开学校 CAS 登录页，请在浏览器完成登录（5 分钟内有效）。" : "已打开学校 CAS。"
        if awaitingCallback { setConnectionPhase("waiting-for-browser") }
        if headlessWorkerMode {
            let bundleID = (Bundle.main.bundleIdentifier ?? "local.szu.securelink.preview") as CFString
            _ = LSSetDefaultHandlerForURLScheme("securelink" as CFString, bundleID)
            emitWorkerLine("OPEN_URL: \(url.absoluteString)")
        } else {
            NSWorkspace.shared.open(url)
        }
    }
    func startHeadlessWorkerIfRequested() {
        guard headlessWorkerMode, !headlessWorkerStarted else { return }
        headlessWorkerStarted = true
        let bundleURL = Bundle.main.bundleURL
        if bundleURL.pathExtension == "app" {
            let lsreg = Process()
            lsreg.executableURL = URL(fileURLWithPath: "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister")
            lsreg.arguments = ["-f", bundleURL.path]
            try? lsreg.run()
            lsreg.waitUntilExit()
        }
        let bundleID = (Bundle.main.bundleIdentifier ?? "local.szu.securelink.preview") as CFString
        _ = LSSetDefaultHandlerForURLScheme("securelink" as CFString, bundleID)
        Task.detached { [weak self] in
            while let rawLine = readLine(strippingNewline: true) {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if line.hasPrefix("CALLBACK ") {
                    let rawURL = String(line.dropFirst("CALLBACK ".count)).trimmingCharacters(in: .whitespaces)
                    if let url = URL(string: rawURL) {
                        await MainActor.run { self?.receiveCallback(url) }
                    }
                } else if line == "DISCONNECT" {
                    await MainActor.run { self?.disconnectTunnel() }
                    break
                }
            }
        }
        prepareIndependentCAS()
    }
    func disconnectTunnel() {
        if let stopEngine = activeDataSessionStop {
            activeDataSessionStop = nil
            status = .disconnecting
            detail = "正在断开零信任网络隧道并回滚内网路由..."
            stopEngine()
        } else {
            stop()
        }
    }
    func stop() {
        if let stopEngine = activeDataSessionStop {
            activeDataSessionStop = nil
            stopEngine()
        }
        backendTask?.cancel(); backendSession.cancel(); status = .unavailable
        activeTunnelInterface = nil; activeVirtualIPv4 = nil
        callbackGate.cancel(); awaitingCallback = false
    }
    func statusText(english: Bool) -> String {
        if english {
            switch status {
            case .connected: return "Connected to Campus Network"
            case .disconnected: return "Not Connected"
            case .connecting: return "Connecting"
            case .disconnecting: return "Disconnecting"
            case .unknown: return "Ready to Connect"
            case .unavailable: return "Ready to Connect"
            }
        }
        switch status {
        case .connected: return "已连接深圳大学校园网"
        case .disconnected: return "未连接校园网"
        case .connecting: return "正在连接校园网"
        case .disconnecting: return "正在断开连接"
        case .unknown: return "准备连接校园网"
        case .unavailable: return "准备连接校园网"
        }
    }
}

@MainActor enum MenuBarStatusIcon {
    private static let connectedIcon = buildImage(connected: true)
    private static let disconnectedIcon = buildImage(connected: false)

    static func image(connected: Bool) -> NSImage {
        connected ? connectedIcon : disconnectedIcon
    }

    private static func buildImage(connected: Bool) -> NSImage {
        let resourceName = connected ? "menubar-connected" : "menubar-disconnected"
        if let url = Bundle.main.url(forResource: resourceName, withExtension: "svg"),
           let bundled = NSImage(contentsOf: url) {
            bundled.size = NSSize(width: 18, height: 18)
            bundled.isTemplate = true
            return bundled
        }
        let size = NSSize(width: 18, height: 18)
        let img = NSImage(size: size, flipped: true) { _ in
            NSColor.labelColor.setStroke()
            NSColor.labelColor.setFill()
            let head = NSBezierPath()
            head.lineWidth = 1.4
            head.lineCapStyle = .round
            head.lineJoinStyle = .round
            head.move(to: NSPoint(x: 6.0, y: 4.8))
            head.appendArc(withCenter: NSPoint(x: 4.8, y: 5.8), radius: 2.0, startAngle: 320, endAngle: 145, clockwise: true)
            head.curve(to: NSPoint(x: 1.8, y: 12.4), controlPoint1: NSPoint(x: 2.5, y: 8.3), controlPoint2: NSPoint(x: 1.8, y: 10.2))
            head.curve(to: NSPoint(x: 9.3, y: 12.4), controlPoint1: NSPoint(x: 4.3, y: 13.2), controlPoint2: NSPoint(x: 7.0, y: 13.1))
            head.curve(to: NSPoint(x: 16.2, y: 12.5), controlPoint1: NSPoint(x: 11.7, y: 11.6), controlPoint2: NSPoint(x: 14.1, y: 11.7))
            head.curve(to: NSPoint(x: 14.1, y: 7.0), controlPoint1: NSPoint(x: 16.2, y: 10.2), controlPoint2: NSPoint(x: 15.5, y: 8.3))
            head.appendArc(withCenter: NSPoint(x: 13.2, y: 5.8), radius: 2.0, startAngle: 35, endAngle: 220, clockwise: true)
            head.curve(to: NSPoint(x: 6.0, y: 4.8), controlPoint1: NSPoint(x: 10.5, y: 4.0), controlPoint2: NSPoint(x: 7.5, y: 4.0))
            head.close()
            if connected {
                head.fill()
                NSGraphicsContext.current?.compositingOperation = .destinationOut
                NSBezierPath(ovalIn: NSRect(x: 5.9, y: 9.1, width: 2.2, height: 2.2)).fill()
                NSBezierPath(ovalIn: NSRect(x: 9.9, y: 9.1, width: 2.2, height: 2.2)).fill()
                NSGraphicsContext.current?.compositingOperation = .sourceOver
            } else {
                head.stroke()
                NSBezierPath(ovalIn: NSRect(x: 5.9, y: 9.1, width: 2.1, height: 2.1)).fill()
                NSBezierPath(ovalIn: NSRect(x: 9.9, y: 9.1, width: 2.1, height: 2.1)).fill()
            }
            let wave = NSBezierPath()
            wave.lineWidth = 1.4
            wave.lineCapStyle = .round
            wave.move(to: NSPoint(x: 1.8, y: 14.6))
            wave.curve(to: NSPoint(x: 9.4, y: 14.5), controlPoint1: NSPoint(x: 4.5, y: 15.4), controlPoint2: NSPoint(x: 7.0, y: 15.2))
            wave.curve(to: NSPoint(x: 16.2, y: 14.7), controlPoint1: NSPoint(x: 11.8, y: 13.8), controlPoint2: NSPoint(x: 14.1, y: 13.9))
            wave.stroke()
            return true
        }
        img.isTemplate = true
        return img
    }
}

@MainActor final class AppCoordinator {
    let catalog: ShortcutCatalogStore
    let chrome: WorkbenchChromeStore
    let session: SessionModel

    init(
        catalog: ShortcutCatalogStore = ShortcutCatalogStore(),
        chrome: WorkbenchChromeStore = WorkbenchChromeStore()
    ) {
        self.catalog = catalog
        self.chrome = chrome
        self.session = SessionModel(catalog: catalog, chrome: chrome)
    }
}

@main enum SecureLinkEntrypoint {
    @MainActor private static var headlessModel: SessionModel?
    static func main() {
        if ProcessInfo.processInfo.arguments.contains("--headless-tunnel-worker") {
            Task { @MainActor in
                let model = SessionModel()
                headlessModel = model
                model.startHeadlessWorkerIfRequested()
            }
            RunLoop.main.run()
            return
        }
        SecureLinkApp.main()
    }
}

struct SecureLinkApp: App {
    private let coordinator = AppCoordinator()

    var body: some Scene {
        Window("SZU SecureLink", id: "main") {
            WorkbenchRootView(coordinator: coordinator)
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("关于 SZU SecureLink") {
                    coordinator.chrome.showAboutSheet = true
                }
            }
            CommandGroup(after: .appInfo) {
                Button("检查更新...") {
                    coordinator.chrome.checkForUpdates()
                    coordinator.chrome.showAboutSheet = true
                }
            }
        }

        MenuBarExtra {
            TrayMenuPopoverView(
                session: coordinator.session,
                catalog: coordinator.catalog,
                chrome: coordinator.chrome
            )
        } label: {
            MenuBarIconLabel(connectionState: coordinator.session.connectionState)
        }
        .menuBarExtraStyle(.window)
    }
}

struct WorkbenchRootView: View {
    let coordinator: AppCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            WorkbenchHeaderView(chrome: coordinator.chrome)
            ConnectionStatusCardView(session: coordinator.session, chrome: coordinator.chrome)
            MenuBarQuickAccessSectionView(
                catalog: coordinator.catalog,
                chrome: coordinator.chrome,
                session: coordinator.session
            )
            CampusServicesSectionView(
                catalog: coordinator.catalog,
                chrome: coordinator.chrome,
                session: coordinator.session
            )
            Divider()
            WorkbenchFooterView(chrome: coordinator.chrome)
        }
        .tint(WorkbenchChromeStore.accentColor)
        .padding(22)
        .frame(width: 600)
        .onAppear {
            let session = coordinator.session
            if session.headlessWorkerMode {
                session.startHeadlessWorkerIfRequested()
                return
            }
            NSApp.activate(ignoringOtherApps: true)
        }
        .onOpenURL { coordinator.session.receiveCallback($0) }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
            coordinator.session.stop()
        }
    }
}

struct WorkbenchHeaderView: View {
    @ObservedObject var chrome: WorkbenchChromeStore

    var body: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 8)
                .fill(WorkbenchChromeStore.accentColor)
                .frame(width: 34, height: 34)
                .overlay(
                    Image(systemName: "building.columns.fill")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(.white)
                )
            VStack(alignment: .leading, spacing: 2) {
                Text("SZU SecureLink")
                    .font(.system(size: 18, weight: .semibold))
                Text(chrome.isEnglishLocale ? "Shenzhen University Campus Access" : "深圳大学校园网与常用服务")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button(chrome.isEnglishLocale ? "中文" : "EN") {
                chrome.isEnglishLocale.toggle()
            }
            .controlSize(.small)
        }
    }
}

struct ConnectionStatusCardView: View {
    @ObservedObject var session: SessionModel
    @ObservedObject var chrome: WorkbenchChromeStore
    @State private var showNetworkDetails = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Circle()
                    .fill(session.status == .connected ? Color(red: 0x2B / 255.0, green: 0x6E / 255.0, blue: 0x48 / 255.0) : Color.secondary.opacity(0.45))
                    .frame(width: 10, height: 10)
                Text(session.statusText(english: chrome.isEnglishLocale))
                    .font(.system(size: 18, weight: .semibold))
                Spacer()
                if session.status == .connected {
                    Button(chrome.isEnglishLocale ? "Disconnect" : "断开") {
                        session.disconnectTunnel()
                    }
                    .controlSize(.regular)
                } else if session.awaitingCallback {
                    Button(chrome.isEnglishLocale ? "Disconnect" : "断开") {
                        session.stop()
                    }
                    .controlSize(.regular)
                } else {
                    Button(chrome.isEnglishLocale ? "Connect" : "连接") {
                        session.prepareIndependentCAS()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(WorkbenchChromeStore.accentColor)
                    .controlSize(.regular)
                }
            }
            Text(session.detail)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 12) {
                Button(showNetworkDetails
                       ? (chrome.isEnglishLocale ? "Hide Network Details" : "收起网络详情")
                       : (chrome.isEnglishLocale ? "Show Network Details" : "展开网络详情")) {
                    showNetworkDetails.toggle()
                }
                .font(.system(size: 12))
                .buttonStyle(.link)
                Spacer()
                Text(chrome.isEnglishLocale
                     ? "Clicking any service below auto-connects and opens it"
                     : "未连接时直接点下方服务，将自动连接并打开")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            if showNetworkDetails {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 16) {
                        Text("IPv4: \(session.activeVirtualIPv4 ?? "1.1.96.100")")
                            .font(.system(size: 12, design: .monospaced))
                        Text("Interface: \(session.activeTunnelInterface ?? "utun4")")
                            .font(.system(size: 12, design: .monospaced))
                        Text("DNS: 192.168.247.6")
                            .font(.system(size: 12, design: .monospaced))
                        Text(SparkleNumericFormatter.formatRouteCount(129, english: chrome.isEnglishLocale) ?? "")
                            .font(.system(size: 12))
                    }
                    .foregroundStyle(.secondary)
                }
                .padding(10)
                .background(Color.secondary.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding(14)
        .background(Color.secondary.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct MenuBarQuickAccessSectionView: View {
    @ObservedObject var catalog: ShortcutCatalogStore
    @ObservedObject var chrome: WorkbenchChromeStore
    let session: SessionModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(chrome.isEnglishLocale ? "Menu Bar Quick Access (4 Pinned Services)" : "菜单栏快速直达（固定 4 项常用服务）")
                    .font(.system(size: 14, weight: .semibold))
                Spacer()
                Text("\(catalog.menuBarPinnedShortcuts.count) / \(MenuBarPinStore.slotCount)")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 8) {
                ForEach(catalog.menuBarPinnedShortcuts) { pin in
                    Button {
                        session.openOrConnectShortcut(pin)
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "pin.fill")
                                .font(.system(size: 11))
                            Text(pin.name)
                                .font(.system(size: 13, weight: .medium))
                                .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .controlSize(.regular)
                }
            }
        }
    }
}

struct CampusServicesSectionView: View {
    @ObservedObject var catalog: ShortcutCatalogStore
    @ObservedObject var chrome: WorkbenchChromeStore
    let session: SessionModel
    @State private var showShortcutManager = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(chrome.isEnglishLocale ? "Campus Services" : "校内常用服务")
                    .font(.system(size: 14, weight: .semibold))
                Spacer()
                Button(showShortcutManager
                       ? (chrome.isEnglishLocale ? "Hide All (\(catalog.shortcuts.count))" : "收起全部 (\(catalog.shortcuts.count))")
                       : (chrome.isEnglishLocale ? "All Services & Custom (\(catalog.shortcuts.count))" : "全部服务与自定义 (\(catalog.shortcuts.count))")) {
                    showShortcutManager.toggle()
                }
                .font(.system(size: 12))
                .buttonStyle(.link)
            }
            let favorites = catalog.shortcuts.filter(\.isFavorite)
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 8) {
                ForEach(favorites) { item in
                    HStack(spacing: 6) {
                        Button {
                            session.openOrConnectShortcut(item)
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.name)
                                    .font(.system(size: 14, weight: .medium))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                Text(item.subtitle)
                                    .font(.system(size: 12))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .buttonStyle(.bordered)
                        Button {
                            catalog.toggleMenuBarPin(item.id)
                        } label: {
                            Image(systemName: catalog.isPinnedToMenuBar(item.id) ? "pin.fill" : "pin")
                                .foregroundStyle(catalog.isPinnedToMenuBar(item.id) ? WorkbenchChromeStore.accentColor : .secondary)
                        }
                        .buttonStyle(.plain)
                        .help(chrome.isEnglishLocale ? "Pin to Menu Bar (4 slots)" : "固定到菜单栏（4 个槽位）")
                    }
                }
            }
            if showShortcutManager {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(catalog.shortcuts) { item in
                        HStack(spacing: 8) {
                            Button {
                                catalog.toggleFavoriteShortcut(item.id)
                            } label: {
                                Image(systemName: item.isFavorite ? "star.fill" : "star")
                                    .foregroundStyle(item.isFavorite ? WorkbenchChromeStore.accentColor : .secondary)
                            }
                            .buttonStyle(.plain)
                            Button {
                                catalog.toggleMenuBarPin(item.id)
                            } label: {
                                Image(systemName: catalog.isPinnedToMenuBar(item.id) ? "pin.fill" : "pin")
                                    .foregroundStyle(catalog.isPinnedToMenuBar(item.id) ? WorkbenchChromeStore.accentColor : .secondary)
                            }
                            .buttonStyle(.plain)
                            Text(item.name).font(.system(size: 13, weight: .medium))
                            Text(item.subtitle).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                            Spacer()
                            Button(chrome.isEnglishLocale ? "Open" : "打开") {
                                session.openOrConnectShortcut(item)
                            }
                            .controlSize(.small)
                            if !item.isBuiltIn {
                                Button(chrome.isEnglishLocale ? "Remove" : "移除") {
                                    catalog.removeCustomShortcut(item.id)
                                }
                                .controlSize(.small)
                            }
                        }
                    }
                    CustomShortcutFormRow(chrome: chrome, catalog: catalog)
                }
                .padding(10)
                .background(Color.secondary.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}

struct CustomShortcutFormRow: View {
    @ObservedObject var chrome: WorkbenchChromeStore
    let catalog: ShortcutCatalogStore
    @State private var customShortcutName = ""
    @State private var customShortcutURL = ""

    var body: some View {
        HStack(spacing: 6) {
            TextField(chrome.isEnglishLocale ? "Service Name" : "服务名称（如：教务部）", text: $customShortcutName)
                .textFieldStyle(.roundedBorder)
                .frame(width: 150)
            TextField(chrome.isEnglishLocale ? "https://..." : "直达网址（http/https）", text: $customShortcutURL)
                .textFieldStyle(.roundedBorder)
            Button(chrome.isEnglishLocale ? "Pin" : "固定") {
                if catalog.addCustomShortcut(name: customShortcutName, url: customShortcutURL) {
                    customShortcutName = ""
                    customShortcutURL = ""
                }
            }
            .disabled(customShortcutName.trimmingCharacters(in: .whitespaces).isEmpty || customShortcutURL.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }
}

struct WorkbenchFooterView: View {
    @ObservedObject var chrome: WorkbenchChromeStore

    var body: some View {
        HStack(spacing: 12) {
            Text(chrome.aboutMetadata.attributionText)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            Spacer()
            if let feedback = chrome.updateCheckFeedback {
                Text(feedback)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            Button(chrome.isEnglishLocale ? "Update" : "更新") {
                chrome.checkForUpdates()
            }
            .font(.system(size: 12))
            .buttonStyle(.link)
            Button(chrome.isEnglishLocale ? "About" : "关于") {
                chrome.showAboutSheet = true
            }
            .font(.system(size: 12))
            .buttonStyle(.link)
        }
        .sheet(isPresented: $chrome.showAboutSheet) {
            AboutSheetView(chrome: chrome)
        }
    }
}

struct MenuBarIconLabel: View {
    @ObservedObject var connectionState: MenuBarConnectionState

    var body: some View {
        Image(nsImage: MenuBarStatusIcon.image(connected: connectionState.isConnected))
    }
}

struct TrayMenuPopoverView: View {
    @ObservedObject var session: SessionModel
    @ObservedObject var catalog: ShortcutCatalogStore
    @ObservedObject var chrome: WorkbenchChromeStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle()
                    .fill(session.status == .connected ? Color(red: 0x2B / 255.0, green: 0x6E / 255.0, blue: 0x48 / 255.0) : Color.secondary.opacity(0.45))
                    .frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 1) {
                    Text(session.statusText(english: chrome.isEnglishLocale))
                        .font(.system(size: 14, weight: .semibold))
                    if let vip = session.activeVirtualIPv4, session.status == .connected {
                        Text(vip)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if session.status == .connected {
                    Button(chrome.isEnglishLocale ? "Disconnect" : "断开") {
                        session.disconnectTunnel()
                    }
                    .controlSize(.small)
                } else {
                    Button(chrome.isEnglishLocale ? "Connect" : "连接") {
                        session.prepareIndependentCAS()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(WorkbenchChromeStore.accentColor)
                    .controlSize(.small)
                }
            }

            Divider()

            Text(chrome.isEnglishLocale ? "Pinned Campus Services (4)" : "固定常用服务（一键连接并打开）")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)

            VStack(spacing: 4) {
                ForEach(catalog.menuBarPinnedShortcuts) { item in
                    Button {
                        session.openOrConnectShortcut(item)
                    } label: {
                        HStack {
                            Text(item.name)
                                .font(.system(size: 13, weight: .medium))
                            Spacer()
                            Text(chrome.isEnglishLocale ? "Open" : "打开")
                                .font(.system(size: 12))
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 4)
                        .padding(.horizontal, 8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .background(Color.secondary.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }

            Divider()

            HStack {
                Button(chrome.isEnglishLocale ? "Open Workbench" : "打开主窗口") {
                    NSApp.activate(ignoringOtherApps: true)
                }
                .font(.system(size: 12))
                .buttonStyle(.link)
                Spacer()
                Button(chrome.isEnglishLocale ? "Update" : "更新") {
                    chrome.checkForUpdates()
                }
                .font(.system(size: 12))
                .buttonStyle(.link)
                Button(chrome.isEnglishLocale ? "Quit" : "退出") {
                    NSApplication.shared.terminate(nil)
                }
                .font(.system(size: 12))
                .buttonStyle(.link)
            }
        }
        .padding(12)
        .frame(width: 280)
    }
}

struct AboutSheetView: View {
    @ObservedObject var chrome: WorkbenchChromeStore

    var body: some View {
        VStack(spacing: 14) {
            RoundedRectangle(cornerRadius: 12)
                .fill(WorkbenchChromeStore.accentColor)
                .frame(width: 48, height: 48)
                .overlay(
                    Image(systemName: "building.columns.fill")
                        .font(.system(size: 22, weight: .semibold))
                        .foregroundStyle(.white)
                )
                .padding(.top, 4)
            VStack(spacing: 4) {
                Text(chrome.aboutMetadata.appName)
                    .font(.system(size: 18, weight: .semibold))
                Text("v\(chrome.aboutMetadata.version) (Build \(chrome.aboutMetadata.build))")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Text(chrome.aboutMetadata.summary)
                .font(.system(size: 13))
                .multilineTextAlignment(.center)
                .foregroundStyle(.primary)
                .padding(.horizontal, 12)
            Divider()
            VStack(spacing: 6) {
                HStack(spacing: 10) {
                    Button(chrome.isEnglishLocale ? "Update" : "更新") {
                        chrome.checkForUpdates()
                    }
                    .controlSize(.small)
                    Text(chrome.updateCheckFeedback ?? chrome.aboutMetadata.updateStatusText)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                Text("GitHub Releases: semantic-craft/szu-securelink-lite")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
                Text(chrome.aboutMetadata.attributionText)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .padding(.top, 2)
            }
            Divider()
            HStack {
                Spacer()
                Button(chrome.isEnglishLocale ? "Close" : "关闭") {
                    chrome.showAboutSheet = false
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(width: 390)
    }
}
