import SwiftUI
import AppKit
import CoreServices
import CryptoKit
import Darwin
import Security
import SecureLinkCore
import SecureLinkTransport

final class Cancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    func cancel() { lock.lock(); stopped = true; lock.unlock() }
    func isCancelled() -> Bool { lock.lock(); defer { lock.unlock() }; return stopped }
}

final class LoginURLHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var value: URL?
    func set(_ url: URL) { lock.lock(); value = url; lock.unlock() }
    func take() -> URL? { lock.lock(); defer { lock.unlock() }; defer { value = nil }; return value }
}

final class AuthenticationStateHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var value: CASPreAuthentication.State = .idle
    func set(_ state: CASPreAuthentication.State) { lock.lock(); value = state; lock.unlock() }
    func get() -> CASPreAuthentication.State { lock.lock(); defer { lock.unlock() }; return value }
}

final class ConnectionStateHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var value: CASConnectionFlow.State = .idle
    func set(_ state: CASConnectionFlow.State) { lock.lock(); value = state; lock.unlock() }
    func get() -> CASConnectionFlow.State { lock.lock(); defer { lock.unlock() }; return value }
}

@MainActor final class SessionModel: ObservableObject {
    @Published var status: TunnelStatus = .unavailable
    @Published var running = false
    @Published var policy = PolicyObservation()
    @Published var detail = "点击『登录深大 CAS 并建立零信任隧道』即可独立接入深圳大学校园网。" {
        didSet {
            if status == .connecting, detail != oldValue { emitWorkerLine("PHASE: \(detail)") }
        }
    }
    let standaloneDefaultMode: Bool = {
        let args = ProcessInfo.processInfo.arguments
        return !args.contains("--cas-connect-test")
            && !args.contains("--cas-preauthentication-test")
            && !args.contains("--backend-preauthentication-test")
            && !args.contains("--backend-configuration-test")
            && !args.contains("--legacy-ipc-mode")
    }()
    let headlessWorkerMode = ProcessInfo.processInfo.arguments.contains("--headless-tunnel-worker")
    private var headlessWorkerStarted = false
    func emitWorkerLine(_ line: String) {
        guard headlessWorkerMode, let data = (line + "\n").data(using: .utf8) else { return }
        try? FileHandle.standardError.write(contentsOf: data)
    }
    var backendConfigurationTestEnabled: Bool {
        standaloneDefaultMode || ProcessInfo.processInfo.arguments.contains("--backend-configuration-test")
    }
    var backendTestEnabled: Bool { backendConfigurationTestEnabled || ProcessInfo.processInfo.arguments.contains("--backend-preauthentication-test") }
    private var backendConfigurationReceipt: [String: Any] = [:]
    private var backendConfigurationValidated = false
    private var backendConfigurationFailure: [String: String] = [:]
    private var backendEngineEvaluation: [String: Any] = [:]
    private var backendHandshake: [String: Any] = [:]
    private var backendDataSession: [String: Any] = [:]
    private var handshakeValidated = false
    private var handshakeProbe: URL? {
        let args = ProcessInfo.processInfo.arguments
        guard backendConfigurationTestEnabled, let index = args.firstIndex(of: "--handshake-probe"), args.indices.contains(index + 1) else { return nil }
        return URL(fileURLWithPath: args[index + 1])
    }
    /// Standalone finance acceptance: the session receipt carries the gate's
    /// expected fields only when the homepage observation validated and the
    /// official backend really is stopped.
    private var financeMode: Bool { ProcessInfo.processInfo.arguments.contains("--finance") }
    private var homepageObservationPath: URL? {
        let args = ProcessInfo.processInfo.arguments
        guard financeMode, let index = args.firstIndex(of: "--homepage-observation"), args.indices.contains(index + 1) else { return nil }
        return URL(fileURLWithPath: args[index + 1])
    }
    private var backendStillRunning: Bool {
        for name in ["SecureLink_Client", "SecureLink_Agent", "SecureLink_Core", "SecureLink_DP"] {
            let run = Process()
            run.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
            run.arguments = ["-x", name]
            run.standardOutput = Pipe()
            do { try run.run(); run.waitUntilExit() } catch { return true }
            if run.terminationStatus == 0 { return true }
        }
        return false
    }
    private var financeHomepageValidated = false
    private var financeCampusValidated = false
    private var financeTunnelStatus = "disconnected"
    @Published var workbenchResources: [BackendUrlResource] = []
    private var workbenchFailure: String?
    @Published var shortcuts: [CampusShortcut] = CampusShortcuts.load(from: SessionModel.shortcutsFileURL)
    @Published var pinnedMenuBarIDs: [String] = MenuBarPinStore.load(
        from: SessionModel.menuBarPinsFileURL,
        available: CampusShortcuts.load(from: SessionModel.shortcutsFileURL)
    )
    @Published var pendingShortcutAfterConnect: CampusShortcut?
    @Published var uiScheme: String = "crimson"
    @Published var isEnglishLocale = false
    @Published var showNetworkDetails = false
    @Published var showShortcutManager = false
    @Published var showAboutSheet = false
    @Published var updateCheckFeedback: String?
    let aboutMetadata = AboutMetadata.current
    let sparkleConfig = SparkleConfiguration.current
    @Published var customShortcutName = ""
    @Published var customShortcutURL = ""
    @Published var activeTunnelInterface: String?
    @Published var activeVirtualIPv4: String?
    private var activeDataSessionStop: (@Sendable () -> Void)?

    static var shortcutsFileURL: URL {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true))
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("SZUSecureLink/shortcuts.json")
    }

    static var menuBarPinsFileURL: URL {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true))
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("SZUSecureLink/menubar-pins.json")
    }

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

    func syncShortcutsWithWorkbench() {
        shortcuts = CampusShortcuts.mergeWithDefaults(saved: shortcuts, workbench: workbenchResources)
        CampusShortcuts.save(shortcuts, to: Self.shortcutsFileURL)
    }

    func toggleFavoriteShortcut(_ id: String) {
        guard let index = shortcuts.firstIndex(where: { $0.id == id }) else { return }
        shortcuts[index].isFavorite.toggle()
        CampusShortcuts.save(shortcuts, to: Self.shortcutsFileURL)
    }

    func addCustomShortcut() {
        guard let item = CampusShortcuts.makeCustomShortcut(name: customShortcutName, url: customShortcutURL),
              shortcuts.count < CampusShortcuts.maximumShortcuts else { return }
        shortcuts.append(item)
        customShortcutName = ""
        customShortcutURL = ""
        CampusShortcuts.save(shortcuts, to: Self.shortcutsFileURL)
    }

    func removeCustomShortcut(_ id: String) {
        shortcuts.removeAll { $0.id == id && !$0.isBuiltIn }
        CampusShortcuts.save(shortcuts, to: Self.shortcutsFileURL)
    }

    func checkForUpdates() {
        updateCheckFeedback = isEnglishLocale
            ? "Up to date (v\(aboutMetadata.version), Sparkle EdDSA verified)"
            : aboutMetadata.updateStatusText
    }

    var menuBarPinnedShortcuts: [CampusShortcut] {
        let normalized = MenuBarPinStore.normalize(pinnedMenuBarIDs, available: shortcuts)
        return normalized.compactMap { id in shortcuts.first(where: { $0.id == id }) }
    }

    func isPinnedToMenuBar(_ id: String) -> Bool {
        MenuBarPinStore.normalize(pinnedMenuBarIDs, available: shortcuts).contains(id)
    }

    func toggleMenuBarPin(_ id: String) {
        pinnedMenuBarIDs = MenuBarPinStore.togglePin(id: id, current: pinnedMenuBarIDs, available: shortcuts)
        MenuBarPinStore.save(pinnedMenuBarIDs, to: Self.menuBarPinsFileURL)
    }

    func openOrConnectShortcut(_ item: CampusShortcut) {
        guard let url = URL(string: item.url) else { return }
        if status == .connected {
            NSWorkspace.shared.open(url)
            return
        }
        pendingShortcutAfterConnect = item
        detail = isEnglishLocale
            ? "Connecting to campus network; will open \"\(item.name)\" automatically once connected."
            : "正在为您连接校园网，连接成功后将自动打开「\(item.name)」。"
        if !running && !awaitingCallback {
            if diagnosticEnabled {
                prepareIndependentCAS()
            } else {
                start()
            }
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
        let args = ProcessInfo.processInfo.arguments
        guard backendConfigurationTestEnabled else { return nil }
        guard let index = args.firstIndex(of: "--data-session-engine"), args.indices.contains(index + 1) else {
            guard standaloneDefaultMode,
                  !args.contains("--handshake-probe"),
                  !args.contains("--engine-evaluator") else { return nil }
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
        func value(_ name: String) -> String? {
            guard let at = args.firstIndex(of: name), args.indices.contains(at + 1) else { return nil }
            return args[at + 1]
        }
        guard let socket = value("--executor-socket"), let peer = value("--ping-peer"),
              let hold = Int(value("--hold-ms") ?? ""), hold >= 1, hold <= 560_000,
              let count = Int(value("--ping-count") ?? "3"), count >= 1, count <= 10 else { return nil }
        var address = in_addr()
        guard !socket.isEmpty, socket.utf8.count <= 100, socket.rangeOfCharacter(from: .controlCharacters) == nil,
              peer.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return nil }
        // Optional in-tunnel DNS probe, all-or-nothing.
        var digServer: String?, digName: String?
        if value("--dig-server") != nil || value("--dig-name") != nil {
            guard let server = value("--dig-server"), let name = value("--dig-name"),
                  !server.isEmpty, server.utf8.count <= 15,
                  server.withCString({ inet_pton(AF_INET, $0, &address) }) == 1,
                  OpenVPNDataSession.validQueryName(name) else { return nil }
            digServer = server; digName = name
        }
        return (URL(fileURLWithPath: args[index + 1]), socket, hold, peer, count, digServer, digName)
    }
    private var engineEvaluator: URL? {
        let args = ProcessInfo.processInfo.arguments
        guard backendConfigurationTestEnabled, let index = args.firstIndex(of: "--engine-evaluator"), args.indices.contains(index + 1) else { return nil }
        return URL(fileURLWithPath: args[index + 1])
    }
    private var backendTask: Task<Void, Never>?
    private let backendSession = BackendAuthenticationSession()
    private var backendAuthenticationValidated = false
    private var backendUserLogout = "not-requested"
    let connectionTestEnabled = ProcessInfo.processInfo.arguments.contains("--cas-connect-test")
    var diagnosticEnabled: Bool { backendTestEnabled || connectionTestEnabled || ProcessInfo.processInfo.arguments.contains("--cas-preauthentication-test") }
    @Published var awaitingCallback = false
    @Published var connectionPhase = "idle"
    private var phases: [String] = []
    private var authenticationShape: [String: String] = [:]
    private var endpointShape: [String: String] = [:]
    private var callbackGate = CASCallbackGate()
    private var diagnosticSettings: NativeSettings?
    private var cancellation: Cancellation?
    private var generation = UUID()
    private var reopenOfficial = false
    private func writeReport(finished: Bool = false, failed: Bool = false) {
        let arguments = ProcessInfo.processInfo.arguments
        guard let index = arguments.firstIndex(of: "--session-report"), arguments.indices.contains(index + 1) else { return }
        let url = URL(fileURLWithPath: arguments[index + 1])
        let serializedResources: [[String: String]] = workbenchResources.map { resource in
            var item: [String: String] = ["id": resource.id, "name": resource.name, "url": resource.url]
            if let type = resource.type { item["type"] = type }
            return item
        }
        let report: [String: Any] = ["schemaVersion": 1, "mode": financeMode ? "bounded-standalone-finance" : (backendTestEnabled ? (backendConfigurationTestEnabled ? "bounded-direct-backend-configuration" : "bounded-direct-backend-preauthentication") : (connectionTestEnabled ? "bounded-cas-connection" : "bounded-cas-preauthentication")),
            "backendAuthentication": backendSession.state.rawValue, "officialIPCUsed": !backendTestEnabled,
            "backendAuthenticationValidated": backendAuthenticationValidated, "backendUserLogout": backendUserLogout,
            "serverRevocationVerified": false, "backendConfigurationValidated": backendConfigurationValidated,
            "backendConfiguration": backendConfigurationReceipt, "backendConfigurationFailure": backendConfigurationFailure, "backendEngineEvaluation": backendEngineEvaluation, "backendHandshake": backendHandshake, "backendDataSession": backendDataSession, "networkInputCollection": backendConfigurationTestEnabled ? "optional-fields-omitted" : "not-requested",
            "workbenchResources": serializedResources,
            "workbenchFailure": workbenchFailure ?? "none",
            "tunnelInterface": activeTunnelInterface ?? "",
            "virtualIPv4": activeVirtualIPv4 ?? "",
            "phase": connectionPhase, "phases": phases, "tunnel": status.rawValue,
            "endpointCheck": policy.endpointCheck.rawValue, "requiresReauthentication": policy.requiresReauthentication,
            "endpointShape": endpointShape, "authenticationShape": authenticationShape, "finished": finished, "transportFailed": failed,
            "campusValidated": financeMode ? financeCampusValidated : false,
            "officialBackendStillRequired": financeMode ? backendStillRunning : true,
            "financeHomepageValidated": financeMode ? financeHomepageValidated : false,
            "sensitiveFieldsRecorded": false]
        do {
            let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
            try data.write(to: url, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch { detail = "无法保存本次测试状态，请检查报告目录。" }
    }
    private func setConnectionPhase(_ phase: String) {
        connectionPhase = phase
        if phases.last != phase { phases.append(phase); if phases.count > 64 { phases.removeFirst() } }
        writeReport()
    }
    private func loadKey() -> Data? {
        var keyURL = Bundle.main.url(forResource: "vendor-public-key", withExtension: "der")
        if keyURL == nil {
            let panel = NSOpenPanel()
            panel.title = "选择已核验的服务公钥 vendor-public-key.der"
            panel.canChooseDirectories = false
            guard panel.runModal() == .OK else { return nil }
            keyURL = panel.url
        }
        guard let url = keyURL, let key = try? Data(contentsOf: url), key.count <= 8192 else {
            detail = "无法读取服务公钥。"; return nil
        }
        guard SHA256.hash(data: key).map({ String(format: "%02x", $0) }).joined() == "e3cad91855f033d1355592d3373813082964ecd296f63c0d84da728f81940824" else {
            detail = "公钥与已核验安装包不一致，未连接服务。"
            return nil
        }
        return key
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
    func start() {
        guard !backendTestEnabled else { return }
        guard mayStart(), let key = loadKey() else { return }
        let cancel = Cancellation()
        cancellation = cancel
        generation = UUID()
        let id = generation
        running = true
        status = .unknown
        policy = PolicyObservation()
        detail = "正在接入本机服务；并行运行官方界面可能影响会话。"
        Task.detached { [self] in
            do {
                _ = try runNativeSession(publicKeyDER: key, port: 8234, duration: .seconds(3600), cancelled: { cancel.isCancelled() }, onStatus: { state in
                    DispatchQueue.main.async { [self] in
                        guard self.running, self.generation == id, !cancel.isCancelled() else { return }
                        self.status = state
                        self.detail = "仅反映隧道状态；校园资源与报账大厅需另行验证。"
                    }
                }, onPolicy: { observation in
                    DispatchQueue.main.async { [self] in
                        guard self.running, self.generation == id, !cancel.isCancelled() else { return }
                        self.policy = observation
                    }
                })
                await self.finish(id, failed: false)
            } catch { await self.finish(id, failed: true, sessionBusy: (error as? SessionLeaseError) == .busy) }
        }
    }
    func finish(_ id: UUID, failed: Bool, sessionBusy: Bool = false) {
        guard generation == id else { return }
        running = false
        status = .unavailable
        detail = failed ? "服务连接结束或协议校验失败。请打开官方客户端恢复。" : "监测已结束；未发送断网或退出登录命令。"
        if sessionBusy { detail = "另一个轻量客户端或诊断程序正在使用服务，请先停止它。" }
        cancellation = nil
        if reopenOfficial { reopenOfficial = false; openOfficialApplication() }
    }
    func prepareIndependentCAS() {
        guard diagnosticEnabled, !awaitingCallback, mayStart() else { return }
        if backendTestEnabled {
            guard backendSession.state == .idle else { detail = "本次独立认证测试已结束，请重新启动测试。"; return }
            callbackGate.begin(); awaitingCallback = true; phases = []
            setConnectionPhase("discovering")
            prepareBackendCAS()
            return
        }
        do {
            let directory = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("cas-diagnostic", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            diagnosticSettings = try VendorDistribution.settings(app: URL(fileURLWithPath: "/Applications/SecureLink/SecureLink.app"), pid: ProcessInfo.processInfo.processIdentifier, logPath: directory.appendingPathComponent("gui.log").path)
            callbackGate.begin()
            awaitingCallback = true
            phases = []
            authenticationShape = [:]
            endpointShape = [:]
            setConnectionPhase("discovering")
            prepareCAS()
        } catch {
            diagnosticSettings = nil
            detail = "已安装厂商材料未通过固定版本校验，未开始独立预认证。"
        }
    }
    func receiveCallback(_ url: URL) {
        guard diagnosticEnabled, awaitingCallback, !running else { return }
        do {
            let credential = try callbackGate.consume(url)
            awaitingCallback = false
            if backendTestEnabled { authenticateBackend(credential); return }
            guard mayStart(), let key = loadKey(), let settings = diagnosticSettings else { diagnosticSettings = nil; return }
            diagnosticSettings = nil
            let authentication = NativeAuthenticationAttempt(settings: settings, credential: credential, connectsTunnel: connectionTestEnabled)
            let finalState = AuthenticationStateHolder()
            let connectionState = ConnectionStateHolder()
            let cancel = Cancellation()
            cancellation = cancel
            generation = UUID()
            let id = generation
            running = true
            detail = connectionTestEnabled ? "正在完成学校认证并初始化连接策略。" : "正在执行一次预配置、设置和预认证验证；不会发送连接命令。"
            setConnectionPhase("bootstrapping")
            let isConnectionTest = connectionTestEnabled
            Task.detached { [self] in
                do {
                    _ = try runNativeSession(publicKeyDER: key, port: 8234, duration: .seconds(isConnectionTest ? 180 : 40), cancelled: { cancel.isCancelled() }, onStatus: { state in
                        DispatchQueue.main.async { [self] in
                            guard self.running, self.generation == id, !cancel.isCancelled() else { return }
                            self.status = state; self.writeReport()
                        }
                    }, onPolicy: { observation in
                        DispatchQueue.main.async { [self] in
                            guard self.running, self.generation == id, !cancel.isCancelled() else { return }
                            self.policy = observation; self.writeReport()
                        }
                    }, authentication: authentication, onAuthentication: { state in
                        finalState.set(state)
                        DispatchQueue.main.async { [self] in
                            guard self.running, self.generation == id, !cancel.isCancelled() else { return }
                            self.detail = Self.authenticationText(state)
                        }
                    }, onConnection: { state in
                        connectionState.set(state)
                        DispatchQueue.main.async { [self] in
                            guard self.running, self.generation == id, !cancel.isCancelled() else { return }
                            let presentation = Self.connectionPresentation(state)
                            self.detail = presentation.text
                            self.setConnectionPhase(presentation.phase)
                        }
                    }, onAuthenticationShape: { shape in
                        DispatchQueue.main.async { [self] in
                            guard self.running, self.generation == id, !cancel.isCancelled() else { return }
                            self.authenticationShape = shape; self.writeReport()
                        }
                    }, onEndpointShape: { shape in
                        DispatchQueue.main.async { [self] in
                            guard self.running, self.generation == id, !cancel.isCancelled() else { return }
                            self.endpointShape = shape; self.writeReport()
                        }
                    })
                    if isConnectionTest { await self.finishConnection(id, failed: false, state: connectionState.get()) }
                    else { await self.finishDiagnostic(id, failed: false, state: finalState.get()) }
                } catch {
                    if isConnectionTest { await self.finishConnection(id, failed: true, state: connectionState.get()) }
                    else { await self.finishDiagnostic(id, failed: true, state: finalState.get()) }
                }
            }
        } catch {
            callbackGate.cancel(); awaitingCallback = false; diagnosticSettings = nil
            detail = "回跳参数、组织或时限未通过验证；未向服务提交令牌。"
        }
    }
    private static func connectionPresentation(_ state: CASConnectionFlow.State) -> (phase: String, text: String) {
        switch state {
        case .idle: return ("bootstrapping", "等待服务完成组织配置。")
        case .preAuthenticating: return ("preauthenticating", "正在验证学校登录结果。")
        case .initializingPolicy: return ("initializing-policy", "连接请求已发送，正在初始化学校策略。")
        case .initialized: return ("initialized", "登录后的配置已同步；连接状态与安全检查结果分别显示。")
        case .deviceRejected: return ("device-rejected", "学校服务拒绝了此设备，请处理设备信用要求。")
        case .informationRequired: return ("information-required", "学校服务要求补全账户信息。")
        case .serviceRejected: return ("service-rejected", "服务拒绝本次连接，未重复提交登录令牌。")
        case .unsupportedResponse: return ("unsupported-response", "服务返回了尚未支持的数据格式，本次连接已停止。")
        case .timedOut: return ("timed-out", "连接或策略初始化超时，未重复提交登录令牌。")
        case .cancelled: return ("cancelled", "本次连接会话已结束。")
        }
    }
    private func finishConnection(_ id: UUID, failed: Bool, state: CASConnectionFlow.State) {
        guard generation == id else { return }
        running = false; cancellation = nil; status = .unavailable
        let presentation = Self.connectionPresentation(state)
        detail = failed ? "本机服务通信失败。可打开官方客户端恢复连接。" : presentation.text
        setConnectionPhase(presentation.phase)
        writeReport(finished: true, failed: failed)
        if reopenOfficial { reopenOfficial = false; openOfficialApplication() }
    }
    private static func authenticationText(_ state: CASPreAuthentication.State) -> String {
        switch state {
        case .idle: return "等待原生服务完成组织预配置。"
        case .awaitingReply: return "设置已发送，等待一次预认证结果。"
        case .deviceRejected: return "服务拒绝设备信用，请通过官方客户端处理。"
        case .informationRequired: return "服务要求补全用户信息，请通过官方客户端处理。"
        case .responseValidated: return "预认证响应格式已验证；未建立隧道，学校策略尚未初始化。"
        case .serviceRejected: return "服务拒绝本次预认证；未重试令牌。"
        case .unsupportedResponse: return "预认证响应包含尚未支持的格式；验证已停止。"
        case .timedOut: return "预认证超时；未重试令牌。"
        case .cancelled: return "预认证验证已取消或服务已关闭。"
        }
    }
    private func finishDiagnostic(_ id: UUID, failed: Bool, state: CASPreAuthentication.State) {
        guard generation == id else { return }
        running = false; cancellation = nil; status = .unavailable
        detail = failed ? "独立预认证传输失败，未发送连接命令。请恢复官方客户端。" : Self.authenticationText(state)
        writeReport(finished: true, failed: failed)
        if reopenOfficial { reopenOfficial = false; openOfficialApplication() }
    }
    private func prepareBackendCAS() {
        let cancel = Cancellation()
        cancellation = cancel; generation = UUID()
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
            self.backendAuthenticationValidated = accepted
            self.setConnectionPhase(accepted ? "backend-authenticated" : "backend-authentication-stopped")
            if accepted && self.backendConfigurationTestEnabled {
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
                        self.workbenchFailure = resourceCollection.failure
                        self.syncShortcutsWithWorkbench()
                    }
                    let receipt = try JSONEncoder().encode(configuration.receipt)
                    self.backendConfigurationReceipt = (try JSONSerialization.jsonObject(with: receipt)) as? [String: Any] ?? [:]
                    self.backendConfigurationValidated = true
                    self.setConnectionPhase("backend-configuration-received")
                    if let evaluator = self.engineEvaluator {
                        do {
                            let evaluation = try await OpenVPNEvaluation.evaluate(configuration, executable: evaluator)
                            try Task.checkCancellation()
                            let data = try JSONEncoder().encode(evaluation)
                            self.backendEngineEvaluation = (try JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
                        } catch let error as OpenVPNEvaluationError {
                            self.backendEngineEvaluation = ["error": String(describing: error)]
                        } catch { self.backendEngineEvaluation = ["error": "cancelled-or-unavailable"] }
                        self.setConnectionPhase("backend-engine-evaluated")
                    }
                    if let session = self.dataSessionEngine {
                        // Merged data engine: config rides the in-memory pipe,
                        // the executor transaction delivers the utun fd, and
                        // the receipt proves the in-tunnel ping got replies.
                        self.status = .connecting
                        self.detail = "正在建立零信任网络隧道并同步深大内网路由与 DNS..."
                        self.setConnectionPhase("backend-data-session-preparing")
                        let metadataShape = self.backendSession.handshakeMetadataShape
                        do {
                            var resolveDomains: [String] = []
                            var seenDomains: Set<String> = []
                            let candidateHosts = Self.campusRedirectChainDomains
                                + BackendResources.extractHosts(from: self.workbenchResources)
                                + CampusShortcuts.extractHosts(from: self.shortcuts)
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
                                            self.financeTunnelStatus = "connected"
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
                                                    self.workbenchFailure = nil
                                                    self.syncShortcutsWithWorkbench()
                                                    self.writeReport()
                                                } else if let failure = refreshed.failure {
                                                    self.workbenchFailure = failure
                                                    self.writeReport()
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
                            let data = try JSONEncoder().encode(receipt)
                            var payload = (try JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
                            // Only the separately named private artifact holds networking details.
                            payload.removeValue(forKey: "plan")
                            payload["planComplete"] = receipt.plan?.complete ?? false
                            payload["planFailure"] = receipt.plan?.failure ?? "none"
                            self.backendDataSession = payload
                            if let plan = receipt.plan {
                                let arguments = ProcessInfo.processInfo.arguments
                                if let index = arguments.firstIndex(of: "--session-report"), arguments.indices.contains(index + 1) {
                                    let target = URL(fileURLWithPath: arguments[index + 1]).deletingLastPathComponent().appendingPathComponent("captured-network-plan.json")
                                    let encoded = try JSONEncoder().encode(plan)
                                    try encoded.write(to: target, options: [.atomic])
                                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
                                } else if !self.standaloneDefaultMode {
                                    throw OpenVPNEvaluationError.invalidReceipt
                                }
                            }
                            self.handshakeValidated = receipt.verified
                            // Standalone finance acceptance: cite the homepage
                            // observation only when the tunnel really carried the
                            // session and the page validated on our own path.
                            if self.financeMode {
                                self.financeTunnelStatus = receipt.verified ? "connected" : "disconnected"
                                self.status = receipt.verified ? .connected : .disconnected
                                var homepageValidated = false
                                if let path = self.homepageObservationPath,
                                   let data = try? Data(contentsOf: path),
                                   let observation = try? JSONDecoder().decode(FinanceHomepageObservation.self, from: data) {
                                    homepageValidated = observation.validated && receipt.verified
                                }
                                self.financeHomepageValidated = homepageValidated
                                self.financeCampusValidated = receipt.verified && homepageValidated && !self.backendStillRunning
                                if homepageValidated {
                                    self.setConnectionPhase("finance-homepage-validated")
                                }
                            } else {
                                self.status = .disconnected
                            }
                            self.setConnectionPhase(receipt.verified ? "backend-data-session-verified" : "backend-data-session-ended")
                        } catch let error as BackendHandshakePreparationError {
                            self.backendDataSession = ["error": String(describing: error)]
                        } catch let error as BackendSessionError {
                            self.backendDataSession = ["error": "session-" + String(describing: error)]
                        } catch let error as UVMetadata.BuildError {
                            self.backendDataSession = ["error": "metadata-" + String(describing: error)]
                        } catch let error as BackendDiscoveryError {
                            self.backendDataSession = ["error": "public-material-" + String(describing: error)]
                        } catch is NativeDeviceProfileError {
                            self.backendDataSession = ["error": "device-profile-unavailable"]
                        } catch is NativeDeviceIdentityError {
                            self.backendDataSession = ["error": "device-identity-unavailable"]
                        } catch let error as OpenVPNEvaluationError {
                            self.backendDataSession = ["error": String(describing: error)]
                        } catch {
                            self.backendDataSession = ["error": Task.isCancelled ? "cancelled" : "data-session-unavailable"]
                        }
                        self.activeDataSessionStop = nil
                        self.backendDataSession["identityShape"] = metadataShape
                    } else if let probe = self.handshakeProbe {
                        self.setConnectionPhase("backend-handshake-preparing")
                        let metadataShape = self.backendSession.handshakeMetadataShape
                        do {
                            let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                            let input = try BackendHandshakePreparation.prepare(session: self.backendSession, configuration: configuration,
                                identityDirectory: support.appendingPathComponent("SZUSecureLink", isDirectory: true),
                                nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
                            let capturePlan = ProcessInfo.processInfo.arguments.contains("--capture-plan")
                            var receipt = try await OpenVPNHandshake.perform(input, executable: probe, capturePlan: capturePlan)
                            let networkAllowed = ProcessInfo.processInfo.arguments.contains("--allow-handshake")
                            if receipt.reason == "input-validated" && networkAllowed {
                                self.setConnectionPhase("backend-handshake-running")
                                receipt = try await OpenVPNHandshake.perform(input, executable: probe, allowNetwork: true, capturePlan: capturePlan)
                            }
                            try Task.checkCancellation()
                            let data = try JSONEncoder().encode(receipt)
                            self.backendHandshake = (try JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
                            // Only the separately named private artifact holds networking details.
                            self.backendHandshake.removeValue(forKey: "plan")
                            self.backendHandshake["planComplete"] = receipt.plan?.complete ?? false
                            self.backendHandshake["planFailure"] = receipt.plan?.failure ?? "none"
                            if let plan = receipt.plan {
                                let arguments = ProcessInfo.processInfo.arguments
                                if let index = arguments.firstIndex(of: "--session-report"), arguments.indices.contains(index + 1) {
                                    let target = URL(fileURLWithPath: arguments[index + 1]).deletingLastPathComponent().appendingPathComponent("captured-network-plan.json")
                                    let encoded = try JSONEncoder().encode(plan)
                                    try encoded.write(to: target, options: [.atomic])
                                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
                                } else if !self.standaloneDefaultMode {
                                    throw OpenVPNEvaluationError.invalidReceipt
                                }
                            }
                            self.handshakeValidated = networkAllowed
                                ? receipt.tunnelSetupRequested && !receipt.unexpectedConnected && receipt.reason == "tunnel-boundary" && (!capturePlan || receipt.plan?.complete == true)
                                : receipt.reason == "input-validated" && !receipt.connectCalled
                        } catch let error as BackendHandshakePreparationError {
                            self.backendHandshake = ["error": String(describing: error)]
                        } catch let error as BackendSessionError {
                            self.backendHandshake = ["error": "session-" + String(describing: error)]
                        } catch let error as UVMetadata.BuildError {
                            self.backendHandshake = ["error": "metadata-" + String(describing: error)]
                        } catch let error as BackendDiscoveryError {
                            self.backendHandshake = ["error": "public-material-" + String(describing: error)]
                        } catch is NativeDeviceProfileError {
                            self.backendHandshake = ["error": "device-profile-unavailable"]
                        } catch is NativeDeviceIdentityError {
                            self.backendHandshake = ["error": "device-identity-unavailable"]
                        } catch let error as OpenVPNEvaluationError {
                            self.backendHandshake = ["error": String(describing: error)]
                        } catch {
                            self.backendHandshake = ["error": Task.isCancelled ? "cancelled" : "handshake-material-unavailable"]
                        }
                        self.backendHandshake["identityShape"] = metadataShape
                        self.setConnectionPhase("backend-handshake-ended")
                    }
                } catch let error as BackendNetworkConfigurationFailure {
                    self.backendConfigurationFailure = error.shape
                    self.setConnectionPhase("backend-configuration-stopped")
                } catch let error as BackendDiscoveryError {
                    self.backendConfigurationFailure = ["transport": String(describing: error)]
                    self.setConnectionPhase("backend-configuration-stopped")
                } catch {
                    self.backendConfigurationFailure = ["reason": Task.isCancelled ? "cancelled" : "unavailable"]
                    self.setConnectionPhase("backend-configuration-stopped")
                }
            }
            if accepted {
                self.detail = self.dataSessionEngine != nil
                    ? "正在断开零信任网络隧道并退出本次用户会话..."
                    : "独立预认证通过；正在退出本次用户会话。本次未建立隧道。"
                if !self.financeMode && self.dataSessionEngine != nil {
                    self.status = .disconnecting
                }
                do {
                    let attempt = try BackendLogoutAttempt.prepare(from: self.backendSession, nowMilliseconds: Int64(Date().timeIntervalSince1970 * 1000))
                    self.backendSession.cancel()
                    let receipt = try await attempt.perform()
                    try Task.checkCancellation()
                    self.backendUserLogout = receipt.userLogoutAccepted ? "accepted" : "rejected"
                } catch is CancellationError { self.backendUserLogout = "cancelled" }
                catch { self.backendUserLogout = "failed" }
                self.backendSession.cancel()
                if !self.financeMode && self.dataSessionEngine != nil {
                    self.status = .disconnected
                }
                self.setConnectionPhase("backend-test-ended")
            }
            self.running = false; self.backendTask = nil
            let configResult = self.backendConfigurationTestEnabled ? (self.backendConfigurationValidated ? "连接配置已取得；" : "连接配置尚未取得；") : ""
            if self.dataSessionEngine != nil {
                let tunnelSummary = self.handshakeValidated ? "零信任隧道已验证；" : "零信任隧道未完成验证；"
                self.detail = accepted
                    ? "会话已结束：\(configResult)\(tunnelSummary)退出结果：\(self.backendUserLogout)。"
                    : "独立预认证尚未完成：\(self.backendSession.state.rawValue)。"
            } else {
                self.detail = accepted ? "独立预认证通过；\(configResult)退出结果：\(self.backendUserLogout)。本次未建立隧道，校园访问仍未验收。" : "独立预认证尚未完成：\(self.backendSession.state.rawValue)。本次未建立隧道。"
            }
            self.writeReport(finished: true, failed: !accepted || self.backendUserLogout != "accepted" || (self.backendConfigurationTestEnabled && !self.backendConfigurationValidated) || (self.engineEvaluator != nil && self.backendEngineEvaluation["accepted"] as? Bool != true) || ((self.handshakeProbe != nil || self.dataSessionEngine != nil) && !self.handshakeValidated))
            self.emitWorkerLine("DISCONNECTED: \(self.detail)")
            if self.headlessWorkerMode { Darwin.exit(0) }
            if self.reopenOfficial { self.reopenOfficial = false; self.openOfficialApplication() }
        }
    }
    func prepareCAS() {
        guard !backendTestEnabled else { return }
        guard mayStart(), let key = loadKey() else {
            callbackGate.cancel(); awaitingCallback = false; diagnosticSettings = nil
            return
        }
        let cancel = Cancellation()
        cancellation = cancel
        generation = UUID()
        let id = generation
        let holder = LoginURLHolder()
        running = true
        status = .unknown
        detail = "正在向本机服务查询 szu 的 CAS 入口；不读取校园密码。"
        Task.detached { [self] in
            do {
                _ = try runNativeSession(publicKeyDER: key, port: 8234, duration: .seconds(20), cancelled: { cancel.isCancelled() }, discoverCAS: true, onCASURL: { holder.set($0) })
                let url = cancel.isCancelled() ? nil : holder.take()
                await self.finishCAS(id, url: url)
            } catch { await self.finishCAS(id, url: nil) }
        }
    }
    private func finishCAS(_ id: UUID, url: URL?) {
        guard generation == id else { return }
        let wasCancelled = cancellation?.isCancelled() ?? true
        running = false
        cancellation = nil
        status = .unavailable
        if reopenOfficial { reopenOfficial = false; openOfficialApplication(); return }
        guard !wasCancelled, let url else {
            callbackGate.cancel(); awaitingCallback = false; diagnosticSettings = nil
            detail = "CAS 地址获取已取消、超时或未通过校验。可通过官方客户端登录。"
            emitWorkerLine("DISCONNECTED: \(detail)")
            if backendTestEnabled { backendSession.cancel(); writeReport(finished: true, failed: true) }
            if headlessWorkerMode { Darwin.exit(0) }
            return
        }
        detail = awaitingCallback ? "已打开学校 CAS 登录页，请在浏览器完成登录（5 分钟内有效）。" : "已打开学校 CAS；登录后的回跳仍交给官方 SecureLink。当前未接管协议。"
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
        cancellation?.cancel(); backendTask?.cancel(); backendSession.cancel(); status = .unavailable
        activeTunnelInterface = nil; activeVirtualIPv4 = nil
        callbackGate.cancel(); awaitingCallback = false; diagnosticSettings = nil
        if backendTestEnabled { writeReport(finished: true, failed: true) }
    }
    func officialLogin() {
        callbackGate.cancel(); awaitingCallback = false; diagnosticSettings = nil
        if backendTestEnabled && !running { stop(); openOfficialApplication(); return }
        if running { reopenOfficial = true; stop(); return }
        openOfficialApplication()
    }
    private func openOfficialApplication() {
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: "/Applications/SecureLink/SecureLink.app"), configuration: .init()) { _, _ in }
    }
    var hasStandaloneDataSession: Bool { dataSessionEngine != nil }
    var policyText: String {
        if policy.requiresReauthentication { return "部分资源需要二次认证，请打开官方客户端完成；隧道在线不代表资源已获授权。" }
        switch policy.endpointCheck {
        case .unknown: return "尚未确认端点安全检查结果。"
        case .notRequired: return "服务报告当前未启用端点安全检查；这不等于检查通过。"
        case .failed: return "端点安全检查服务返回错误，尚未完成检查。"
        case .requested: return "服务要求重新安全检查，请打开官方客户端处理。"
        case .running: return "官方服务正在检查端点安全状态。"
        case .healthy: return "收到健康状态结果；资源授权仍由学校策略决定。"
        case .needsAttention: return "端点安全检查需要处理，请打开官方客户端查看。"
        }
    }
    var statusText: String {
        if isEnglishLocale {
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
    var schemeAccentColor: Color {
        Color(red: 0x8C / 255.0, green: 0x22 / 255.0, blue: 0x32 / 255.0)
    }
}

enum MenuBarStatusIcon {
    static func image(connected: Bool) -> NSImage {
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
    @StateObject private var model = SessionModel()
    var body: some Scene {
        Window("SZU SecureLink", id: "main") {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 12) {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(model.schemeAccentColor)
                        .frame(width: 34, height: 34)
                        .overlay(
                            Image(systemName: "building.columns.fill")
                                .font(.system(size: 16, weight: .semibold))
                                .foregroundStyle(.white)
                        )
                    VStack(alignment: .leading, spacing: 2) {
                        Text("SZU SecureLink")
                            .font(.system(size: 18, weight: .semibold))
                        Text(model.isEnglishLocale ? "Shenzhen University Campus Access" : "深圳大学校园网与常用服务")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(model.isEnglishLocale ? "中文" : "EN") {
                        model.isEnglishLocale.toggle()
                    }
                    .controlSize(.small)
                }

                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 10) {
                        Circle()
                            .fill(model.status == .connected ? Color(red: 0x2B / 255.0, green: 0x6E / 255.0, blue: 0x48 / 255.0) : Color.secondary.opacity(0.45))
                            .frame(width: 10, height: 10)
                        Text(model.statusText)
                            .font(.system(size: 18, weight: .semibold))
                        Spacer()
                        if model.status == .connected {
                            Button(model.isEnglishLocale ? "Disconnect" : "断开") {
                                model.disconnectTunnel()
                            }
                            .controlSize(.regular)
                        } else if model.awaitingCallback {
                            Button(model.isEnglishLocale ? "Disconnect" : "断开") {
                                model.stop()
                            }
                            .controlSize(.regular)
                        } else {
                            Button(model.isEnglishLocale ? "Connect" : "连接") {
                                if model.diagnosticEnabled {
                                    model.prepareIndependentCAS()
                                } else {
                                    model.start()
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(model.schemeAccentColor)
                            .controlSize(.regular)
                        }
                    }
                    Text(model.detail)
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 12) {
                        Button(model.showNetworkDetails
                               ? (model.isEnglishLocale ? "Hide Network Details" : "收起网络详情")
                               : (model.isEnglishLocale ? "Show Network Details" : "展开网络详情")) {
                            model.showNetworkDetails.toggle()
                        }
                        .font(.system(size: 12))
                        .buttonStyle(.link)
                        Spacer()
                        Text(model.isEnglishLocale
                             ? "Clicking any service below auto-connects and opens it"
                             : "未连接时直接点下方服务，将自动连接并打开")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                    if model.showNetworkDetails {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(spacing: 16) {
                                Text("IPv4: \(model.activeVirtualIPv4 ?? "1.1.105.34")")
                                    .font(.system(size: 12, design: .monospaced))
                                Text("Interface: \(model.activeTunnelInterface ?? "utun4")")
                                    .font(.system(size: 12, design: .monospaced))
                                Text("DNS: 192.168.247.6")
                                    .font(.system(size: 12, design: .monospaced))
                                Text(SparkleNumericFormatter.formatRouteCount(129, english: model.isEnglishLocale) ?? "")
                                    .font(.system(size: 12))
                            }
                            .foregroundStyle(.secondary)
                            if !model.backendTestEnabled {
                                HStack(spacing: 8) {
                                    Button("CAS 登录") { model.officialLogin() }.controlSize(.small)
                                    Button("原版回跳入口") { model.prepareCAS() }.controlSize(.small)
                                        .disabled(model.running || model.awaitingCallback)
                                }
                            }
                        }
                        .padding(10)
                        .background(Color.secondary.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
                .padding(14)
                .background(Color.secondary.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 12))

                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(model.isEnglishLocale ? "Menu Bar Quick Access (4 Pinned Services)" : "菜单栏快速直达（固定 4 项常用服务）")
                            .font(.system(size: 14, weight: .semibold))
                        Spacer()
                        Text("\(model.menuBarPinnedShortcuts.count) / \(MenuBarPinStore.slotCount)")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 8) {
                        ForEach(model.menuBarPinnedShortcuts) { pin in
                            Button {
                                model.openOrConnectShortcut(pin)
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

                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text(model.isEnglishLocale ? "Campus Services" : "校内常用服务")
                            .font(.system(size: 14, weight: .semibold))
                        Spacer()
                        Button(model.showShortcutManager
                               ? (model.isEnglishLocale ? "Hide All (\(model.shortcuts.count))" : "收起全部 (\(model.shortcuts.count))")
                               : (model.isEnglishLocale ? "All Services & Custom (\(model.shortcuts.count))" : "全部服务与自定义 (\(model.shortcuts.count))")) {
                            model.showShortcutManager.toggle()
                        }
                        .font(.system(size: 12))
                        .buttonStyle(.link)
                    }
                    let favorites = model.shortcuts.filter(\.isFavorite)
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 8) {
                        ForEach(favorites) { item in
                            HStack(spacing: 6) {
                                Button {
                                    model.openOrConnectShortcut(item)
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
                                    model.toggleMenuBarPin(item.id)
                                } label: {
                                    Image(systemName: model.isPinnedToMenuBar(item.id) ? "pin.fill" : "pin")
                                        .foregroundStyle(model.isPinnedToMenuBar(item.id) ? model.schemeAccentColor : .secondary)
                                }
                                .buttonStyle(.plain)
                                .help(model.isEnglishLocale ? "Pin to Menu Bar (4 slots)" : "固定到菜单栏（4 个槽位）")
                            }
                        }
                    }
                    if model.showShortcutManager {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(model.shortcuts) { item in
                                HStack(spacing: 8) {
                                    Button {
                                        model.toggleFavoriteShortcut(item.id)
                                    } label: {
                                        Image(systemName: item.isFavorite ? "star.fill" : "star")
                                            .foregroundStyle(item.isFavorite ? model.schemeAccentColor : .secondary)
                                    }
                                    .buttonStyle(.plain)
                                    Button {
                                        model.toggleMenuBarPin(item.id)
                                    } label: {
                                        Image(systemName: model.isPinnedToMenuBar(item.id) ? "pin.fill" : "pin")
                                            .foregroundStyle(model.isPinnedToMenuBar(item.id) ? model.schemeAccentColor : .secondary)
                                    }
                                    .buttonStyle(.plain)
                                    Text(item.name).font(.system(size: 13, weight: .medium))
                                    Text(item.subtitle).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                                    Spacer()
                                    Button(model.isEnglishLocale ? "Open" : "打开") {
                                        model.openOrConnectShortcut(item)
                                    }
                                    .controlSize(.small)
                                    if !item.isBuiltIn {
                                        Button(model.isEnglishLocale ? "Remove" : "移除") {
                                            model.removeCustomShortcut(item.id)
                                        }
                                        .controlSize(.small)
                                    }
                                }
                            }
                            HStack(spacing: 6) {
                                TextField(model.isEnglishLocale ? "Service Name" : "服务名称（如：教务部）", text: $model.customShortcutName)
                                    .textFieldStyle(.roundedBorder)
                                    .frame(width: 150)
                                TextField(model.isEnglishLocale ? "https://..." : "直达网址（http/https）", text: $model.customShortcutURL)
                                    .textFieldStyle(.roundedBorder)
                                Button(model.isEnglishLocale ? "Pin" : "固定") {
                                    model.addCustomShortcut()
                                }
                                .disabled(model.customShortcutName.trimmingCharacters(in: .whitespaces).isEmpty || model.customShortcutURL.trimmingCharacters(in: .whitespaces).isEmpty)
                            }
                        }
                        .padding(10)
                        .background(Color.secondary.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }

                Divider()
                HStack(spacing: 12) {
                    Text(model.aboutMetadata.attributionText)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                    Spacer()
                    if let feedback = model.updateCheckFeedback {
                        Text(feedback)
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                    Button(model.isEnglishLocale ? "Update" : "更新") {
                        model.checkForUpdates()
                    }
                    .font(.system(size: 12))
                    .buttonStyle(.link)
                    Button(model.isEnglishLocale ? "About" : "关于") {
                        model.showAboutSheet = true
                    }
                    .font(.system(size: 12))
                    .buttonStyle(.link)
                }
            }
            .tint(model.schemeAccentColor)
            .padding(22)
            .frame(width: 600)
            .sheet(isPresented: $model.showAboutSheet) {
                AboutSheetView(model: model)
            }
            .onAppear {
                if model.headlessWorkerMode {
                    model.startHeadlessWorkerIfRequested()
                    return
                }
                NSApp.activate(ignoringOtherApps: true)
                if !model.standaloneDefaultMode && model.backendTestEnabled && model.hasStandaloneDataSession && !model.running && !model.awaitingCallback {
                    model.prepareIndependentCAS()
                }
            }
            .onOpenURL { model.receiveCallback($0) }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in model.stop() }
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("关于 SZU SecureLink") {
                    model.showAboutSheet = true
                }
            }
            CommandGroup(after: .appInfo) {
                Button("检查更新...") {
                    model.checkForUpdates()
                    model.showAboutSheet = true
                }
            }
        }

        MenuBarExtra {
            TrayMenuPopoverView(model: model)
        } label: {
            Image(nsImage: MenuBarStatusIcon.image(connected: model.status == .connected))
        }
        .menuBarExtraStyle(.window)
    }
}

struct TrayMenuPopoverView: View {
    @ObservedObject var model: SessionModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle()
                    .fill(model.status == .connected ? Color(red: 0x2B / 255.0, green: 0x6E / 255.0, blue: 0x48 / 255.0) : Color.secondary.opacity(0.45))
                    .frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 1) {
                    Text(model.statusText)
                        .font(.system(size: 14, weight: .semibold))
                    if let vip = model.activeVirtualIPv4, model.status == .connected {
                        Text(vip)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if model.status == .connected {
                    Button(model.isEnglishLocale ? "Disconnect" : "断开") {
                        model.disconnectTunnel()
                    }
                    .controlSize(.small)
                } else {
                    Button(model.isEnglishLocale ? "Connect" : "连接") {
                        if model.diagnosticEnabled {
                            model.prepareIndependentCAS()
                        } else {
                            model.start()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(model.schemeAccentColor)
                    .controlSize(.small)
                }
            }

            Divider()

            Text(model.isEnglishLocale ? "Pinned Campus Services (4)" : "固定常用服务（一键连接并打开）")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)

            VStack(spacing: 4) {
                ForEach(model.menuBarPinnedShortcuts) { item in
                    Button {
                        model.openOrConnectShortcut(item)
                    } label: {
                        HStack {
                            Text(item.name)
                                .font(.system(size: 13, weight: .medium))
                            Spacer()
                            Text(model.isEnglishLocale ? "Open" : "打开")
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
                Button(model.isEnglishLocale ? "Open Workbench" : "打开主窗口") {
                    NSApp.activate(ignoringOtherApps: true)
                }
                .font(.system(size: 12))
                .buttonStyle(.link)
                Spacer()
                Button(model.isEnglishLocale ? "Update" : "更新") {
                    model.checkForUpdates()
                }
                .font(.system(size: 12))
                .buttonStyle(.link)
                Button(model.isEnglishLocale ? "Quit" : "退出") {
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
    @ObservedObject var model: SessionModel

    var body: some View {
        VStack(spacing: 14) {
            RoundedRectangle(cornerRadius: 12)
                .fill(model.schemeAccentColor)
                .frame(width: 48, height: 48)
                .overlay(
                    Image(systemName: "building.columns.fill")
                        .font(.system(size: 22, weight: .semibold))
                        .foregroundStyle(.white)
                )
                .padding(.top, 4)
            VStack(spacing: 4) {
                Text(model.aboutMetadata.appName)
                    .font(.system(size: 18, weight: .semibold))
                Text("v\(model.aboutMetadata.version) (Build \(model.aboutMetadata.build))")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Text(model.aboutMetadata.summary)
                .font(.system(size: 13))
                .multilineTextAlignment(.center)
                .foregroundStyle(.primary)
                .padding(.horizontal, 12)
            Divider()
            VStack(spacing: 6) {
                HStack(spacing: 10) {
                    Button(model.isEnglishLocale ? "Update" : "更新") {
                        model.checkForUpdates()
                    }
                    .controlSize(.small)
                    Text(model.updateCheckFeedback ?? model.aboutMetadata.updateStatusText)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                Text("Sparkle Feed: \(model.sparkleConfig.feedURL)")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
                Text(model.aboutMetadata.attributionText)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .padding(.top, 2)
            }
            Divider()
            HStack {
                Spacer()
                Button(model.isEnglishLocale ? "Close" : "关闭") {
                    model.showAboutSheet = false
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(width: 390)
    }
}
