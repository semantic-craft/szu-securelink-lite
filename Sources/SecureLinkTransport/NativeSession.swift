import Foundation
import Security
import Darwin
import SecureLinkCore

enum LiveProbeError: Error { case invalidKey, randomFailure, socketFailure, timeout, malformed, invalidMode }
public struct LiveReport: Encodable, Sendable {
    let mode = "bounded-native-live-handshake"
    var connected = false
    var handshakeSent = false
    var encryptedFrames = 0
    var heartbeatReplies = 0
    var commands: [String:Int] = [:]
    var elapsedMilliseconds = 0
    var closed = false
}
public func runNativeSession(publicKeyDER: Data, port: UInt16, duration: Duration = .seconds(4), cancelled: @Sendable () -> Bool = { false }, onStatus: @Sendable (TunnelStatus) -> Void = { _ in }, onPolicy: @Sendable (PolicyObservation) -> Void = { _ in }, discoverCAS: Bool = false, onCASURL: @Sendable (URL) -> Void = { _ in }, authentication: NativeAuthenticationAttempt? = nil, onAuthentication: @Sendable (CASPreAuthentication.State) -> Void = { _ in }, onConnection: @Sendable (CASConnectionFlow.State) -> Void = { _ in }, onAuthenticationShape: @Sendable ([String: String]) -> Void = { _ in }, onEndpointShape: @Sendable ([String: String]) -> Void = { _ in }) throws -> LiveReport {
    let authenticationLimit: Duration = authentication?.connectsTunnel == true ? .seconds(300) : .seconds(40)
    guard !discoverCAS || authentication == nil, authentication == nil || (duration > .zero && duration <= authenticationLimit) else { throw LiveProbeError.invalidMode }
    if cancelled() { throw CancellationError() }
    let lease = try SessionLease()
    defer { lease.release() }
    guard publicKeyDER.count < 8192 else { throw LiveProbeError.invalidKey }
    var error: Unmanaged<CFError>?
    let attributes: [CFString:Any] = [kSecAttrKeyType:kSecAttrKeyTypeRSA, kSecAttrKeyClass:kSecAttrKeyClassPublic]
    guard let publicKey = SecKeyCreateWithData(publicKeyDER as CFData, attributes as CFDictionary, &error) else { throw LiveProbeError.invalidKey }
    var random = [UInt8](repeating: 0, count: 16)
    guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else { throw LiveProbeError.randomFailure }
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
    var key = Data(random.map { alphabet[Int($0 & 63)] })
    defer { key.resetBytes(in: 0..<key.count); _ = random.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    let sessionCipher = try SessionCipher(key: key, iv: Data("SeCuReLiNkCliENT".utf8))
    guard let rsa = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, (Data([71])+key) as CFData, &error) else { throw LiveProbeError.invalidKey }
    if cancelled() { throw CancellationError() }
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { throw LiveProbeError.socketFailure }
    defer { close(fd) }
    var timeout = timeval(tv_sec: 1, tv_usec: 0)
    var noSignal: Int32 = 1
    guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
          setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
          setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw LiveProbeError.socketFailure }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    guard result == 0 else { throw LiveProbeError.socketFailure }
    var report = LiveReport(); report.connected = true
    let start = ContinuousClock.now
    func send(_ data: Data) throws {
        var sent = 0
        try data.withUnsafeBytes { bytes in
            while sent < data.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: sent), data.count-sent)
                guard count > 0 else { throw LiveProbeError.socketFailure }; sent += count
            }
        }
    }
    func envelope(_ data: Data) -> Data {
        let count = UInt32(data.count)
        return Data([0,8,16,24].map { UInt8(truncatingIfNeeded: count >> $0) }) + data
    }
    if cancelled() { throw CancellationError() }
    try send(envelope(rsa as Data)); report.handshakeSent = true
    var engine: NativeProtocolSession
    if let authentication {
        engine = NativeProtocolSession(cipher: sessionCipher, settings: authentication.settings, credential: authentication.credential, connectsTunnel: authentication.connectsTunnel)
    } else {
        engine = NativeProtocolSession(cipher: sessionCipher, discoverCAS: discoverCAS)
    }
    defer { try? engine.finish(); onStatus(.unavailable) }
    while !cancelled(), !engine.discoveryComplete, !engine.authenticationComplete, start.duration(to: .now) < duration {
        var bytes = [UInt8](repeating: 0, count: 65536)
        let count = Darwin.read(fd, &bytes, bytes.count)
        if count == 0 { try engine.finish(); break }
        if count < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                try engine.advanceAuthentication(elapsed: start.duration(to: .now))
                if let state = engine.authenticationState { onAuthentication(state) }
                if let state = engine.connectionState { onConnection(state) }
                for status in engine.tick(elapsed: start.duration(to: .now)) { onStatus(status) }
                continue
            }
            throw LiveProbeError.socketFailure
        }
        let effects = try engine.receive(Data(bytes.prefix(count)), elapsed: start.duration(to: .now))
        guard !cancelled() else { break }
        if let shape = effects.authenticationShape { onAuthenticationShape(shape) }
        if let shape = effects.endpointShape { onEndpointShape(shape) }
        guard effects.outgoing.count == effects.outgoingCommands.count else { throw LiveProbeError.malformed }
        for (frame, command) in zip(effects.outgoing, effects.outgoingCommands) {
            guard !cancelled() else { throw CancellationError() }
            try send(frame)
            engine.didSend(command: command, elapsed: start.duration(to: .now))
        }
        if let state = engine.authenticationState { onAuthentication(state) }
        if let state = engine.connectionState { onConnection(state) }
        for status in effects.statuses { onStatus(status) }
        if let policy = effects.policy { onPolicy(policy) }
        if let url = effects.loginURL { onCASURL(url) }
        report.encryptedFrames += effects.commands.count
        report.heartbeatReplies += effects.heartbeatReplies
        for command in effects.commands { report.commands[String(command), default: 0] += 1 }
    }
    let duration = start.duration(to: .now).components
    report.elapsedMilliseconds = Int(duration.seconds * 1000 + duration.attoseconds / 1_000_000_000_000_000)
    if authentication != nil {
        if !engine.authenticationComplete { try engine.finish() }
        if let state = engine.authenticationState { onAuthentication(state) }
        if let state = engine.connectionState { onConnection(state) }
    }
    report.closed = true
    return report
}

/// Explicit bounded authentication. Tokens stay in memory; the default stops
/// before connection. Full connection still requires the normal browser callback.
public struct NativeAuthenticationAttempt: Sendable {
    let settings: NativeSettings
    let credential: PendingCASCredential
    let connectsTunnel: Bool
    public init(settings: NativeSettings, credential: PendingCASCredential, connectsTunnel: Bool = false) {
        self.settings = settings
        self.credential = credential
        self.connectsTunnel = connectsTunnel
    }
}
