import Foundation

/// Socket-independent protocol reducer. Time is elapsed monotonic duration supplied
/// by the transport; heartbeats never refresh the age of the tunnel status.
public struct NativeProtocolSession {
    public struct Effects {
        public var outgoing: [Data] = []
        public var outgoingCommands: [UInt32] = []
        public var statuses: [TunnelStatus] = []
        public var policy: PolicyObservation?
        public var loginURL: URL?
        public var commands: [UInt32] = []
        public var heartbeatReplies = 0
        public var authenticationShape: [String: String]?
        public var endpointShape: [String: String]?
    }
    private var bootstrap: NativeBootstrap?
    private var credential: PendingCASCredential?
    private var preAuthentication: CASPreAuthentication?
    private var connection: CASConnectionFlow?
    public var connectionState: CASConnectionFlow.State? { connection?.state }
    public mutating func didSend(command: UInt32, elapsed: Duration) {
        guard !ended else { return }
        connection?.didSend(command: command, elapsed: elapsed)
    }
    public var authenticationState: CASPreAuthentication.State? { preAuthentication?.state }
    public var authenticationComplete: Bool {
        if let connection { return connection.isTerminalFailure }
        guard let state = authenticationState else { return false }
        return state != .idle && state != .awaitingReply
    }
    private let cipher: SessionCipher
    private let discoveryEnabled: Bool
    private var decoder = EncryptedStreamDecoder()
    private var discovery = CASDiscovery()
    private var discoveryStarted = false
    private var latestStatusAt: Duration?
    private var displayedStatus: TunnelStatus = .unavailable
    private var policy = PolicyObservation()
    private var ended = false
    public private(set) var discoveryComplete = false
    public init(cipher: SessionCipher, discoverCAS: Bool = false) {
        self.cipher = cipher
        discoveryEnabled = discoverCAS
    }
    public init(cipher: SessionCipher, settings: NativeSettings, credential: PendingCASCredential, connectsTunnel: Bool = false) {
        self.cipher = cipher
        discoveryEnabled = false
        bootstrap = NativeBootstrap(settings: settings)
        self.credential = credential
        if connectsTunnel { connection = CASConnectionFlow(settings: settings) }
        else { preAuthentication = CASPreAuthentication() }
    }
    public mutating func advanceAuthentication(elapsed: Duration) throws {
        guard !ended else { return }
        do { try bootstrap?.advance(elapsed: elapsed) }
        catch { ended = true; credential = nil; throw error }
        preAuthentication?.advance(elapsed: elapsed)
        connection?.advance(elapsed: elapsed)
    }
    public mutating func receive(_ bytes: Data, elapsed: Duration) throws -> Effects {
        guard !ended, !discoveryComplete, !authenticationComplete else { throw FrameError.failedStream }
        var effects = Effects()
        do {
            try advanceAuthentication(elapsed: elapsed)
            for encrypted in try decoder.append(bytes) {
                var plain = try cipher.decrypt(encrypted)
                defer { plain.resetBytes(in: 0..<plain.count) }
                let message = try PlainFrame.decode(plain)
                effects.commands.append(message.command)
                if message.command == 20 {
                    effects.endpointShape = EndpointReplyShape.describe(message.payload)
                    effects.endpointShape?["currentCheckSent"] = connection?.policy?.securityCheckSent == true ? "yes" : "no"
                }
                if message.command == 10, connection != nil || preAuthentication != nil {
                    effects.authenticationShape = AuthenticationReplyShape.describe(message.payload)
                }
                if message.command == 3 {
                    latestStatusAt = elapsed
                    displayedStatus = TunnelStatus.decode(message.payload)
                    effects.statuses.append(displayedStatus)
                }
                let previous = policy
                if connection == nil { policy.receive(message) }
                if message.command == 1 {
                    effects.outgoing.append(envelope(try cipher.encrypt(plain)))
                    effects.outgoingCommands.append(1)
                    effects.heartbeatReplies += 1
                }
                if bootstrap != nil {
                    if message.command == 18, bootstrap?.state == .idle {
                        effects.outgoing.append(try encode(bootstrap!.begin(elapsed: elapsed)))
                        effects.outgoingCommands.append(35)
                    } else if bootstrap?.state == .awaitingPreConfig {
                        if let settings = try bootstrap!.receive(message, elapsed: elapsed) {
                            effects.outgoing.append(try encode(settings))
                            effects.outgoingCommands.append(settings.command)
                            guard let credential else { throw NativeBootstrapError.unexpectedResponse }
                            let pending = try connection?.begin(credential, elapsed: elapsed) ?? preAuthentication?.begin(credential, elapsed: elapsed)
                            guard let request = pending else {
                                throw NativeBootstrapError.unexpectedResponse
                            }
                            self.credential = nil
                            effects.outgoing.append(try encode(request))
                            effects.outgoingCommands.append(request.command)
                        }
                    } else {
                        preAuthentication?.receive(message, elapsed: elapsed)
                        if let connection {
                            for request in try connection.receive(message, elapsed: elapsed) {
                                effects.outgoing.append(try encode(request))
                                effects.outgoingCommands.append(request.command)
                            }
                        }
                    }
                }
                if discoveryEnabled {
                    if message.command == 18, !discoveryStarted {
                        discoveryStarted = true
                        effects.outgoing.append(try encode(discovery.begin()))
                        effects.outgoingCommands.append(28)
                    } else {
                        switch try discovery.receive(message) {
                        case .ignored: break
                        case .request(let request):
                            effects.outgoing.append(try encode(request))
                            effects.outgoingCommands.append(request.command)
                        case .ready(let url):
                            effects.loginURL = url
                            discoveryComplete = true
                        }
                    }
                }
                if let connection { policy = connection.policy?.observation ?? PolicyObservation() }
                if previous != policy { effects.policy = policy }
                if discoveryComplete || authenticationComplete { break }
            }
            effects.statuses.append(contentsOf: tick(elapsed: elapsed))
            return effects
        } catch { ended = true; credential = nil; throw error }
    }
    public mutating func tick(elapsed: Duration) -> [TunnelStatus] {
        guard !ended, let latestStatusAt, elapsed - latestStatusAt >= .seconds(10), displayedStatus != .unavailable else { return [] }
        displayedStatus = .unavailable
        return [.unavailable]
    }
    public mutating func finish() throws {
        ended = true
        credential = nil
        preAuthentication?.cancel()
        connection?.cancel()
        displayedStatus = .unavailable
        try decoder.finish()
    }
    private func encode(_ message: Message) throws -> Data {
        var plain = try PlainFrame.encode(message)
        defer { plain.resetBytes(in: 0..<plain.count) }
        return envelope(try cipher.encrypt(plain))
    }
    private func envelope(_ data: Data) -> Data {
        let count = UInt32(data.count)
        return Data([0, 8, 16, 24].map { UInt8(truncatingIfNeeded: count >> $0) }) + data
    }
}
