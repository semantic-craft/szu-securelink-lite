import Foundation

/// Bounded data-session driver for the merged engine binary: config travels
/// through the in-memory pipe, the executor transaction delivers the utun fd,
/// and the receipt records whether the in-tunnel ping actually got replies.
public enum OpenVPNDataSession {
    public struct Receipt: Codable, Sendable {
        public let mode: String
        public let engine: String
        public let reason: String
        public let phase: String
        public let interface: String
        public let fdAccepted: Bool
        public let connectCalled: Bool
        public let socketObserved: Bool
        public let tunnelSetupRequested: Bool
        public let tunnelStarted: Bool
        public let connectedInDataMode: Bool
        public let pingRan: Bool
        public let pingExitStatus: Int
        public let pingTransmitted: Int
        public let pingReceived: Int
        public let digRan: Bool
        public let digExitStatus: Int
        public let digStatus: String?
        public let digAnswers: Int
        public let digServer: String?
        public let digName: String?
        public let ctrlPushesObserved: Int
        public let ctrlUpdatesSent: Int
        public let ctrlUpdatesFailed: Int
        public let ctrlRoutesPushed: [String]
        public let planCaptureRequested: Bool
        public let planComplete: Bool
        public let plan: CapturedTunnelPlan?
        public let holdMs: Int
        public let heartbeatsSent: Int
        public let disconnectSent: Bool
        public let deadlineReached: Bool
        public let unexpectedConnected: Bool
        public let eventsDropped: Bool
        public let events: [String]

        /// Verified means: real fd, connected, in-tunnel replies, clean finish.
        public var verified: Bool {
            reason == "data-session-verified" && fdAccepted && tunnelStarted
                && connectedInDataMode && pingRan && pingReceived > 0 && disconnectSent
        }
        /// In-tunnel DNS query answered through a vendor-dns-host-route resolver.
        public var dnsVerified: Bool {
            digRan && digStatus == "NOERROR" && digAnswers > 0 && digExitStatus == 0
        }
        /// Session ran end to end even when the peer never answered.
        public var ran: Bool {
            fdAccepted && tunnelStarted && connectedInDataMode
        }
    }

    public struct ActiveState: Sendable, Equatable {
        public let interface: String
        public let virtualIPv4: String?
        public init(interface: String, virtualIPv4: String? = nil) {
            self.interface = interface
            self.virtualIPv4 = virtualIPv4
        }
    }

    public static func parseActiveLine(_ line: String) -> ActiveState? {
        let prefix = "engine: active on "
        guard line.hasPrefix(prefix) else { return nil }
        let parts = line.dropFirst(prefix.count).split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let iface = parts.first, iface.hasPrefix("utun"), iface.utf8.count <= 16,
              iface.dropFirst(4).allSatisfy({ $0.isNumber }), iface.dropFirst(4).count >= 1 else {
            return nil
        }
        var virtualIP: String?
        for token in parts.dropFirst() where token.hasPrefix("vip=") {
            let candidate = String(token.dropFirst(4))
            var addr = in_addr()
            if !candidate.isEmpty, candidate.utf8.count <= 15,
               candidate.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 {
                virtualIP = candidate
            }
        }
        return ActiveState(interface: iface, virtualIPv4: virtualIP)
    }

    static let allowedReasons: Set<String> = ["data-session-verified", "data-session-ended",
        "unexpected-connected", "connection-ended", "deadline", "transaction-failed",
        "capture-incomplete", "control-policy-rejected", "profile-rejected",
        "credentials-rejected", "internal-error", "plan-limit", "invalid-input"]
    static let allowedEvents: Set<String> = ["RESOLVE", "WAIT", "CONNECTING", "GET_CONFIG", "AUTH_PENDING",
        "AUTH_FAILED", "CERT_VERIFY_FAIL", "TLS_VERSION_MIN", "TLS_ALERT_UNKNOWN_CA",
        "TLS_ALERT_HANDSHAKE_FAILURE", "TLS_ALERT_CERTIFICATE_EXPIRED", "TLS_ALERT_CERTIFICATE_REVOKED",
        "DYNAMIC_CHALLENGE", "TRANSPORT_ERROR", "CONNECTION_TIMEOUT", "TUN_SETUP_FAILED", "TUN_IFACE_CREATE",
        "DISCONNECTED", "RECONNECTING", "CLIENT_SETUP", "NEED_CREDS", "CONNECTED"]

    public static func perform(_ input: OpenVPNHandshakeInput, engine: URL, socket: String,
                               holdMs: Int, pingPeer: String, pingCount: Int = 3,
                               digServer: String? = nil, digName: String? = nil,
                               resolveDomains: [String] = [],
                               onActive: (@Sendable (ActiveState) -> Void)? = nil,
                               onStopHandle: (@Sendable (@escaping @Sendable () -> Void) -> Void)? = nil) async throws -> Receipt {
        guard !socket.isEmpty, socket.utf8.count <= 100,
              socket.rangeOfCharacter(from: .controlCharacters) == nil,
              (1...560_000).contains(holdMs), (1...10).contains(pingCount),
              !pingPeer.isEmpty, pingPeer.utf8.count <= 15,
              resolveDomains.count <= 32,
              resolveDomains.allSatisfy({ Self.validQueryName($0) }) else {
            throw OpenVPNEvaluationError.invalidInput
        }
        var address = in_addr()
        guard pingPeer.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else {
            throw OpenVPNEvaluationError.invalidInput
        }
        // In-tunnel DNS probe is optional but all-or-nothing.
        var digAddress = in_addr()
        if digServer != nil || digName != nil {
            guard let server = digServer, let name = digName,
                  !server.isEmpty, server.utf8.count <= 15,
                  server.withCString({ inet_pton(AF_INET, $0, &digAddress) }) == 1,
                  Self.validQueryName(name) else {
                throw OpenVPNEvaluationError.invalidInput
            }
        }
        let child = PrivateEngineProcess()
        onStopHandle?({ child.requestGracefulFinish() })
        var builtArguments = ["--data-session", "--socket", socket, "--hold-ms", String(holdMs),
                              "--ping-peer", pingPeer, "--ping-count", String(pingCount)]
        if let server = digServer, let name = digName {
            builtArguments += ["--dig-server", server, "--dig-name", name]
        }
        if !resolveDomains.isEmpty {
            builtArguments += ["--resolve-domains", resolveDomains.joined(separator: ",")]
        }
        let arguments = builtArguments
        let stderrCallback: (@Sendable (String) -> Void)?
        if let onActive {
            stderrCallback = { line in
                if let active = Self.parseActiveLine(line) {
                    onActive(active)
                }
            }
        } else {
            stderrCallback = nil
        }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            // Session hold plus transaction, authentication and capture margins.
            let result = try await Task.detached {
                try child.run(input: input.pipePayload, executable: engine, arguments: arguments,
                              timeout: TimeInterval(holdMs / 1000 + 120), onStderrLine: stderrCallback)
            }.value
            try Task.checkCancellation()
            return try receipt(result.output, status: result.exitStatus, holdMs: holdMs,
                               pingCount: pingCount, digServer: digServer, digName: digName)
        } onCancel: { child.stop(graceful: true) }
    }

    public static func validQueryName(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253 else { return false }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63
                && label.first != "-" && label.last != "-"
                && label.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0)
                    || (48...57).contains($0) || $0 == 45 }
        }
    }

    /// "a.b.c.d/p" numeric IPv4 CIDR, as echoed for pushed ctrl routes.
    static func validRouteEntry(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
              parts[0].utf8.count <= 15 else { return false }
        var address = in_addr()
        return String(parts[0]).withCString { inet_pton(AF_INET, $0, &address) } == 1
    }

    static func receipt(_ data: Data, status: Int32, holdMs: Int, pingCount: Int,
                        digServer: String? = nil, digName: String? = nil) throws -> Receipt {
        try ReceiptJSONKeys.validate(data)
        guard let value = try? JSONDecoder().decode(Receipt.self, from: data),
              value.mode == "bounded-data-session", value.engine.hasPrefix("data-engine-"),
              allowedReasons.contains(value.reason),
              value.events.count <= 32, Set(value.events).isSubset(of: allowedEvents),
              // connect() is only skipped by the pre-connect rejection paths.
              (!["profile-rejected", "credentials-rejected", "invalid-input"].contains(value.reason))
                  || !value.connectCalled,
              !value.connectCalled || !["invalid-input"].contains(value.reason),
              value.tunnelStarted == value.fdAccepted,
              value.fdAccepted == (value.interface.hasPrefix("utun") && value.phase == "active"),
              (1...560_000).contains(value.holdMs), value.holdMs == holdMs,
              value.heartbeatsSent >= 0,
              value.heartbeatsSent <= value.holdMs / 1000 + 5 else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        // Ping accounting: -1 pair when not run; bounded counts when run.
        guard !value.pingRan || (value.pingReceived >= 0 && value.pingTransmitted >= value.pingReceived
                && value.pingTransmitted <= pingCount && value.pingExitStatus >= 0),
              value.pingRan || (value.pingReceived == -1 && value.pingTransmitted == -1 && value.pingExitStatus == -1) else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        // dig accounting mirrors ping accounting; a run implies a live session
        // and, when the caller configured a probe, the echoed target must
        // match it exactly.
        if value.digRan {
            guard value.ran, value.digExitStatus >= 0, let digStatus = value.digStatus,
                  !digStatus.isEmpty, digStatus.utf8.count <= 32,
                  digStatus.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0)
                      || $0 == 45 || $0 == 95 }),
                  value.digAnswers >= 0,
                  let server = value.digServer, let name = value.digName else {
                throw OpenVPNEvaluationError.invalidReceipt
            }
            if let expectedServer = digServer, let expectedName = digName,
               !(server == expectedServer && name == expectedName) {
                throw OpenVPNEvaluationError.invalidReceipt
            }
        } else {
            guard value.digExitStatus == -1, value.digAnswers == -1,
                  value.digStatus == nil || value.digStatus?.isEmpty == true else {
                throw OpenVPNEvaluationError.invalidReceipt
            }
        }
        // Ctrl push accounting: every observed push is either sent or failed,
        // route entries are numeric CIDRs, and a push can only exist on a
        // session that ran or on the pre-transaction fail-closed rejection.
        guard value.ctrlPushesObserved >= 0, value.ctrlUpdatesSent >= 0, value.ctrlUpdatesFailed >= 0,
              value.ctrlPushesObserved == value.ctrlUpdatesSent + value.ctrlUpdatesFailed,
              value.ctrlPushesObserved <= 8, value.ctrlRoutesPushed.count <= 64,
              value.ctrlRoutesPushed.allSatisfy({ route in Self.validRouteEntry(route) }),
              value.ctrlPushesObserved == 0 || value.ran || value.reason == "control-policy-rejected",
              !value.verified || (value.ran && value.ctrlUpdatesFailed == 0
                  && value.ctrlUpdatesSent == value.ctrlPushesObserved) else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        // Session outcomes imply the transaction; failures imply no session.
        guard value.connectedInDataMode == value.ran,
              !value.disconnectSent || value.fdAccepted,
              !value.unexpectedConnected || value.ran,
              // A verified claim must carry every leg of the proof; a session
              // that merely ended still required the tunnel; transaction and
              // pre-connect failures cannot claim any session side effects.
              value.reason != "data-session-verified" || (value.ran && value.disconnectSent
                  && value.pingRan && value.pingReceived > 0),
              value.reason != "data-session-ended" || value.ran,
              !["transaction-failed", "capture-incomplete", "profile-rejected", "credentials-rejected"].contains(value.reason)
                  || (!value.fdAccepted && !value.connectedInDataMode && !value.pingRan && !value.disconnectSent) else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        // Plan bookkeeping mirrors the handshake receipt.
        guard value.planCaptureRequested, value.plan == nil || value.tunnelSetupRequested,
              value.planComplete == (value.plan?.complete ?? false),
              value.plan == nil || value.planComplete || value.reason == "capture-incomplete" else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        try value.plan?.validate()
        // Exit-status pairing with the fixed reason vocabulary.
        let paired: Bool
        switch status {
        case 0: paired = value.reason == "data-session-verified"
        case 1: paired = ["data-session-ended", "unexpected-connected", "connection-ended"].contains(value.reason)
        case 2: paired = ["deadline", "transaction-failed", "capture-incomplete", "control-policy-rejected",
                          "profile-rejected", "credentials-rejected"].contains(value.reason)
        case 3: paired = ["invalid-input", "internal-error", "plan-limit"].contains(value.reason)
        default: paired = false
        }
        guard paired else { throw OpenVPNEvaluationError.invalidReceipt }
        guard !value.verified || (value.pingReceived > 0 && value.pingReceived <= value.pingTransmitted) else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        return value
    }
}
