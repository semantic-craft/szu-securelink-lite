import Foundation

public struct OpenVPNHandshakeInput: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    fileprivate let data: Data
    fileprivate let vendorConfusion: Bool
    fileprivate let activeShapingNotExercised: Bool
    fileprivate let gmsslRenegotiationNotExercised: Bool
    init(configuration: String, username: String, password: String, peerInfo: [String: String], vendorConfusion: Bool = false,
         activeShapingNotExercised: Bool = false, gmsslRenegotiationNotExercised: Bool = false) throws {
        self.vendorConfusion = vendorConfusion
        self.activeShapingNotExercised = activeShapingNotExercised
        self.gmsslRenegotiationNotExercised = gmsslRenegotiationNotExercised
        let allowed: Set<String> = ["UV_CODE", "UV_SL_SERVERTYPE", "UV_EXTRA_PARAM_3", "UV_EXTRA_PARAM_4", "UV_EXTRA_PARAM_5"]
        guard !configuration.isEmpty, !username.isEmpty, !password.isEmpty,
              Set(peerInfo.keys).isSubset(of: allowed),
              peerInfo.values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 8192 && $0.rangeOfCharacter(from: .controlCharacters) == nil }) else {
            throw OpenVPNEvaluationError.invalidInput
        }
        data = try JSONSerialization.data(withJSONObject: ["config": configuration, "username": username,
                                                          "password": password, "peerInfo": peerInfo, "vendorConfusion": vendorConfusion,
                                                          "activeShapingNotExercised": activeShapingNotExercised,
                                                          "gmsslRenegotiationNotExercised": gmsslRenegotiationNotExercised])
        guard data.count <= 2 * 1024 * 1024 else { throw OpenVPNEvaluationError.invalidInput }
    }
    public var description: String { "OpenVPNHandshakeInput(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["input": "redacted"]) }
    /// In-memory pipe payload for sibling drivers (the data session); never logged.
    var pipePayload: Data { data }
}

public enum OpenVPNHandshake {
    public struct Receipt: Codable, Sendable {
        public let planCaptureRequested: Bool?
        public let planComplete: Bool?
        public let plan: CapturedTunnelPlan?
        public let mode: String
        public let reason: String
        public let connectCalled: Bool
        public let socketObserved: Bool
        public let tunnelSetupRequested: Bool
        public let tunnelStarted: Bool
        public let connected: Bool
        public let routesChanged: Bool
        public let dnsChanged: Bool
        public let deadlineReached: Bool
        public let unexpectedConnected: Bool
        public let eventsDropped: Bool
        public let events: [String]
        public let vendorConfusion: Bool
        public let clientCertificateSuppressed: Bool
        public let activeShapingNotExercised: Bool
        public let gmsslRenegotiationNotExercised: Bool
    }
    public static func perform(_ input: OpenVPNHandshakeInput, executable: URL, allowNetwork: Bool = false, capturePlan: Bool = false) async throws -> Receipt {
        let child = PrivateEngineProcess()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let result = try await Task.detached {
                try child.run(input: input.data, executable: executable,
                              arguments: [allowNetwork ? "--allow-handshake" : "--validate-input"] + (capturePlan ? ["--capture-plan"] : []), timeout: 32)
            }.value
            try Task.checkCancellation()
            let value = try receipt(result.output, status: result.exitStatus, allowNetwork: allowNetwork, capturePlan: capturePlan)
            if value.reason == "input-validated" || value.connectCalled {
                guard value.vendorConfusion == input.vendorConfusion,
                      value.activeShapingNotExercised == input.activeShapingNotExercised,
                      value.gmsslRenegotiationNotExercised == input.gmsslRenegotiationNotExercised else { throw OpenVPNEvaluationError.invalidReceipt }
            }
            return value
        } onCancel: { child.stop() }
    }
    static func receipt(_ data: Data, status: Int32, allowNetwork: Bool, capturePlan: Bool = false) throws -> Receipt {
        try ReceiptJSONKeys.validate(data)
        let allowedEvents: Set<String> = ["RESOLVE", "WAIT", "CONNECTING", "GET_CONFIG", "AUTH_PENDING", "AUTH_FAILED",
            "CERT_VERIFY_FAIL", "TLS_VERSION_MIN", "TLS_ALERT_UNKNOWN_CA", "TLS_ALERT_HANDSHAKE_FAILURE",
            "TLS_ALERT_CERTIFICATE_EXPIRED", "TLS_ALERT_CERTIFICATE_REVOKED", "DYNAMIC_CHALLENGE",
            "TRANSPORT_ERROR", "CONNECTION_TIMEOUT", "TUN_SETUP_FAILED", "TUN_IFACE_CREATE",
            "DISCONNECTED", "RECONNECTING", "CLIENT_SETUP", "NEED_CREDS"]
        let allowedReasons: Set<String> = ["input-validated", "profile-rejected", "credentials-rejected", "deadline",
            "tunnel-boundary", "connection-ended", "unexpected-connected", "invalid-input", "internal-error", "plan-limit", "control-policy-rejected"]
        guard let value = try? JSONDecoder().decode(Receipt.self, from: data),
              value.mode == "bounded-handshake-probe", allowedReasons.contains(value.reason),
              !value.tunnelStarted, !value.connected, !value.routesChanged, !value.dnsChanged,
              value.vendorConfusion == value.clientCertificateSuppressed,
              value.events.count <= 32, Set(value.events).isSubset(of: allowedEvents),
              allowNetwork || (!value.connectCalled && !value.socketObserved && !value.tunnelSetupRequested && !value.unexpectedConnected),
              !value.socketObserved || value.connectCalled,
              !value.tunnelSetupRequested || value.connectCalled,
              !value.unexpectedConnected || (value.connectCalled && value.reason == "unexpected-connected"),
              value.reason != "tunnel-boundary" || value.tunnelSetupRequested,
              value.reason != "control-policy-rejected" || (value.connectCalled && value.planComplete != true),
              (status == 0 && value.reason == "input-validated" && !value.connectCalled)
                || (status == 2 && ["profile-rejected", "credentials-rejected", "deadline", "tunnel-boundary", "connection-ended", "unexpected-connected", "control-policy-rejected"].contains(value.reason))
                || (status == 3 && ["invalid-input", "internal-error", "plan-limit"].contains(value.reason)) else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        guard (value.planCaptureRequested ?? false) == capturePlan,
              capturePlan || value.plan == nil,
              (value.planComplete ?? false) == (value.plan?.complete ?? false),
              value.plan == nil || value.tunnelSetupRequested,
              value.plan?.complete != true || value.reason == "tunnel-boundary" else {
            throw OpenVPNEvaluationError.invalidReceipt
        }
        try value.plan?.validate()
        return value
    }
}
