import Foundation

public enum NativeSettingsError: Error { case invalidValue }

/// Values must come from the installed vendor's verified distribution, never from
/// a callback URL or a saved user password. This object intentionally has no Codable conformance.
public struct NativeSettings: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    private let certificateID: String
    private let certificateKey: String
    private let publicKey: String
    private let pid: Int32
    private let logPath: String
    public var description: String { "NativeSettings(szu; vendor material redacted)" }
    public var debugDescription: String { description }

    public init(certificateID: String, certificateKey: String, publicKey: String, pid: Int32, logPath: String) throws {
        guard !certificateID.isEmpty, certificateID.utf8.count <= 256,
              !certificateKey.isEmpty, certificateKey.utf8.count <= 8192,
              publicKey.hasPrefix("-----BEGIN PUBLIC KEY-----"), publicKey.utf8.count <= 8192,
              pid > 0, logPath.hasPrefix("/"), logPath.utf8.count <= 4096,
              [certificateID, certificateKey, logPath].allSatisfy({ $0.rangeOfCharacter(from: .controlCharacters) == nil }) else {
            throw NativeSettingsError.invalidValue
        }
        self.certificateID = certificateID
        self.certificateKey = certificateKey
        self.publicKey = publicKey
        self.pid = pid
        self.logPath = logPath
    }

    public func message(identity: AuthenticatedIdentity? = nil, autoReconnect: Bool = true) throws -> Message {
        let fields: [String: Any] = [
            "identify": "szu", "authConfigId": identity?.authConfigId as Any? ?? NSNull(), "username": identity?.username ?? "", "password": "",
            "dot1PreAuthType": 0, "autoAdjustTime": 1, "guiLogPath": logPath,
            "autoReconnect": autoReconnect ? 1 : 0, "locale": "zh_CN", "apiVersion": "5.18.0.0",
            "version": "3.11.1", "pid": pid, "publishType": 0,
            "sheetaApiUrl": "https://sheetaapi.wangsu.com",
            "sheetaApiCertId": certificateID, "sheetaApiCertKey": certificateKey,
            "sheetaApiPublicKey": publicKey
        ]
        return Message(command: 5, payload: try JSONSerialization.data(withJSONObject: fields))
    }
}

public enum NativeBootstrapError: Error { case unexpectedResponse, rejected, malformed, timedOut }
public struct NativeBootstrap {
    public enum State: Equatable { case idle, awaitingPreConfig, settingsIssued, failed }
    public private(set) var state: State = .idle
    private var startedAt: Duration?
    private var settings: NativeSettings?
    public init(settings: NativeSettings) { self.settings = settings }
    public mutating func begin(elapsed: Duration) throws -> Message {
        guard state == .idle else { throw NativeBootstrapError.unexpectedResponse }
        state = .awaitingPreConfig
        startedAt = elapsed
        return Message(command: 35, payload: try JSONSerialization.data(withJSONObject: ["type": 0, "gmtls": 0, "org": "szu", "version": "3.11.1"]))
    }
    public mutating func advance(elapsed: Duration) throws {
        guard state == .awaitingPreConfig, let startedAt else { return }
        if elapsed < startedAt || elapsed - startedAt >= .seconds(20) {
            state = .failed; settings = nil
            throw NativeBootstrapError.timedOut
        }
    }
    public mutating func receive(_ message: Message, elapsed: Duration) throws -> Message? {
        try advance(elapsed: elapsed)
        guard message.command == 35 else { return nil }
        guard state == .awaitingPreConfig, let settings else { throw NativeBootstrapError.unexpectedResponse }
        self.settings = nil
        guard let reply = try? JSONDecoder().decode(Reply.self, from: message.payload) else {
            state = .failed; throw NativeBootstrapError.malformed
        }
        guard reply.returnCode == 1 else { state = .failed; throw NativeBootstrapError.rejected }
        let request = try settings.message()
        // Command 5 has no replay contract in the official dispatcher. This is
        // only ordered issuance, not acknowledgement of settings or policy readiness.
        state = .settingsIssued
        return request
    }
    private struct Reply: Decodable { let returnCode: Int }
}
