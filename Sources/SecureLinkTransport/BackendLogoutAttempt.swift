import Foundation
import SecureLinkCore

public actor BackendLogoutAttempt: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private var accessToken: String?
    private init(accessToken: String) { self.accessToken = accessToken }
    public nonisolated var description: String { "BackendLogoutAttempt(redacted; single attempt)" }
    public nonisolated var debugDescription: String { description }
    public nonisolated var customMirror: Mirror { Mirror(self, children: ["token": "redacted"], displayStyle: .class) }

    public struct Receipt: Encodable, Sendable {
        public let userLogoutAccepted: Bool
        public let deviceSessionMayRemain = true
        public let serverRevocationVerified = false
    }
    public static func prepare(from session: BackendAuthenticationSession, nowMilliseconds: Int64) throws -> BackendLogoutAttempt {
        try session.withAccessToken(nowMilliseconds: nowMilliseconds) { BackendLogoutAttempt(accessToken: $0) }
    }
    public func perform() async throws -> Receipt {
        guard let token = accessToken else { throw BackendSessionError.unavailable }
        accessToken = nil
        try Task.checkCancellation()
        let material = try BackendPublicMaterial.production()
        let response = try await BackendDiscovery.request(material: material, operation: .logout, payload: [:], accessToken: token)
        try Task.checkCancellation()
        return try Self.receipt(response)
    }
    static func receipt(_ data: Data) throws -> Receipt {
        struct Result: Decodable { let returnCode: Int }
        guard let result = try? JSONDecoder().decode(Result.self, from: data) else { throw BackendDiscoveryError.invalidResponse }
        return Receipt(userLogoutAccepted: result.returnCode == 1)
    }
}
