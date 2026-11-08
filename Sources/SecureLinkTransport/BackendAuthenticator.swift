import Foundation
import SecureLinkCore

public struct BackendAuthenticationReply: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let response: Data
    init(response: Data) { self.response = response }
    public var description: String { "BackendAuthenticationReply(redacted; not yet accepted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["response": "redacted"], displayStyle: .struct) }

    /// The caller supplies local epoch milliseconds. Server clock adjustment is not implemented here.
    public func apply(to session: BackendAuthenticationSession, nowMilliseconds: Int64) {
        session.receive(response, nowMilliseconds: nowMilliseconds)
    }
}

public enum BackendAuthenticator {
    public static func authenticate(credential: PendingCASCredential, identityDirectory: URL) async throws -> BackendAuthenticationReply {
        try Task.checkCancellation()
        let material = try BackendPublicMaterial.production()
        let profile = try NativeDeviceProfile.collect(directory: identityDirectory)
        let payload = loginPayload(profile: profile, emptyPasswordEnvelope: material.emptyPasswordEnvelope)
        let response = try await BackendDiscovery.request(material: material, operation: .ssoLogin, payload: payload, credential: credential)
        try Task.checkCancellation()
        return BackendAuthenticationReply(response: response)
    }
    static func loginPayload(profile: NativeDeviceProfile, emptyPasswordEnvelope: String) -> [String: Any] {
        var payload = profile.loginFields
        payload["org"] = "szu"
        payload["password"] = emptyPasswordEnvelope
        return payload
    }
}
