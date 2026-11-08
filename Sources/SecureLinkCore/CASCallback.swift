import Foundation

public enum CASCallbackError: Error { case noPendingLogin, expired, invalidURL, wrongOrganization, unsupportedRegistration }

public struct PendingCASCredential: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable, Sendable {
    private let token: String
    fileprivate init(token: String) { self.token = token }
    public var description: String { "PendingCASCredential(redacted; not authenticated)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["credential": "redacted"], displayStyle: .struct) }
    public func withBearerToken<Result>(_ use: (String) throws -> Result) rethrows -> Result {
        try use(token)
    }
    func connectionRequest(creditFlag: Int) throws -> Message {
        Message(command: 11, payload: try JSONSerialization.data(withJSONObject: [
            "authToken": token, "identify": "szu", "creditType": creditFlag == 1 ? 1 : 0
        ]))
    }
    public func preAuthenticationRequest() throws -> Message {
        Message(command: 10, payload: try JSONSerialization.data(withJSONObject: ["authToken": token, "identify": "szu", "version": "3.11.1"]))
    }
}

/// Local intent/expiry checks only. The vendor service must still validate the token;
/// this does not establish cryptographic binding to the browser login session.
public struct CASCallbackGate {
    private var deadline: Date?
    public init() {}
    public mutating func begin(now: Date = Date()) { deadline = now.addingTimeInterval(300) }
    public mutating func cancel() { deadline = nil }
    public mutating func consume(_ url: URL, now: Date = Date()) throws -> PendingCASCredential {
        guard let deadline else { throw CASCallbackError.noPendingLogin }
        guard now < deadline else { self.deadline = nil; throw CASCallbackError.expired }
        guard url.absoluteString.utf8.count <= 32768,
              let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              parts.scheme == "securelink", parts.host == "sso_login",
              parts.path.isEmpty || parts.path == "/",
              parts.user == nil, parts.password == nil, parts.port == nil, parts.fragment == nil,
              let items = parts.queryItems else { throw CASCallbackError.invalidURL }
        let names = items.map(\.name)
        let allowed: Set<String> = ["authToken", "projectLabel", "username", "selfRegistration", "selfRegistrationKey"]
        guard names.count == Set(names).count, Set(names).isSubset(of: allowed),
              items.allSatisfy({ $0.value != nil }) else { throw CASCallbackError.invalidURL }
        let query = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value!) })
        guard query["projectLabel"] == "szu" else { throw CASCallbackError.wrongOrganization }
        guard query["selfRegistration"] == nil || query["selfRegistration"] == "0" else { throw CASCallbackError.unsupportedRegistration }
        guard let token = query["authToken"], !token.isEmpty, token.utf8.count <= 16384,
              token.rangeOfCharacter(from: .controlCharacters) == nil else { throw CASCallbackError.invalidURL }
        self.deadline = nil
        return PendingCASCredential(token: token)
    }
}
