import Foundation

public enum BackendSessionError: Error {
    case unavailable, handshakeExpired, handshakeSessionUnavailable, handshakeMetadataUnavailable
}

/// In-memory HTTP preauthentication state. Ready does not authorize a tunnel or prove endpoint health.
/// Callers supply service-aligned epoch milliseconds; transport owns the request timeout and does not replay CAS tokens.
public final class BackendAuthenticationSession: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public enum State: String, Sendable {
        case idle, awaitingResponse, ready, requiresSecondFactor, deviceRejected, informationRequired
        case rejected, transportFailed, unsupportedResponse, accessExpired, expired, cancelled
    }
    public private(set) var state: State = .idle
    public private(set) var identity: AuthenticatedIdentity?
    public private(set) var creditFlag: Int?
    /// Fixed field names and classifications only; retained across invalidation for a safe final receipt.
    public private(set) var handshakeMetadataShape: [String: String] = [:]
    private var tokens: Tokens?
    private var terminalUserID: Int64?
    private var authenticationType: Int?
    private var lastNow: Int64?
    public init() {}
    public var description: String { "BackendAuthenticationSession(\(state.rawValue); redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["state": state.rawValue], displayStyle: .class) }

    @discardableResult public func begin() -> Bool {
        guard state == .idle else { return false }
        state = .awaitingResponse
        return true
    }
    public func receive(_ response: Data, nowMilliseconds: Int64) {
        guard state == .awaitingResponse else { return }
        guard response.count <= 2 * 1024 * 1024, nowMilliseconds > 0 else {
            invalidate(.unsupportedResponse); return
        }
        handshakeMetadataShape = (try? JSONDecoder().decode(MetadataShape.self, from: response).fields) ?? [:]
        guard let reply = try? JSONDecoder().decode(Reply.self, from: response) else {
            invalidate(.unsupportedResponse); return
        }
        if reply.returnCode == 2041 {
            guard let token = reply.content?.tempToken, Self.validToken(token) else { invalidate(.unsupportedResponse); return }
            invalidate(.requiresSecondFactor); return
        }
        guard reply.returnCode == 1 else { invalidate(.rejected); return }
        guard let content = reply.content else { invalidate(.unsupportedResponse); return }
        let (policyState, identity) = content.policy.decision
        if policyState == .deviceRejected { invalidate(.deviceRejected); return }
        if policyState == .informationRequired { invalidate(.informationRequired); return }
        if let challenge = content.twoFactorToken, !challenge.isEmpty {
            invalidate(Self.validToken(challenge) ? .requiresSecondFactor : .unsupportedResponse); return
        }
        guard case let .responseValidated(creditFlag) = policyState, let identity,
              let tokens = content.loginMessage, tokens.isWellFormed else {
            invalidate(.unsupportedResponse); return
        }
        self.tokens = tokens
        self.identity = identity
        self.creditFlag = creditFlag
        terminalUserID = content.terminalUserId
        authenticationType = content.authTypeInternal
        lastNow = nowMilliseconds
        state = .ready
        advance(nowMilliseconds: nowMilliseconds)
    }
    public func advance(nowMilliseconds: Int64) {
        guard state == .ready || state == .accessExpired, let tokens else { return }
        guard let lastNow, nowMilliseconds >= lastNow else { invalidate(.expired); return }
        self.lastNow = nowMilliseconds
        if nowMilliseconds >= tokens.refreshTokenExpire && nowMilliseconds >= tokens.accessTokenExpire { invalidate(.expired) }
        else if nowMilliseconds >= tokens.accessTokenExpire { state = .accessExpired }
    }
    public func cancel() { invalidate(.cancelled) }
    public func transportFailed() {
        guard state == .awaitingResponse else { return }
        invalidate(.transportFailed)
    }
    public func withAccessToken<Result>(nowMilliseconds: Int64, _ use: (String) throws -> Result) throws -> Result {
        advance(nowMilliseconds: nowMilliseconds)
        guard state == .ready, let tokens else { throw BackendSessionError.unavailable }
        return try use(tokens.accessToken)
    }
    public func withRefreshToken<Result>(nowMilliseconds: Int64, _ use: (String) throws -> Result) throws -> Result {
        advance(nowMilliseconds: nowMilliseconds)
        guard state == .ready || state == .accessExpired, let tokens,
              nowMilliseconds < tokens.refreshTokenExpire else { throw BackendSessionError.unavailable }
        return try use(tokens.refreshToken)
    }
    public func withHandshakeIdentity<Result>(nowMilliseconds: Int64, _ use: (String, Int64, Int) throws -> Result) throws -> Result {
        advance(nowMilliseconds: nowMilliseconds)
        guard state != .accessExpired && state != .expired else { throw BackendSessionError.handshakeExpired }
        guard state == .ready, let identity else { throw BackendSessionError.handshakeSessionUnavailable }
        guard let terminalUserID, terminalUserID > 0, let authenticationType else {
            throw BackendSessionError.handshakeMetadataUnavailable
        }
        return try use(identity.username, terminalUserID, authenticationType)
    }
    private func invalidate(_ state: State) {
        self.state = state
        identity = nil; creditFlag = nil; tokens = nil; lastNow = nil; terminalUserID = nil; authenticationType = nil
    }
    private static func validToken(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 16384 && value.rangeOfCharacter(from: .controlCharacters) == nil
    }
    private struct MetadataShape: Decodable {
        enum Key: String, CodingKey { case content, loginMessage, terminalUserId, authTypeInternal }
        let fields: [String: String]
        init(from decoder: Decoder) throws {
            let root = try decoder.container(keyedBy: Key.self)
            let content = try? root.nestedContainer(keyedBy: Key.self, forKey: .content)
            let nested = try? content?.nestedContainer(keyedBy: Key.self, forKey: .loginMessage)
            var fields: [String: String] = [:]
            for (prefix, container) in [("content", content), ("loginMessage", nested)] {
                for key in [Key.terminalUserId, .authTypeInternal] {
                    let name = prefix + "." + key.rawValue
                    let integer = try? container?.decode(Int64.self, forKey: key)
                    let type: String
                    if container?.contains(key) != true { type = "missing" }
                    else if (try? container?.decodeNil(forKey: key)) == true { type = "null" }
                    else if integer != nil { type = "integer" }
                    else if (try? container?.decode(String.self, forKey: key)) != nil { type = "string" }
                    else { type = "other" }
                    fields[name + ".type"] = type
                    fields[name + ".parsed"] = integer != nil ? "true" : "false"
                    fields[name + ".positive"] = (integer ?? 0) > 0 ? "true" : "false"
                }
            }
            self.fields = fields
        }
    }
    private struct Reply: Decodable {
        let returnCode: Int
        let content: Content?
    }
    private struct Content: Decodable {
        let policy: CASIdentityPolicy
        let twoFactorToken: String?
        let tempToken: String?
        let loginMessage: Tokens?
        let terminalUserId: Int64?
        let authTypeInternal: Int?
        enum CodingKeys: String, CodingKey { case twoFactorToken, tempToken, loginMessage, terminalUserId, authTypeInternal }
        init(from decoder: Decoder) throws {
            policy = try CASIdentityPolicy(from: decoder)
            let values = try decoder.container(keyedBy: CodingKeys.self)
            twoFactorToken = try values.decodeIfPresent(String.self, forKey: .twoFactorToken)
            tempToken = try values.decodeIfPresent(String.self, forKey: .tempToken)
            loginMessage = try? values.decodeIfPresent(Tokens.self, forKey: .loginMessage)
            terminalUserId = try? values.decodeIfPresent(Int64.self, forKey: .terminalUserId)
            // ResetWithResp unmarshals into a fresh Go authApiLoginResp (AuthType int).
            // An absent field therefore retains zero. Present null or invalid types remain
            // unavailable here; the diagnostic shape still reports the original missing field.
            authTypeInternal = values.contains(.authTypeInternal)
                ? (try? values.decode(Int.self, forKey: .authTypeInternal)) : 0
        }
    }
    private struct Tokens: Decodable {
        let accessToken: String
        let accessTokenExpire: Int64
        let refreshToken: String
        let refreshTokenExpire: Int64
        let inUsed: [String: String]?
        var isWellFormed: Bool {
            validToken(accessToken) && validToken(refreshToken) && accessTokenExpire > 0 &&
                refreshTokenExpire > 0 && (inUsed?.count ?? 0) <= 64 &&
                (inUsed ?? [:]).allSatisfy { !$0.key.isEmpty && $0.key.utf8.count <= 256 && $0.value.utf8.count <= 16384 }
        }
    }
}
