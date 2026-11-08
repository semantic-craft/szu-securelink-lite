import Foundation

/// A bounded, single-request diagnostic. This never authorizes a tunnel or skips
/// policy initialization. Numeric szu completion flags are covered by a live trial.
public final class CASPreAuthentication {
    public enum State: Equatable, Sendable {
        case idle, awaitingReply, deviceRejected, informationRequired
        case responseValidated(creditFlag: Int)
        case serviceRejected, unsupportedResponse, timedOut, cancelled
    }
    public private(set) var state: State = .idle
    public private(set) var identity: AuthenticatedIdentity?
    private var startedAt: Duration?
    public init() {}

    public func begin(_ credential: PendingCASCredential, elapsed: Duration) throws -> Message? {
        guard state == .idle else { return nil }
        let request = try credential.preAuthenticationRequest()
        startedAt = elapsed
        state = .awaitingReply
        return request
    }

    public func advance(elapsed: Duration) {
        guard state == .awaitingReply, let startedAt else { return }
        if elapsed < startedAt || elapsed - startedAt >= .seconds(15) {
            state = .timedOut
            self.startedAt = nil
        }
    }

    public func cancel() {
        guard state == .idle || state == .awaitingReply else { return }
        state = .cancelled
        startedAt = nil
    }

    public func receive(_ message: Message, elapsed: Duration) {
        advance(elapsed: elapsed)
        guard state == .awaitingReply, message.command == 10 else { return }
        defer { startedAt = nil }
        guard let reply = try? JSONDecoder().decode(Reply.self, from: message.payload) else {
            state = .unsupportedResponse
            return
        }
        guard reply.returnCode == nil || reply.returnCode == 1 else {
            state = .serviceRejected
            return
        }
        guard let content = reply.content else { state = .unsupportedResponse; return }
        (state, identity) = content.decision
    }

    private struct Reply: Decodable {
        let returnCode: Int?
        let content: CASIdentityPolicy?
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: Keys.self)
            returnCode = values.contains(.returnCode) ? try values.decode(Int.self, forKey: .returnCode) : nil
            content = values.contains(.content) ? try values.decode(CASIdentityPolicy.self, forKey: .content) : try CASIdentityPolicy(from: decoder)
        }
        enum Keys: String, CodingKey { case returnCode, content }
    }
}

public struct AuthenticatedIdentity: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let username: String
    public let authConfigId: Int?
    public var description: String { "AuthenticatedIdentity(redacted)" }
    public var debugDescription: String { description }
    init(username: String, authConfigId: Int?) {
        self.username = username
        self.authConfigId = authConfigId
    }
}
