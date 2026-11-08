import Foundation

/// Single-use CAS continuation. Transport must deliver each output in order, stopping on write failure.
public final class CASConnectionFlow {
    public enum State: Equatable, Sendable {
        case idle, preAuthenticating, initializingPolicy, initialized
        case deviceRejected, informationRequired, serviceRejected, unsupportedResponse, timedOut, cancelled
    }
    public private(set) var state: State = .idle
    public var identity: AuthenticatedIdentity? { preAuthentication.identity }
    public private(set) var policy: PolicyInitialization?
    public var isTerminalFailure: Bool {
        [.deviceRejected, .informationRequired, .serviceRejected, .unsupportedResponse, .timedOut, .cancelled].contains(state)
    }
    private let settings: NativeSettings
    private var credential: PendingCASCredential?
    private let preAuthentication = CASPreAuthentication()
    public init(settings: NativeSettings) { self.settings = settings }
    public func begin(_ credential: PendingCASCredential, elapsed: Duration) throws -> Message? {
        guard state == .idle else { return nil }
        let request = try preAuthentication.begin(credential, elapsed: elapsed)
        self.credential = credential; state = .preAuthenticating
        return request
    }
    public func advance(elapsed: Duration) {
        if state == .preAuthenticating {
            preAuthentication.advance(elapsed: elapsed)
            if preAuthentication.state == .timedOut { stop(.timedOut) }
        }
        policy?.advance(elapsed: elapsed); updatePolicyState()
    }
    public func cancel() {
        preAuthentication.cancel(); policy?.cancel(); stop(.cancelled)
    }
    public func didSend(command: UInt32, elapsed: Duration) {
        guard !isTerminalFailure else { return }
        policy?.didSend(command: command, elapsed: elapsed); updatePolicyState()
    }
    public func receive(_ message: Message, elapsed: Duration) throws -> [Message] {
        advance(elapsed: elapsed)
        if state == .preAuthenticating, message.command == 10 {
            preAuthentication.receive(message, elapsed: elapsed)
            switch preAuthentication.state {
            case .responseValidated(let flag):
                guard let credential, let identity else { stop(.unsupportedResponse); return [] }
                let connect = try credential.connectionRequest(creditFlag: flag)
                self.credential = nil
                let policy = PolicyInitialization(identity: identity, settings: settings)
                self.policy = policy; state = .initializingPolicy
                return [connect, policy.begin(elapsed: elapsed)!]
            case .deviceRejected: stop(.deviceRejected)
            case .informationRequired: stop(.informationRequired)
            case .serviceRejected: stop(.serviceRejected)
            case .timedOut: stop(.timedOut)
            default: stop(.unsupportedResponse)
            }
        } else if state == .initializingPolicy || state == .initialized, let policy {
            let output = try policy.receive(message, elapsed: elapsed)
            updatePolicyState(); return output
        }
        return []
    }
    private func updatePolicyState() {
        guard !isTerminalFailure, let policy else { return }
        switch policy.state {
        case .initialized: state = .initialized
        case .serviceRejected: stop(.serviceRejected)
        case .unsupportedResponse: stop(.unsupportedResponse)
        case .timedOut: stop(.timedOut)
        case .cancelled: stop(.cancelled)
        default: break
        }
    }
    private func stop(_ terminal: State) { credential = nil; state = terminal }
}
