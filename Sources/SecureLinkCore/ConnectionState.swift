public enum TunnelState: String, Codable, Sendable {
    case unknown, disconnected, authenticating, configuring, connected, reconnecting, expired
    public init(vendorState: String) {
        switch vendorState {
        case "CONNECTED": self = .connected
        case "AUTH": self = .authenticating
        case "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES": self = .configuring
        case "DISCONNECTED", "EXITING": self = .disconnected
        case "RECONNECTING": self = .reconnecting
        case "EXPIRED": self = .expired
        default: self = .unknown
        }
    }
}
public struct ConnectionState: Sendable {
    public var transportConnected = false
    public var authenticated = false
    public private(set) var tunnel: TunnelState = .unknown
    public init() {}
    public mutating func receiveTunnelState(_ vendorState: String) { tunnel = TunnelState(vendorState: vendorState) }
    public mutating func transportClosed() {
        transportConnected = false; authenticated = false; tunnel = .unknown
    }
    public var canAttemptCampusResource: Bool { transportConnected && authenticated && tunnel == .connected }
}
