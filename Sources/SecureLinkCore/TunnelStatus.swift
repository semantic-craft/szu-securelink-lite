import Foundation

public enum TunnelStatus: String, Sendable {
    case connected, disconnected, connecting, disconnecting, unavailable, unknown
    public static func decode(_ data: Data) -> Self {
        guard let root = try? JSONDecoder().decode(StatusReply.self, from: data),
              root.returnCode == nil || root.returnCode == 1 else { return .unknown }
        return Self(rawValue: root.content.state.lowercased()) ?? .unknown
    }
    private struct StatusReply: Decodable {
        let returnCode: Int?
        let content: Content
        struct Content: Decodable { let state: String }
    }
}
