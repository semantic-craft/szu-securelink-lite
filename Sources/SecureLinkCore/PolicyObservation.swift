import Foundation

public struct PolicyObservation: Equatable, Sendable {
    public enum EndpointCheck: String, Sendable { case unknown, requested, running, healthy, needsAttention, notRequired, failed }
    public private(set) var endpointCheck: EndpointCheck = .unknown
    public private(set) var requiresReauthentication = false
    public init() {}
    public mutating func receive(_ message: Message) {
        switch message.command {
        case 21:
            guard let root = try? JSONDecoder().decode(AgentReply.self, from: message.payload),
                  root.returnCode == nil || root.returnCode == 1 else { return }
            if root.content.value.type == 2 { endpointCheck = .requested }
            if root.content.value.type == 3, root.content.value.clientMessage?.value.needTwoFactor == true {
                requiresReauthentication = true
            }
        case 20:
            guard let root = try? JSONDecoder().decode(CheckReply.self, from: message.payload) else { endpointCheck = .unknown; return }
            guard root.returnCode == nil || root.returnCode == 1 else { endpointCheck = .failed; return }
            guard let content = root.content?.value else { endpointCheck = .unknown; return }
            if content.enable == 0 { endpointCheck = .notRequired; return }
            if let enable = content.enable, enable != 1 { endpointCheck = .unknown; return }
            switch content.checkStatus {
            case 0: endpointCheck = .running
            case 1, 2:
                endpointCheck = content.healthStatus == 0 ? .healthy : .needsAttention
            default: endpointCheck = .unknown
            }
        default: break
        }
    }
    private struct AgentReply: Decodable {
        let returnCode: Int?
        let content: JSONContent<Content>
        struct Content: Decodable {
            let type: Int
            let clientMessage: JSONContent<ClientMessage>?
        }
        struct ClientMessage: Decodable { let needTwoFactor: Bool? }
    }
    private struct CheckReply: Decodable {
        let returnCode: Int?
        let content: JSONContent<Content>?
        struct Content: Decodable { let enable: Int?; let checkStatus: Int?; let healthStatus: Int? }
        enum CodingKeys: String, CodingKey { case returnCode, content }
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            returnCode = values.contains(.returnCode) ? try values.decode(Int.self, forKey: .returnCode) : nil
            // Service errors may contain plain text, not a check result.
            if let returnCode, returnCode != 1 { content = nil }
            else { content = try values.decodeIfPresent(JSONContent<Content>.self, forKey: .content) }
        }
    }
}

/// The official transport parses JSON-encoded objects inside the envelope.
/// Decode one object layer at each known field; do not coerce scalar types.
private struct JSONContent<Value: Decodable>: Decodable {
    let value: Value
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let text = try? container.decode(String.self) {
            value = try JSONDecoder().decode(Value.self, from: Data(text.utf8))
        } else { value = try container.decode(Value.self) }
    }
}
