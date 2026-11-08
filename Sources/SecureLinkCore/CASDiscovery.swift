import Foundation

public enum CASDiscoveryError: Error { case rejected, malformed, unsupportedProvider, unsafeURL, unexpectedResponse }
public enum CASDiscoveryStep {
    case ignored
    case request(Message)
    case ready(URL)
}
public struct CASDiscovery {
    private let configID: String
    private let urlID: String
    private var phase = 0
    public init(identifier: String = UUID().uuidString) {
        configID = identifier + "-config"
        urlID = identifier + "-url"
    }
    public mutating func begin() throws -> Message {
        guard phase == 0 else { throw CASDiscoveryError.unexpectedResponse }
        phase = 1
        return try request(id: configID, api: "getAuthConfig", body: ["org": "szu"])
    }
    public mutating func receive(_ message: Message) throws -> CASDiscoveryStep {
        guard message.command == 28 else { return .ignored }
        let reply = try JSONDecoder().decode(Reply.self, from: message.payload)
        guard reply.id == configID || reply.id == urlID else { return .ignored }
        guard reply.returnCode == 1, let content = reply.content else {
            phase = 3; throw CASDiscoveryError.rejected
        }
        if phase == 1, reply.id == configID {
            let candidates = (content.list ?? []).filter { $0.reportType == 9 && !$0.name.isEmpty && $0.name.utf8.count <= 256 }
            guard candidates.count == 1 else { phase = 3; throw CASDiscoveryError.unsupportedProvider }
            phase = 2
            return .request(try request(id: urlID, api: "getAuthUrl", body: ["org": "szu", "name": candidates[0].name]))
        }
        if phase == 2, reply.id == urlID {
            phase = 3
            guard content.action == 2, let raw = content.loginUrl else { throw CASDiscoveryError.malformed }
            return .ready(try Self.validateLoginURL(raw))
        }
        throw CASDiscoveryError.unexpectedResponse
    }
    public static func validateLoginURL(_ raw: String) throws -> URL {
        guard raw.utf8.count <= 16384,
              let parts = URLComponents(string: raw), parts.scheme == "https",
              parts.host == "authserver.szu.edu.cn", parts.path == "/authserver/login",
              parts.user == nil, parts.password == nil, parts.port == nil,
              parts.fragment == nil, let query = parts.queryItems,
              query.count == 1, query[0].name == "service", let service = query[0].value,
              let callback = URLComponents(string: service), callback.scheme == "https",
              callback.host == "securelinksso.wangsu.com", callback.user == nil,
              callback.password == nil, callback.port == nil, callback.fragment == nil,
              let url = parts.url else { throw CASDiscoveryError.unsafeURL }
        return url
    }
    private func request(id: String, api: String, body: [String: String]) throws -> Message {
        let payload: [String: Any] = ["id": id, "version": "3.11.1", "path": "/authApi/sso/authConfig/\(api)?locale=zh_CN", "header": ["apiVersion": "5.18.0.0"], "body": body, "tokenType": 0, "method": "POST"]
        return Message(command: 28, payload: try JSONSerialization.data(withJSONObject: payload))
    }
    private struct Reply: Decodable {
        let id: String
        let returnCode: Int
        let content: Content?
    }
    private struct Content: Decodable {
        let list: [Provider]?
        let action: Int?
        let loginUrl: String?
    }
    private struct Provider: Decodable { let name: String; let reportType: Int? }
}
