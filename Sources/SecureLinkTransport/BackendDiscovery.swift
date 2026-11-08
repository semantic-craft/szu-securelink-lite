import Foundation
import CryptoKit
import Security
import SecureLinkCore

public enum BackendDiscoveryError: Error { case invalidMaterial, invalidRequest, invalidResponse, rejected, tooLarge, transport }

/// Bounded control-plane requests. Discovery alone does not authenticate an account or authorize a tunnel.
public enum BackendDiscovery {
    static let maximumResponse = 2 * 1024 * 1024
    public struct Receipt: Encodable {
        public let result = "organization-preconfig-accepted"
        public let vendorArtifactRequired = false
        public let officialIPCUsed = false
        public let credentialUsed = false
        public let campusValidated = false
        public let uninstallReady = false
        public let fieldTypes: [String: String]
    }
    static func signature(certID: String, timestamp: String, nonce: String, body: String) -> String {
        let input = Data("\(certID)-\(timestamp)-\(nonce)-\(body)".utf8)
        let hex = Insecure.SHA1.hash(data: input).map { String(format: "%02x", $0) }.joined()
        return Data(hex.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").uppercased()
    }
    static func body(payload: [String: Any], key: Data, iv: Data) throws -> String {
        try body(json: JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]), key: key, iv: iv)
    }
    private static func body(json: Data, key: Data, iv: Data) throws -> String {
        try SessionCipher(key: key, iv: iv).encrypt(json).base64EncodedString()
    }
    private static func decode(response: Data, status: Int, key: Data, iv: Data) throws -> Data {
        guard response.count <= maximumResponse else { throw BackendDiscoveryError.tooLarge }
        guard status == 200 else { throw BackendDiscoveryError.rejected }
        guard let text = String(data: response, encoding: .utf8),
              let encrypted = Data(base64Encoded: text.replacingOccurrences(of: "%2B", with: "+")) else {
            throw BackendDiscoveryError.invalidResponse
        }
        do { return try SessionCipher(key: key, iv: iv).decrypt(encrypted) }
        catch { throw BackendDiscoveryError.invalidResponse }
    }
    static func receipt(response: Data, status: Int, key: Data, iv: Data) throws -> Receipt {
        try sanitizedReceipt(decode(response: response, status: status, key: key, iv: iv))
    }
    private static func sanitizedReceipt(_ decoded: Data) throws -> Receipt {
        let content = try content(decoded)
        var fields: [String: String] = [:]
        for name in ["algorithmType", "spaSwitch", "captchaCodeSwitch", "resetPasswordSwitch", "clientCert", "apiAddress"] {
            guard let value = content[name] else { continue }
            if value is NSNull { fields[name] = "null" }
            else if let number = value as? NSNumber { fields[name] = CFGetTypeID(number) == CFBooleanGetTypeID() ? "boolean" : "number" }
            else if value is String { fields[name] = "string" }
            else if value is [String: Any] { fields[name] = "object" }
            else if value is [Any] { fields[name] = "array" }
        }
        return Receipt(fieldTypes: fields)
    }
    public struct CASReceipt: Encodable {
        public let result = "cas-login-entry-discovered"
        public let vendorArtifactRequired = false
        public let officialIPCUsed = false
        public let credentialUsed = false
        public let browserOpened = false
        public let campusValidated = false
        public let uninstallReady = false
    }
    public static func run() async throws -> Receipt {
        try Task.checkCancellation()
        let material = try BackendPublicMaterial.production()
        let decoded = try await request(material: material, operation: .preconfig, payload: ["org": "szu"])
        return try sanitizedReceipt(decoded)
    }
    public static func discoverCAS() async throws -> CASReceipt {
        _ = try await loginURL()
        return CASReceipt()
    }
    public static func loginURL() async throws -> URL {
        try Task.checkCancellation()
        let material = try BackendPublicMaterial.production()
        let config = try await request(material: material, operation: .authConfig, payload: ["org": "szu"])
        let name = try providerName(config)
        let url = try await request(material: material, operation: .authURL, payload: ["org": "szu", "name": name])
        return try validateCASResponse(url)
    }
    static func content(_ decoded: Data) throws -> [String: Any] {
        guard let object = try? JSONSerialization.jsonObject(with: decoded) as? [String: Any],
              let code = object["returnCode"] as? NSNumber, CFGetTypeID(code) != CFBooleanGetTypeID(), code == 1,
              let content = object["content"] as? [String: Any] else { throw BackendDiscoveryError.rejected }
        return content
    }
    static func providerName(_ decoded: Data) throws -> String {
        let content = try content(decoded)
        guard let providers = content["list"] as? [[String: Any]] else { throw BackendDiscoveryError.invalidResponse }
        let candidates = providers.filter {
            guard let code = $0["reportType"] as? NSNumber, CFGetTypeID(code) != CFBooleanGetTypeID(), code == 9,
                  let name = $0["name"] as? String else { return false }
            return !name.isEmpty && name.utf8.count <= 256
        }
        guard candidates.count == 1, let name = candidates[0]["name"] as? String else { throw BackendDiscoveryError.rejected }
        return name
    }
    @discardableResult static func validateCASResponse(_ decoded: Data) throws -> URL {
        let content = try content(decoded)
        guard let action = content["action"] as? NSNumber, CFGetTypeID(action) != CFBooleanGetTypeID(), action == 2,
              let url = content["loginUrl"] as? String else { throw BackendDiscoveryError.rejected }
        do { return try CASDiscovery.validateLoginURL(url) }
        catch { throw BackendDiscoveryError.invalidResponse }
    }
    enum Operation {
        case preconfig, authConfig, authURL, ssoLogin, logout, networkConfig, getApplications
        var path: String {
            switch self {
            case .preconfig: return "/slAppApi/is/slapp/preConfig"
            case .authConfig: return "/authApi/sso/authConfig/getAuthConfig"
            case .authURL: return "/authApi/sso/authConfig/getAuthUrl"
            case .ssoLogin: return "/authApi/is/sso/login"
            case .logout: return "/authApi/is/logout"
            case .networkConfig: return "/networkApi/is/network/initConfig"
            case .getApplications: return "/networkApi/gcable/getApplications"
            }
        }
        var version: String {
            switch self {
            case .networkConfig: return "5.0.0.0"
            case .preconfig, .logout: return "4.25.0.0"
            default: return "5.18.0.0"
            }
        }
    }
    static func request(material: BackendPublicMaterial, operation: Operation, payload: [String: Any], credential: PendingCASCredential? = nil, accessToken: String? = nil, serverScope: String? = nil, configuration: URLSessionConfiguration? = nil) async throws -> Data {
        try Task.checkCancellation()
        var key = Data(count: 16)
        let randomStatus = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard randomStatus == errSecSuccess else { throw BackendDiscoveryError.invalidMaterial }
        defer { key.resetBytes(in: 0..<key.count) }
        let request = try preparedRequest(material: material, operation: operation, payload: payload, key: key,
                                          timestamp: String(Int64(Date().timeIntervalSince1970 * 1000)),
                                          nonce: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + "1",
                                          credential: credential, accessToken: accessToken, serverScope: serverScope)

        let configuration = configuration ?? URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil; configuration.httpShouldSetCookies = false
        configuration.urlCache = nil; configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 20; configuration.timeoutIntervalForResource = 20
        configuration.connectionProxyDictionary = [:]
        let data = try await receive(request, configuration: configuration)
        return try decode(response: data, status: 200, key: key, iv: material.iv)
    }

    static func preparedRequest(material: BackendPublicMaterial, operation: Operation, payload: [String: Any],
                                key: Data, timestamp: String, nonce: String, credential: PendingCASCredential?, accessToken: String? = nil, serverScope: String? = nil) throws -> URLRequest {
        if let serverScope {
            guard (operation == .networkConfig || operation == .getApplications),
                  BackendPublicEnvelope.validServerScope(serverScope) else {
                throw BackendDiscoveryError.invalidRequest
            }
        }
        switch operation {
        case .ssoLogin:
            guard credential != nil, accessToken == nil else { throw BackendDiscoveryError.invalidRequest }
        case .networkConfig, .getApplications:
            guard credential == nil, let accessToken, !accessToken.isEmpty else { throw BackendDiscoveryError.invalidRequest }
        case .logout:
            guard credential == nil, let accessToken, !accessToken.isEmpty, payload.isEmpty else { throw BackendDiscoveryError.invalidRequest }
        default:
            guard credential == nil, accessToken == nil else { throw BackendDiscoveryError.invalidRequest }
        }
        let body = try operation == .logout ? body(json: Data([34, 34]), key: key, iv: material.iv) : body(payload: payload, key: key, iv: material.iv)
        var error: Unmanaged<CFError>?
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        guard let rsa = SecKeyCreateWithData(material.publicDER as CFData, attributes as CFDictionary, &error),
              let encryptedKey = SecKeyCreateEncryptedData(rsa, .rsaEncryptionPKCS1, key as CFData, &error) else {
            throw BackendDiscoveryError.invalidMaterial
        }
        var components = URLComponents(string: "https://sheetaapi.wangsu.com" + operation.path)!
        components.queryItems = [URLQueryItem(name: "locale", value: material.locale)]
        var request = URLRequest(url: components.url!, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        request.httpMethod = "POST"; request.httpBody = Data(body.utf8)
        request.allHTTPHeaderFields = ["Content-Type": "application/json", "apiVersion": operation.version, "certId": material.certID,
            "nonce": nonce, "reqTimestamp": timestamp, "secret": (encryptedKey as Data).base64EncodedString(),
            "sheetaSign": signature(certID: material.certID, timestamp: timestamp, nonce: nonce, body: body)]
        if operation == .networkConfig || operation == .getApplications {
            let scope = try serverScope ?? BackendPublicEnvelope.serverScope(material: material, timestamp: timestamp)
            request.setValue(scope, forHTTPHeaderField: "SlServerType")
        }
        if operation == .getApplications {
            request.setValue("vpn", forHTTPHeaderField: "slTokenType")
            request.setValue("vpn", forHTTPHeaderField: "twoFactorType")
        }
        if let credential {
            credential.withBearerToken { request.setValue("Bearer " + $0, forHTTPHeaderField: "Authorization") }
        } else if let accessToken {
            request.setValue("Bearer " + accessToken, forHTTPHeaderField: "Authorization")
        }
        return request
    }

    static func receive(_ request: URLRequest, configuration: URLSessionConfiguration) async throws -> Data {
        try Task.checkCancellation()
        let session = URLSession(configuration: configuration, delegate: NoBackendRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw BackendDiscoveryError.rejected }
            guard response.expectedContentLength <= maximumResponse else { throw BackendDiscoveryError.tooLarge }
            var data = Data()
            for try await byte in bytes {
                try Task.checkCancellation()
                guard data.count < maximumResponse else { throw BackendDiscoveryError.tooLarge }
                data.append(byte)
            }
            defer { data.resetBytes(in: 0..<data.count) }
            try Task.checkCancellation()
            return data
        } catch is CancellationError { throw CancellationError() }
        catch let error as URLError where error.code == .cancelled { throw CancellationError() }
        catch let error as BackendDiscoveryError { throw error }
        catch { throw BackendDiscoveryError.transport }
    }
}

private final class NoBackendRedirect: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
