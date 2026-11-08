import Foundation
import CoreFoundation

/// A closed diagnostic vocabulary: never retains JSON, string values, or decoding errors.
public struct BackendNetworkConfigurationFailure: Error, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let shape: [String: String]
    public var description: String { "BackendNetworkConfigurationFailure(redacted; inspect shape)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["failure": "redacted"]) }
    enum Reason: String { case tooLarge, invalidResponse, rejected }

    private static let paths: [[String]] = {
        let base = ["content", "networkConfig"]
        var paths = [["returnCode"], ["content"], base]
        for name in ["appaAccConf", "clientCert", "clientFlowRedirect", "clientConf", "idleTimeout", "ipv6DnsResolve", "priorServers", "alternateServers", "portHideEnable", "spaKey", "spaHmacKey", "controllerIpMapping", "serverTime"] { paths.append(base + [name]) }
        for name in ["caCert", "signCert", "signPrivateKey", "encryptCert", "encryptPrivateKey", "certSign", "org", "apiAddress", "md5", "versionType", "gmtls", "enable", "inner", "spaSwitch"] { paths.append(base + ["clientCert", name]) }
        for name in ["host", "ports"] { paths.append(base + ["appaAccConf", name]) }
        for name in ["clientModeSwitch", "caCert"] { paths.append(base + ["clientFlowRedirect", name]) }
        for server in ["priorServers", "alternateServers"] {
            paths.append(base + [server, "[]"])
            for name in ["ip", "flystoneId", "ports", "accessMode", "IfIndex"] { paths.append(base + [server, "[]", name]) }
            paths.append(base + [server, "[]", "ports", "[]"])
        }
        paths.append(base + ["appaAccConf", "ports", "[]"])
        paths.append(base + ["controllerIpMapping", "[]"])
        for name in ["domain", "ips"] { paths.append(base + ["controllerIpMapping", "[]", name]) }
        paths.append(base + ["controllerIpMapping", "[]", "ips", "[]"])
        return paths
    }()
    static func make(_ data: Data?, reason: Reason, decodingError: Error? = nil) -> Self {
        var shape = ["reason": reason.rawValue]
        let root = data.flatMap { try? JSONSerialization.jsonObject(with: $0, options: [.fragmentsAllowed]) }
        func type(_ value: Any?) -> String {
            guard let value else { return "missing" }
            if value is NSNull { return "null" }
            if let number = value as? NSNumber { return CFGetTypeID(number) == CFBooleanGetTypeID() ? "boolean" : "number" }
            if value is String { return "string" }
            if value is [String: Any] { return "object" }
            if value is [Any] { return "array" }
            return "unknown"
        }
        shape["root"] = type(root)
        // Array element contents are never sampled into diagnostics; their decoder path suffices.
        for path in paths where !path.contains("[]") {
            var value: Any? = root
            for component in path { value = (value as? [String: Any])?[component] }
            shape[path.joined(separator: ".")] = type(value)
        }
        if let number = (root as? [String: Any])?["returnCode"] as? NSNumber,
           CFGetTypeID(number) != CFBooleanGetTypeID() {
            let value = number.doubleValue
            if value.isFinite && value.rounded() == value && (-1_000_000...1_000_000).contains(value) {
                shape["returnCodeValue"] = String(Int(value))
            } else { shape["returnCodeValue"] = "outside-safe-integer-range" }
        }
        var codingPath: [any CodingKey]?
        if let decodingError {
            switch decodingError {
            case let DecodingError.typeMismatch(_, context): codingPath = context.codingPath
            case let DecodingError.valueNotFound(_, context): codingPath = context.codingPath
            case let DecodingError.keyNotFound(key, context): codingPath = context.codingPath + [key]
            case let DecodingError.dataCorrupted(context): codingPath = context.codingPath
            default: break
            }
        }
        if let codingPath {
            let normalized = codingPath.map { $0.intValue == nil ? $0.stringValue : "[]" }
            shape["decodePath"] = normalized.isEmpty ? "root" : (paths.contains(normalized) ? normalized.joined(separator: ".") : "unknown")
        }
        return Self(shape: shape)
    }
}
