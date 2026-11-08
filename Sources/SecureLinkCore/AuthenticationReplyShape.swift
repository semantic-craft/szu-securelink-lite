import Foundation
import CoreFoundation

/// Fixed field names and type labels only. Never includes values, arbitrary keys,
/// lengths, error descriptions or serialized service responses.
enum AuthenticationReplyShape {
    static func describe(_ data: Data) -> [String: String] {
        guard let root = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) else {
            return ["root": "invalid-json"]
        }
        var result = ["root": kind(root)]
        guard let object = root as? [String: Any] else { return result }
        result["returnCode"] = kind(object["returnCode"])
        result["content"] = kind(object["content"])
        let content = object["content"] as? [String: Any] ?? object
        for key in ["rejectedByNonCredit", "userInfoCompletion", "creditFlag", "username", "authConfigId"] {
            result[key] = kind(content[key])
        }
        return result
    }
    static func kind(_ value: Any?) -> String {
        guard let value else { return "absent" }
        if value is NSNull { return "null" }
        if value is String { return "string" }
        if let number = value as? NSNumber {
            return CFGetTypeID(number) == CFBooleanGetTypeID() ? "boolean" : "number"
        }
        if value is [String: Any] { return "object" }
        if value is [Any] { return "array" }
        return "unknown"
    }
}

/// Only protocol enums and fixed type labels; no check item details or identities.
enum EndpointReplyShape {
    static func describe(_ data: Data) -> [String: String] {
        guard let root = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) else { return ["root": "invalid-json"] }
        var result = ["root": AuthenticationReplyShape.kind(root)]
        guard let object = root as? [String: Any] else { return result }
        result["returnCode"] = AuthenticationReplyShape.kind(object["returnCode"])
        result["content"] = AuthenticationReplyShape.kind(object["content"])
        if let code = object["returnCode"] as? NSNumber, CFGetTypeID(code) != CFBooleanGetTypeID(), (0...99999).contains(code.intValue), code == NSNumber(value: code.intValue) {
            result["returnCodeEnum"] = code.stringValue
        }
        if let text = object["content"] as? String {
            let lower = text.lowercased()
            let words = ["agent", "connect", "timeout", "unmarshal", "version", "auth", "permission", "disabled", "health", "success", "support", "check", "rpc", "refused", "failed", "error"]
            for word in words where lower.contains(word) { result["message-has-" + word] = "yes" }
            if let bytes = text.data(using: .utf8), let value = try? JSONSerialization.jsonObject(with: bytes, options: [.fragmentsAllowed]) {
                result["contentJSON"] = AuthenticationReplyShape.kind(value)
            } else { result["contentJSON"] = "no" }
        }
        var content = object["content"] as? [String: Any] ?? object
        if let text = object["content"] as? String, let inner = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] { content = inner }
        for key in ["enable", "checkStatus", "healthStatus", "checkItems"] {
            let value = content[key]
            result[key] = AuthenticationReplyShape.kind(value)
            if key != "checkItems", let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() {
                let allowed = key == "enable" ? [0, 1] : [0, 1, 2, 3]
                if allowed.contains(where: { number == NSNumber(value: $0) }) { result[key + "Enum"] = number.stringValue }
                else { result[key + "Enum"] = "other" }
            }
        }
        return result
    }
}
