import Foundation

/// UV emission only. Callers must derive authenticated values and any IP-family
/// fallback payloads separately; this type supplies no authentication defaults.
public struct UVMetadata: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public enum Field: String, CaseIterable, Sendable {
        case serverType = "UV_SL_SERVERTYPE", encryptedPassword = "UV_ENCPASS"
        case deviceID = "UV_DEVICEID", authType = "UV_AUTH_TYPE", locale = "UV_LOCALE"
        case systemBits = "UV_SYSTEM_BITS", extra1 = "UV_EXTRA_PARAM_1", extra2 = "UV_EXTRA_PARAM_2"
        case userID = "UV_USERID", secureLinkVersion = "UV_SL_VERSION", version = "UV_VERSION"
        case serverIP = "UV_SERVER_IP", systemName = "UV_SYSTEM_NAME", systemModel = "UV_SYSTEM_MODEL"
        case deviceName = "UV_DEVICE_NAME", deviceModel = "UV_DEVICE_MODEL"
        case extra3 = "UV_EXTRA_PARAM_3", extra4 = "UV_EXTRA_PARAM_4", extra5 = "UV_EXTRA_PARAM_5"
    }
    public enum BuildError: Error, Equatable {
        case missingInternalValue, missingField(Field), missingCode, unsafeValue
        case fixedPartsTooLarge, emittedTextTooLarge
    }
    private let fixedBytes: Int
    private let codeBudgetBytes: Int
    private let values: [Field: String]
    private let ipv4Encoded: String
    private let ipv6Encoded: String
    public var description: String { "UVMetadata(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["metadata": "redacted"]) }

    /// Internal strings are used only for the official length reservation. Do not
    /// substitute unverified placeholder lengths when wiring a real transport.
    public init(vpnInitInfo: String, username: String, password: String, openVPNBase: String,
                codeForBudget: String, values: [Field: String], ipv4Encoded: String = "", ipv6Encoded: String = "") throws {
        let internalValues = [vpnInitInfo, username, password, openVPNBase]
        guard internalValues.allSatisfy({ !$0.isEmpty }) else { throw BuildError.missingInternalValue }
        guard !codeForBudget.isEmpty else { throw BuildError.missingCode }
        // Internal configuration can contain lines; it is never interpolated into
        // emitted directives. Values must not introduce lines or quote/escape syntax.
        for value in Array(values.values) + [codeForBudget, ipv4Encoded, ipv6Encoded] {
            guard !value.unicodeScalars.contains(where: {
                CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0)
                    || $0 == "\"" || $0 == "'" || $0 == "\\"
            }) else { throw BuildError.unsafeValue }
        }
        let required: [Field] = [.encryptedPassword, .deviceID, .authType, .extra1, .extra2,
                                 .userID, .secureLinkVersion, .version, .serverIP, .serverType]
        for field in required where values[field, default: ""].isEmpty { throw BuildError.missingField(field) }
        // Saturate at the limit before addition; enormous caller input cannot overflow.
        self.fixedBytes = internalValues.reduce(0) { min(2009, $0 + min(2009, $1.utf8.count)) }
        self.codeBudgetBytes = "UV_CODE=\(codeForBudget)\n".utf8.count
        self.values = values
        self.ipv4Encoded = ipv4Encoded
        self.ipv6Encoded = ipv6Encoded
    }

    public struct Output: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        private let directives: String
        public let omittedFields: [Field]
        public var description: String { "UVMetadata.Output(redacted)" }
        public var debugDescription: String { description }
        public var customMirror: Mirror { Mirror(self, children: ["metadata": "redacted"]) }
        fileprivate init(directives: String, omitted: [Field]) {
            self.directives = directives; self.omittedFields = omitted
        }
        /// Only emitted directives are exposed. Transport supplies UV_CODE
        /// separately from the current authenticated session, never from this output.
        public func withDirectives<T>(_ use: (String) throws -> T) rethrows -> T {
            try use(directives)
        }
    }

    public func build() throws -> Output {
        let budget = 2009 - fixedBytes
        var remaining = budget - codeBudgetBytes
        guard budget > 0, remaining >= 0 else { throw BuildError.fixedPartsTooLarge }
        var emitted = ""
        var omitted: [Field] = []
        func admit(_ field: Field, _ value: String) {
            let cost = "\(field.rawValue)=\(value)\n".utf8.count
            guard !value.isEmpty, cost <= remaining else { omitted.append(field); return }
            emitted += "setenv \(field.rawValue) \(value)\n"
            remaining -= cost
        }
        for field in Field.allCases where field != .extra5 { admit(field, values[field, default: ""]) }
        let full = values[.extra5, default: ""]
        if full.isEmpty {
            omitted.append(.extra5)
        } else if "UV_EXTRA_PARAM_5=\(full)\n".utf8.count <= remaining {
            admit(.extra5, full)
        } else {
            // The official branch chooses IPv4 by presence, not by whether it
            // fits. An oversized IPv4 candidate does NOT fall through to IPv6.
            admit(.extra5, ipv4Encoded.isEmpty ? ipv6Encoded : ipv4Encoded)
        }
        guard emitted.utf8.count <= budget else { throw BuildError.emittedTextTooLarge }
        return Output(directives: emitted, omitted: omitted)
    }
}
