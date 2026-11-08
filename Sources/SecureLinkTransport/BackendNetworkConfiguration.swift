import Foundation
import Darwin
import CryptoKit
import SecureLinkCore

/// Explicit caller input. No interface, DNS, SSID or official configuration is collected here.
public struct BackendNetworkInput: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let intranetIP: String
    private let dns: String
    private let wifiSSIDs: [String]
    public let org: String
    public let username: String?
    public let deviceId: String?
    public init(intranetIP: String = "", dns: String = "", wifiSSIDs: [String] = [],
                org: String = "szu", username: String? = nil, deviceId: String? = nil) {
        self.intranetIP = intranetIP; self.dns = dns; self.wifiSSIDs = wifiSSIDs
        self.org = org; self.username = username; self.deviceId = deviceId
    }
    public var description: String { "BackendNetworkInput(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["input": "redacted"]) }
    var payload: [String: Any] {
        var fields: [String: Any] = ["system": 3]
        if !intranetIP.isEmpty { fields["intranetIp"] = intranetIP }
        if !dns.isEmpty { fields["dns"] = dns }
        if !wifiSSIDs.isEmpty { fields["wifiSsid"] = wifiSSIDs }
        return fields
    }
}

/// Typed sensitive material stays in memory. Receipt is evidence of shape, never of tunnel support.
public struct BackendNetworkConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let network: Network
    private let serverScope: String?
    private let accessTokenBinding: Data?
    public let receipt: Receipt
    public var description: String { "BackendNetworkConfiguration(redacted; transport unverified)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["configuration": "redacted"]) }
    public enum ModeEvidence: String, Encodable, Sendable { case absent, zero, nonzeroUnverified, nearby, specifiedGateway }
    public struct Receipt: Encodable, Sendable {
        public let result = "network-configuration-parsed"
        public let fieldTypes: [String: String]
        public let modes: [String: ModeEvidence]
        public let switches: [String: Bool]
        public let present: [String: Bool]
        public let template: [String: String]
        public let directivePresence: [String: Bool]
        public let directiveAnalysisComplete: Bool
        public let vendorOptionCompatibility = "no-tun-probe-only-tcp-confusion"
        public let activeShapingImplemented = false
        public let gmsslRenegotiationImplemented = false
        public let vendorActiveFeaturesImplemented = false
        public let tunnelSupported = false
        public let campusValidated = false
        public let uninstallReady = false
    }
    private struct Response: Decodable { let returnCode: Int; let content: Content? }
    private struct Content: Decodable { let networkConfig: Network }
    private struct Network: Decodable, Sendable {
        let appaAccConf: Accelerator?
        let clientCert: Certificate?
        let clientFlowRedirect: Redirect?
        let clientConf: String?
        let idleTimeout: Int64?
        let ipv6DnsResolve: Int?
        let priorServers: [Server]?
        let alternateServers: [Server]?
        let portHideEnable: Int?
        let spaKey: String?
        let spaHmacKey: String?
        let controllerIpMapping: [Mapping]?
        let serverTime: Int64?
    }
    private struct Accelerator: Decodable, Sendable { let host: String?; let ports: [Int]? }
    private struct Certificate: Decodable, Sendable {
        let caCert: String?, signCert: String?, signPrivateKey: String?, encryptCert: String?, encryptPrivateKey: String?
        let certSign: String?, org: String?, apiAddress: String?, md5: String?
        let versionType: Int?, gmtls: Int?
        let enable: Bool?, inner: Bool?, spaSwitch: Bool?
    }
    private struct Redirect: Decodable, Sendable { let clientModeSwitch: Int?; let caCert: String? }
    private struct Server: Decodable, Sendable { let ip: String?; let flystoneId: Int64?; let ports: [Int]?; let accessMode: Int?; let IfIndex: Int? }
    private struct Mapping: Decodable, Sendable { let domain: String?; let ips: [String]? }

    func evaluationInput() throws -> Data {
        guard let text = network.clientConf?.replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
              !text.isEmpty else { throw OpenVPNEvaluationError.invalidInput }
        let data = Data(text.utf8)
        guard data.count <= BackendDiscovery.maximumResponse else { throw OpenVPNEvaluationError.invalidInput }
        return data
    }

    private func candidateServer() throws -> Server {
        guard let server = network.priorServers?.first ?? network.alternateServers?.first,
              let ip = server.ip, ip.utf8.allSatisfy({ "0123456789abcdefABCDEF:.".utf8.contains($0) }),
              let ports = server.ports, !ports.isEmpty, ports.count <= 64,
              ports.allSatisfy({ (1...65535).contains($0) }) else { throw OpenVPNEvaluationError.invalidInput }
        var ipv4 = in_addr(), ipv6 = in6_addr()
        guard inet_pton(AF_INET, ip, &ipv4) == 1 || inet_pton(AF_INET6, ip, &ipv6) == 1 else {
            throw OpenVPNEvaluationError.invalidInput
        }
        return server
    }

    func candidateEvaluationInput() throws -> Data {
        var data = try evaluationInput()
        let server = try candidateServer()
        guard let ip = server.ip, let ports = server.ports else { throw OpenVPNEvaluationError.invalidInput }
        for port in ports { data.append(Data("\nremote \(ip) \(port)".utf8)) }
        data.append(10)
        guard data.count <= BackendDiscovery.maximumResponse else { throw OpenVPNEvaluationError.invalidInput }
        return data
    }

    struct HandshakeProbeOptions {
        let vendorConfusion: Bool
        let activeShapingNotExercised: Bool
        let gmsslRenegotiationNotExercised: Bool
    }
    /// Private no-TUN probe handoff only. Never use this admission path for a working tunnel.
    /// The scope is exactly the one sent in the configuration request.
    func withHandshakeProbeCandidate<T>(accessToken: String, _ use: (String, String, String, HandshakeProbeOptions) throws -> T) throws -> T {
        guard let serverScope, BackendPublicEnvelope.validServerScope(serverScope),
              accessTokenBinding == Data(SHA256.hash(data: Data(accessToken.utf8))) else {
            throw BackendHandshakePreparationError.unboundConfiguration
        }
        guard receipt.directiveAnalysisComplete else { throw BackendHandshakePreparationError.invalidConfiguration }
        guard receipt.directivePresence.values.allSatisfy({ !$0 }) else { throw BackendHandshakePreparationError.unsupportedDirective }
        guard network.portHideEnable == 0 else { throw BackendHandshakePreparationError.unsupportedPortHiding }
        guard network.ipv6DnsResolve == nil || network.ipv6DnsResolve == 0 else { throw BackendHandshakePreparationError.unsupportedIPv6DNS }
        // UpdateFlowRedirect returns at mode 0 before reading caCert (0x1005bbbc0 -> 0x1005bbf00).
        // The inactive flow CA is neither tunnel trust material nor a certificate to install.
        guard network.clientFlowRedirect == nil || network.clientFlowRedirect?.clientModeSwitch == 0 else {
            throw BackendHandshakePreparationError.unsupportedFlowRedirection
        }
        guard network.appaAccConf == nil || ((network.appaAccConf?.host ?? "").isEmpty && (network.appaAccConf?.ports ?? []).isEmpty) else {
            throw BackendHandshakePreparationError.unsupportedAcceleration
        }
        if let certificate = network.clientCert {
            guard certificate.gmtls == 0, certificate.versionType == 0,
                  certificate.enable == false, certificate.inner == false, certificate.spaSwitch == false,
                  [certificate.caCert, certificate.signCert, certificate.signPrivateKey, certificate.encryptCert,
                   certificate.encryptPrivateKey, certificate.certSign].allSatisfy({ ($0 ?? "").isEmpty }) else {
                throw BackendHandshakePreparationError.unsupportedTLSProfile
            }
        }
        let options = try validateHandshakeProbeTemplate()
        let server = try candidateServer()
        guard server.accessMode.map({ [0, 1, 2].contains($0) }) ?? true else { throw BackendHandshakePreparationError.unsupportedGatewaySelection }
        guard let ip = server.ip, var text = String(data: try candidateEvaluationInput(), encoding: .utf8) else {
            throw BackendHandshakePreparationError.invalidConfiguration
        }
        if options.gmsslRenegotiationNotExercised {
            // Only this previously validated GMSSL-only option is removed for the no-TUN TCP probe.
            // Never remap it to OpenVPN reneg-sec or modify certificate/other profile lines.
            var block: String?
            text = text.components(separatedBy: "\n").filter { raw in
                let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                if let current = block {
                    if line == "</" + current + ">" { block = nil }
                    return true
                }
                if line.hasPrefix("<") && line.hasSuffix(">") { block = String(line.dropFirst().dropLast()); return true }
                return line.split(whereSeparator: { $0.isWhitespace }).first != "tls-reneg-sec"
            }.joined(separator: "\n")
        }
        return try use(text, ip, serverScope, options)
    }

    private static let inlineAllowed: Set<String> = ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"]
    private static let noArgument: Set<String> = ["client", "tls-client", "nobind", "persist-key", "persist-tun", "auth-nocache", "auth-user-pass",
            "remote-random", "pull", "route-nopull", "push-peer-info", "mute-replay-warnings", "float", "client-cert-not-required"]
    private static let standard: Set<String> = ["resolv-retry", "dev", "dev-type", "proto", "remote-cert-tls", "verify-x509-name", "remote-cert-ku", "remote-cert-eku",
            "tls-version-min", "tls-version-max", "tls-cipher", "tls-ciphersuites", "tls-cert-profile", "peer-fingerprint", "key-direction",
            "auth", "cipher", "data-ciphers", "data-ciphers-fallback", "reneg-sec", "reneg-bytes", "reneg-pkts", "hand-window", "tran-window",
            "tls-timeout", "ping", "ping-restart", "ping-exit", "connect-retry", "connect-retry-max", "connect-timeout", "server-poll-timeout",
            "explicit-exit-notify", "verb", "mute", "tun-mtu", "tun-mtu-extra", "link-mtu", "mssfix", "sndbuf", "rcvbuf",
            "route", "route-ipv6", "route-delay", "redirect-gateway", "dhcp-option", "inactive", "ifconfig", "ifconfig-ipv6", "topology"]
    private static let references: Set<String> = ["ca", "capath", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "config", "include",
            "pkcs12", "secret", "crl-verify", "plugin", "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify",
            "script-security", "http-proxy", "http-proxy-user-pass", "socks-proxy", "management", "log", "log-append", "status", "writepid"]

    // Only explicitly verified vendor values may appear in the ignore list.
    private static let conditionalVendorOptions: Set<String> = ["shaper", "enable-confusion-proto", "disable-set-dns", "tls-reneg-sec"]

    /// This is an admission whitelist, not a replacement for OpenVPN's own parser.
    /// Self-contained standard TLS material only; no profile files, hooks or proxies.
    private func validateHandshakeProbeTemplate() throws -> HandshakeProbeOptions {
        let rawText = String(decoding: try evaluationInput(), as: UTF8.self)
            .replacingOccurrences(of: "\r\n", with: "\n")
        guard rawText.unicodeScalars.allSatisfy({ ($0.value >= 0x20 && $0.value <= 0x7E) || $0 == "\n" || $0 == "\t" }) else {
            throw BackendHandshakePreparationError.invalidConfiguration
        }
        let text = rawText
        let inlineAllowed = Self.inlineAllowed
        let noArgument = Self.noArgument
        let standard = Self.standard
        let references = Self.references
        var block: String?, blockHasContent = false
        var hasTrust = false, hasProtocol = false
        var inactiveSeen: Set<String> = []
        var ignoredInactive: Set<String>?
        var vendorConfusion = false, activeShaping = false, gmsslRenegotiation = false
        var protocols: [String] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            let line = rawLine.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
            if let current = block {
                if line == "</" + current + ">" {
                    guard blockHasContent else { throw BackendHandshakePreparationError.unsupportedInlineMaterial }
                    if current == "ca" { hasTrust = true }
                    block = nil
                } else if !line.isEmpty { blockHasContent = true }
                continue
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("<") && line.hasSuffix(">") {
                let name = String(line.dropFirst().dropLast())
                guard inlineAllowed.contains(name) else { throw BackendHandshakePreparationError.unsupportedInlineMaterial }
                block = name; blockHasContent = false; continue
            }
            let words = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let name = words.first else { continue }
            if Self.conditionalVendorOptions.contains(name) {
                guard words.count == 2, inactiveSeen.insert(name).inserted else { throw BackendHandshakePreparationError.unsupportedDirective }
                if name == "disable-set-dns" {
                    guard words[1] == "0" else { throw BackendHandshakePreparationError.unsupportedDirective }
                } else {
                    guard words[1].utf8.allSatisfy({ (48...57).contains($0) }),
                          let value = Int32(words[1]), value >= 0, value > 0 || words[1] == "0" else { throw BackendHandshakePreparationError.unsupportedDirective }
                    if name == "enable-confusion-proto" { vendorConfusion = value > 0 }
                    if name == "shaper" { activeShaping = value > 0 }
                    if name == "tls-reneg-sec" { gmsslRenegotiation = true }
                }
                continue
            }
            if name == "ignore-unknown-option" {
                let arguments = Set(words.dropFirst())
                guard ignoredInactive == nil, words.count >= 2, words.count <= 5,
                      arguments.count == words.count - 1, arguments.isSubset(of: Self.conditionalVendorOptions) else {
                    throw BackendHandshakePreparationError.unsupportedDirective
                }
                ignoredInactive = arguments
                continue
            }
            if name == "setenv" {
                guard words.count == 3, words[1] == "CLIENT_CERT", ["0", "1"].contains(words[2]) else {
                    throw BackendHandshakePreparationError.unsupportedDirective
                }
                continue
            }
            if references.contains(name) || (name == "auth-user-pass" && words.count != 1) { throw BackendHandshakePreparationError.externalReference }
            // The candidate selection is explicit; an existing remote could silently win over it.
            guard name != "remote" else { throw BackendHandshakePreparationError.invalidConfiguration }
            if noArgument.contains(name) {
                guard words.count == 1 else { throw BackendHandshakePreparationError.invalidConfiguration }
                continue
            }
            if ["explicit-exit-notify", "mssfix", "route-delay"].contains(name) && words.count == 1 { continue }
            guard standard.contains(name), words.count >= 2, words.count <= 16 else { throw BackendHandshakePreparationError.unsupportedDirective }
            switch name {
            case "resolv-retry":
                // OpenVPN3 ignores this option. Candidates are numeric IPs and the probe owns its deadline.
                guard Self.validResolvRetry(words) else { throw BackendHandshakePreparationError.unsupportedDirective }
            case "proto":
                // OpenVPN3 remotelist uses CLIENT_SUFFIX: bare tcp/tcp4/tcp6 are client transports too.
                guard words.count == 2, ["udp", "udp4", "udp6", "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client"].contains(words[1]) else { throw BackendHandshakePreparationError.unsupportedProtocol }
                hasProtocol = true
                protocols.append(words[1])
            case "dev", "dev-type":
                guard words.count == 2, words[1] == "tun" else { throw BackendHandshakePreparationError.unsupportedDeviceType }
            case "remote-cert-tls":
                guard words.count == 2, words[1] == "server" else { throw BackendHandshakePreparationError.unsupportedTLSProfile }
            case "tls-cert-profile":
                guard words.count == 2, ["legacy", "preferred", "suiteb"].contains(words[1]) else { throw BackendHandshakePreparationError.unsupportedTLSProfile }
            case "peer-fingerprint": hasTrust = true
            default: break
            }
        }
        guard ignoredInactive?.isSubset(of: inactiveSeen) ?? true else { throw BackendHandshakePreparationError.unsupportedDirective }
        guard block == nil, hasTrust, hasProtocol else { throw BackendHandshakePreparationError.invalidConfiguration }
        if vendorConfusion || activeShaping || gmsslRenegotiation {
            guard protocols.count == 1, ["tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client"].contains(protocols[0]) else {
                throw BackendHandshakePreparationError.unsupportedProtocol
            }
        }
        return HandshakeProbeOptions(vendorConfusion: vendorConfusion, activeShapingNotExercised: activeShaping,
                                     gmsslRenegotiationNotExercised: gmsslRenegotiation)
    }

    private static func validResolvRetry(_ words: [String]) -> Bool {
        guard words.count == 2 else { return false }
        let value = words[1]
        return value == "infinite" || (!value.isEmpty && value.utf8.allSatisfy { (48...57).contains($0) } && UInt64(value) != nil)
    }

    private static func integerSign(_ value: String) -> String? {
        let digits = value.hasPrefix("-") ? String(value.dropFirst()) : value
        guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) }), let number = Int64(value) else { return nil }
        return number == 0 ? "zero" : (number > 0 ? "positive" : "negative")
    }

    /// Bounded, value-free diagnostics. Unknown names and all directive arguments are discarded.
    static func templateEvidence(_ encoded: String?) -> [String: String] {
        let known = BackendOpenVPNDiagnosticOptions.names.union(BackendOpenVPNDiagnosticOptions.vendorNames).union(standard).union(noArgument).union(references).union(["setenv", "remote", "gmtls", "tls-proxy", "black-hole-route"])
        var result = Dictionary(uniqueKeysWithValues: known.map { ("directive." + $0, "false") })
        for name in ["ca", "cert", "key", "sign_cert"] { result["inline." + name] = "false" }
        for name in BackendOpenVPNDiagnosticOptions.vendorNames { result["vendorArgumentShape." + name] = "absent" }
        result["proto"] = "missing"; result["dev"] = "missing"; result["dev-type"] = "missing"
        result["unknownDirectiveCount"] = "0"
        result["resolvRetryBehavior"] = "absent"
        result["ignoreUnknownOption.knownArguments"] = ""
        result["ignoreUnknownOption.unknownArgumentCount"] = "0"
        result["ignoreUnknownOption.argumentAnalysisComplete"] = "true"
        result["shaper.argumentCount"] = "0"
        result["shaper.argumentShape"] = "absent"
        guard let text = encoded?.replacingOccurrences(of: "+", with: " ").removingPercentEncoding else {
            result["analysisComplete"] = "false"; return result
        }
        let protocols: Set<String> = ["tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client", "tcp-server", "tcp4-server", "tcp6-server", "udp", "udp4", "udp6"]
        var block: String?, unknownCount = 0
        var ignoredKnown: Set<String> = [], ignoredUnknown = 0, shaperArguments = 0
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if let current = block {
                if line == "</" + current + ">" { block = nil }
                continue
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("<") && line.hasSuffix(">") {
                let name = String(line.dropFirst().dropLast())
                if ["ca", "cert", "key", "sign_cert"].contains(name) { result["inline." + name] = "true" }
                if !inlineAllowed.contains(name) { unknownCount = min(unknownCount + 1, 100) }
                block = name; continue
            }
            let words = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            guard let name = words.first else { continue }
            if known.contains(name) { result["directive." + name] = "true" }
            else { unknownCount = min(unknownCount + 1, 100) }
            if BackendOpenVPNDiagnosticOptions.vendorNames.contains(name) {
                let shapeKey = "vendorArgumentShape." + name
                let value = words.count == 2 ? words[1] : ""
                let shape: String
                if ["tls-reneg-bytes", "tls-reneg-sec"].contains(name) {
                    shape = !value.isEmpty && value.utf8.allSatisfy { (48...57).contains($0) } && UInt64(value) != nil
                        ? "nonnegativeInteger" : "other"
                } else if ["disable-set-dns", "enable-confusion-proto"].contains(name) {
                    shape = words.count == 1 ? "noArgument" : (words.count == 2 ? Self.integerSign(value) ?? "other" : "other")
                } else if words.count == 1 { shape = "noArgument" }
                else if words.count == 2 && value == "0" { shape = "zero" }
                else if words.count == 2 && value == "1" { shape = "one" }
                else { shape = "other" }
                result[shapeKey] = result[shapeKey] == "absent" ? shape : "other"
            }
            if name == "ignore-unknown-option" {
                for argument in words.dropFirst() {
                    if known.contains(argument) { ignoredKnown.insert(argument) }
                    else { ignoredUnknown = min(ignoredUnknown + 1, 100) }
                    if argument.contains("\\") || argument.contains("\"") || argument.contains("'") {
                        result["ignoreUnknownOption.argumentAnalysisComplete"] = "false"
                    }
                }
                result["ignoreUnknownOption.knownArguments"] = ignoredKnown.sorted().joined(separator: ",")
                result["ignoreUnknownOption.unknownArgumentCount"] = String(ignoredUnknown)
            }
            if name == "shaper" {
                shaperArguments = min(shaperArguments + words.count - 1, 100)
                let value = words.count == 2 ? words[1] : ""
                result["shaper.argumentShape"] = result["shaper.argumentShape"] == "absent"
                    ? (Self.integerSign(value) ?? "invalid") : "multiple"
                result["shaper.argumentCount"] = String(shaperArguments)
            }
            if name == "resolv-retry" {
                let priorInvalid = result["resolvRetryBehavior"] == "invalid"
                result["resolvRetryBehavior"] = !priorInvalid && validResolvRetry(words) ? "engineIgnored" : "invalid"
            }
            if ["proto", "dev", "dev-type"].contains(name) {
                let allowed = name == "proto" ? protocols : Set(["tun", "tap"])
                let classification = words.count == 2 && allowed.contains(words[1]) ? words[1] : "unknown"
                result[name] = result[name] == "missing" ? classification : "multiple"
            }
        }
        result["unknownDirectiveCount"] = String(unknownCount)
        result["analysisComplete"] = analyzeDirectives(encoded).complete ? "true" : "false"
        return result
    }

    /// Mirrors query-unescape semantics without emitting configuration or unknown names.
    static func directives(_ clientConf: String?) -> [String: Bool] {
        analyzeDirectives(clientConf).presence
    }
    static func analyzeDirectives(_ clientConf: String?) -> (presence: [String: Bool], complete: Bool) {
        var complete = true
        var result = ["gmtls": false, "tls-proxy": false, "black-hole-route": false]
        guard let rawText = clientConf?.replacingOccurrences(of: "+", with: " ").removingPercentEncoding else { return (result, clientConf == nil) }
        let text = rawText.replacingOccurrences(of: "\r\n", with: "\n")
        if !text.unicodeScalars.allSatisfy({ ($0.value >= 0x20 && $0.value <= 0x7E) || $0 == "\n" || $0 == "\t" }) {
            complete = false
        }
        var inlineBlock: String?
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            let line = rawLine.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
            if let block = inlineBlock {
                if line == "</" + block + ">" { inlineBlock = nil }
                continue
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            // Every inline payload block, including unknown ones, is opaque data.
            if line.hasPrefix("\"") || line.hasPrefix("'") || line.hasPrefix("--") { complete = false; continue }
            if line.hasPrefix("<") {
                if let end = line.firstIndex(of: ">"), !line.hasPrefix("</") {
                    inlineBlock = String(line[line.index(after: line.startIndex)..<end])
                    if inlineBlock == "connection" { complete = false }
                    if end != line.index(before: line.endIndex) { complete = false }
                } else { complete = false }
                continue
            }
            if line.contains("\\") { complete = false }
            guard let name = line.split(whereSeparator: { $0.isWhitespace }).first else { continue }
            let words = line.split(whereSeparator: { $0.isWhitespace })
            if name == "setenv" && words.count > 1 && words[1] == "opt" { complete = false }
            if name == "config" || name == "include" || name.contains("\"") || name.contains("'") { complete = false }
            if result[String(name)] != nil { result[String(name)] = true }
        }
        return (result, complete && inlineBlock == nil)
    }

    static func parse(_ data: Data, serverScope: String? = nil, accessToken: String? = nil) throws -> Self {
        guard data.count <= BackendDiscovery.maximumResponse else { throw BackendNetworkConfigurationFailure.make(nil, reason: .tooLarge) }
        let response: Response
        do { response = try JSONDecoder().decode(Response.self, from: data) }
        catch { throw BackendNetworkConfigurationFailure.make(data, reason: .invalidResponse, decodingError: error) }
        guard response.returnCode == 1 else { throw BackendNetworkConfigurationFailure.make(data, reason: .rejected) }
        guard let network = response.content?.networkConfig else { throw BackendNetworkConfigurationFailure.make(data, reason: .invalidResponse) }
        var types: [String: String] = [:]
        func field<T>(_ name: String, _ value: T?, _ type: String) { if value != nil { types[name] = type } }
        field("appaAccConf", network.appaAccConf, "object")
        field("clientCert", network.clientCert, "object")
        field("clientFlowRedirect", network.clientFlowRedirect, "object")
        field("clientConf", network.clientConf, "string")
        field("priorServers", network.priorServers, "array")
        field("alternateServers", network.alternateServers, "array")
        field("controllerIpMapping", network.controllerIpMapping, "array")
        field("spaKey", network.spaKey, "string")
        field("spaHmacKey", network.spaHmacKey, "string")
        field("serverTime", network.serverTime, "integer")
        field("idleTimeout", network.idleTimeout, "integer")
        func mode(_ value: Int?) -> ModeEvidence { value.map { $0 == 0 ? .zero : .nonzeroUnverified } ?? .absent }
        func gatewayMode(_ value: Int?) -> ModeEvidence {
            switch value { case nil: return .absent; case 0: return .zero; case 1: return .nearby; case 2: return .specifiedGateway; default: return .nonzeroUnverified }
        }
        let modes = ["gmtls": mode(network.clientCert?.gmtls), "versionType": mode(network.clientCert?.versionType),
                     "portHideEnable": mode(network.portHideEnable), "clientModeSwitch": mode(network.clientFlowRedirect?.clientModeSwitch),
                     "ipv6DnsResolve": mode(network.ipv6DnsResolve),
                     "selectedAccessMode": gatewayMode((network.priorServers?.first ?? network.alternateServers?.first)?.accessMode)]
        var switches: [String: Bool] = [:]
        switches["clientCert.enable"] = network.clientCert?.enable
        switches["clientCert.inner"] = network.clientCert?.inner
        switches["clientCert.spaSwitch"] = network.clientCert?.spaSwitch
        let present = [
            "clientConf": !(network.clientConf ?? "").isEmpty,
            "clientFlowRedirect.caCert": !(network.clientFlowRedirect?.caCert ?? "").isEmpty,
            "priorServers": !(network.priorServers ?? []).isEmpty,
            "alternateServers": !(network.alternateServers ?? []).isEmpty,
            "clientCert.caCert": !(network.clientCert?.caCert ?? "").isEmpty,
            "clientCert.signCert": !(network.clientCert?.signCert ?? "").isEmpty,
            "clientCert.signPrivateKey": !(network.clientCert?.signPrivateKey ?? "").isEmpty,
            "clientCert.encryptCert": !(network.clientCert?.encryptCert ?? "").isEmpty,
            "clientCert.encryptPrivateKey": !(network.clientCert?.encryptPrivateKey ?? "").isEmpty
        ]
        let analysis = analyzeDirectives(network.clientConf)
        return Self(network: network, serverScope: serverScope, accessTokenBinding: accessToken.map { Data(SHA256.hash(data: Data($0.utf8))) }, receipt: Receipt(fieldTypes: types, modes: modes, switches: switches, present: present, template: templateEvidence(network.clientConf), directivePresence: analysis.presence, directiveAnalysisComplete: analysis.complete))
    }
}

public actor BackendNetworkConfigurationAttempt: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private var accessToken: String?
    private let input: BackendNetworkInput
    private let sessionUsername: String?
    private let identityDirectory: URL?
    private init(accessToken: String, input: BackendNetworkInput, sessionUsername: String?,
                 identityDirectory: URL? = nil) {
        self.accessToken = accessToken
        self.input = input
        self.sessionUsername = sessionUsername
        self.identityDirectory = identityDirectory
    }
    public nonisolated var description: String { "BackendNetworkConfigurationAttempt(redacted; single attempt)" }
    public nonisolated var debugDescription: String { description }
    public nonisolated var customMirror: Mirror { Mirror(self, children: ["request": "redacted"]) }
    public static func prepare(from session: BackendAuthenticationSession, nowMilliseconds: Int64,
                               input: BackendNetworkInput, identityDirectory: URL? = nil) throws -> BackendNetworkConfigurationAttempt {
        let username = session.identity?.username
        return try session.withAccessToken(nowMilliseconds: nowMilliseconds) {
            BackendNetworkConfigurationAttempt(accessToken: $0, input: input, sessionUsername: username,
                                               identityDirectory: identityDirectory)
        }
    }
    public func perform() async throws -> BackendNetworkConfiguration {
        try await performCollectingResources().configuration
    }

    /// Unit 5: the same authenticated round trip, additionally collecting the
    /// workbench quick-access resources (getApplications with the vpn token).
    /// Resource collection is fail-soft: a failure records the reason and
    /// never blocks the configuration itself.
    public func performCollectingResources() async throws -> (configuration: BackendNetworkConfiguration, resources: WorkbenchResourceCollection) {
        guard let token = accessToken else { throw BackendSessionError.unavailable }
        accessToken = nil
        try Task.checkCancellation()
        let material = try BackendPublicMaterial.production()
        let scope = try BackendPublicEnvelope.serverScope(material: material, timestamp: String(Int64(Date().timeIntervalSince1970 * 1000)))
        let data = try await BackendDiscovery.request(material: material, operation: .networkConfig, payload: input.payload,
                                                      accessToken: token, serverScope: scope)
        try Task.checkCancellation()
        let configuration = try BackendNetworkConfiguration.parse(data, serverScope: scope, accessToken: token)
        let collection = await Self.collectResources(
            material: material, accessToken: token, serverScope: scope,
            org: input.org, username: input.username ?? sessionUsername,
            deviceId: input.deviceId ?? (identityDirectory.flatMap { try? NativeDeviceIdentity.loadOrCreate(directory: $0).value })
        )
        return (configuration, collection)
    }

    public func collectResources() async -> WorkbenchResourceCollection {
        guard let token = accessToken else {
            var collection = WorkbenchResourceCollection()
            collection.failure = "session-unavailable"
            return collection
        }
        accessToken = nil
        let material = try? BackendPublicMaterial.production()
        let scope = material.flatMap {
            try? BackendPublicEnvelope.serverScope(material: $0, timestamp: String(Int64(Date().timeIntervalSince1970 * 1000)))
        }
        return await Self.collectResources(
            material: material, accessToken: token, serverScope: scope,
            org: input.org, username: input.username ?? sessionUsername,
            deviceId: input.deviceId ?? (identityDirectory.flatMap { try? NativeDeviceIdentity.loadOrCreate(directory: $0).value })
        )
    }

    public static func collectResources(
        material: BackendPublicMaterial? = nil,
        accessToken: String,
        serverScope: String? = nil,
        org: String = "szu",
        username: String?,
        deviceId: String?
    ) async -> WorkbenchResourceCollection {
        var collection = WorkbenchResourceCollection()
        guard let username, let deviceId,
              (1...64).contains(org.utf8.count), (1...64).contains(username.utf8.count),
              (1...128).contains(deviceId.utf8.count) else {
            collection.failure = "missing-identity-fields"
            return collection
        }
        do {
            let resolvedMaterial = try material ?? BackendPublicMaterial.production()
            collection.resources = try await BackendResources.fetch(
                material: resolvedMaterial, accessToken: accessToken,
                org: org, username: username, deviceId: deviceId, system: "3",
                serverScope: serverScope
            )
        } catch let error as BackendResourcesError {
            collection.failure = String(describing: error)
        } catch {
            collection.failure = "unavailable"
        }
        return collection
    }
}

/// Unit 5 workbench resource collection outcome for the session report.
/// Names and URLs only; no session tokens or credentials.
public struct WorkbenchResourceCollection: Sendable, CustomStringConvertible {
    public var resources: [BackendUrlResource] = []
    public var failure: String?

    public init() {}
    public var description: String { "WorkbenchResourceCollection(redacted; \(resources.count) named entries)" }
}
