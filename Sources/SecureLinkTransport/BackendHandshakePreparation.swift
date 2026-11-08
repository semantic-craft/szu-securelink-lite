import Foundation
import SecureLinkCore

public enum BackendHandshakePreparationError: Error {
    case unboundConfiguration, unsupportedMode, invalidConfiguration, unavailableMetadata, metadataBudget
    case unsupportedDirective, unsupportedInlineMaterial, externalReference
    case unsupportedPortHiding, unsupportedFlowRedirection, unsupportedGatewaySelection
    case unsupportedProtocol, unsupportedDeviceType, unsupportedTLSProfile, unsupportedIPv6DNS, unsupportedAcceleration
}

public enum BackendHandshakePreparation {
    /// Prepares private input exclusively for the no-TUN handshake probe.
    /// Active shaping and GMSSL renegotiation can be declared unexercised here, never implemented.
    /// This does not run the engine or authorize network access, and cannot prepare a working tunnel.
    public static func prepare(session: BackendAuthenticationSession, configuration: BackendNetworkConfiguration,
                               identityDirectory: URL, nowMilliseconds: Int64) throws -> OpenVPNHandshakeInput {
        try session.withHandshakeIdentity(nowMilliseconds: nowMilliseconds) { _, _, _ in
            let material = try BackendPublicMaterial.production()
            let profile = try NativeDeviceProfile.collect(directory: identityDirectory)
            return try prepare(session: session, configuration: configuration, profile: profile,
                               locale: material.locale, nowMilliseconds: nowMilliseconds)
        }
    }

    static func prepare(session: BackendAuthenticationSession, configuration: BackendNetworkConfiguration,
                        profile: NativeDeviceProfile, locale: String, nowMilliseconds: Int64) throws -> OpenVPNHandshakeInput {
        try session.withHandshakeIdentity(nowMilliseconds: nowMilliseconds) { username, userID, authType in
            try session.withAccessToken(nowMilliseconds: nowMilliseconds) { token in
                try configuration.withHandshakeProbeCandidate(accessToken: token) { text, ip, scope, options in
                    try build(profile: profile, locale: locale, username: username, userID: userID,
                              authType: authType, token: token, text: text, ip: ip, scope: scope, options: options)
                }
            }
        }
    }

    private static func build(profile: NativeDeviceProfile, locale: String, username: String, userID: Int64,
                              authType: Int, token: String, text: String, ip: String, scope: String, options: BackendNetworkConfiguration.HandshakeProbeOptions) throws -> OpenVPNHandshakeInput {
        let fields = profile.loginFields
        func field(_ key: String) throws -> String {
            guard let value = fields[key] as? String, !value.isEmpty else { throw BackendHandshakePreparationError.unavailableMetadata }
            return value
        }
        func encoded(_ text: String) -> String { Data(text.utf8).base64EncodedString() }
        let version = try field("version")
        guard !locale.isEmpty, let range = version.range(of: #"^[0-9]+.[0-9]+.[0-9]+"#, options: .regularExpression),
              try field("system") == "3", username.rangeOfCharacter(from: .controlCharacters) == nil else {
            throw BackendHandshakePreparationError.unavailableMetadata
        }
        let values: [UVMetadata.Field: String] = [
            .serverType: scope, .encryptedPassword: "1", .deviceID: try field("deviceId"), .authType: "2",
            .locale: locale, .systemBits: try field("systemBits"),
            .extra1: encoded("{\"system\":3}"), .extra2: encoded("{\"authType\":\(authType)}"),
            .userID: String(userID), .secureLinkVersion: version, .version: String(version[range]), .serverIP: ip,
            .systemName: encoded(try field("systemName")), .systemModel: encoded(try field("systemModel")),
            .deviceName: encoded(try field("deviceName")), .deviceModel: encoded(try field("deviceModel"))
        ]
        let metadata = try UVMetadata(vpnInitInfo: String(repeating: "*", count: 280), username: username,
                                      password: "-", openVPNBase: String(repeating: "*", count: 230),
                                      codeForBudget: token, values: values).build()
        let required: Set<UVMetadata.Field> = [.serverType, .encryptedPassword, .deviceID, .authType, .extra1,
                                              .extra2, .userID, .secureLinkVersion, .version, .serverIP]
        guard required.isDisjoint(with: metadata.omittedFields) else { throw BackendHandshakePreparationError.metadataBudget }
        return try metadata.withDirectives { directives in
            let scopeLine = "setenv UV_SL_SERVERTYPE " + scope
            let filtered = directives.split(separator: "\n", omittingEmptySubsequences: false)
                .filter { $0 != scopeLine }.joined(separator: "\n")
            return try OpenVPNHandshakeInput(configuration: text + "\npush-peer-info\n" + filtered,
                                             username: username, password: "-",
                                             peerInfo: ["UV_CODE": token, "UV_SL_SERVERTYPE": scope], vendorConfusion: options.vendorConfusion,
                                             activeShapingNotExercised: options.activeShapingNotExercised,
                                             gmsslRenegotiationNotExercised: options.gmsslRenegotiationNotExercised)
        }
    }
}
