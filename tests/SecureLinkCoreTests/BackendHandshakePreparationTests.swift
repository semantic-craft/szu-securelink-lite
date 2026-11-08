import Foundation
import Security
import XCTest
@testable import SecureLinkCore
@testable import SecureLinkTransport

final class BackendHandshakePreparationTests: XCTestCase {
    private let token = "RAW-TOKEN-SENTINEL"
    private var scope: String { Data(repeating: 7, count: 256).base64EncodedString() }
    private var profile: NativeDeviceProfile {
        NativeDeviceProfile(deviceID: "native-fixture", deviceName: "fixture", deviceModel: "fixture",
                            systemModel: "macOS fixture", architecture: "arm64", deviceMac: "-", serialNumber: "fixture")
    }
    private func session(metadata: Bool = true) throws -> BackendAuthenticationSession {
        var content: [String: Any] = ["creditFlag": 1, "username": "fixture-user", "loginMessage": [
            "accessToken": token, "accessTokenExpire": 5000, "refreshToken": "REFRESH-SENTINEL", "refreshTokenExpire": 6000]]
        if metadata { content["terminalUserId"] = 42; content["authTypeInternal"] = 7 }
        let session = BackendAuthenticationSession(); session.begin()
        session.receive(try JSONSerialization.data(withJSONObject: ["returnCode": 1, "content": content]), nowMilliseconds: 1000)
        return session
    }
    private func configuration(_ updates: [String: Any] = [:], scope: String? = nil, bound: Bool = true) throws -> BackendNetworkConfiguration {
        var network: [String: Any] = ["clientConf": "client\nproto udp\nauth-user-pass\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n", "portHideEnable": 0,
            "priorServers": [["ip": "192.0.2.1", "ports": [443, 444], "accessMode": 1]]]
        network.merge(updates) { _, new in new }
        let data = try JSONSerialization.data(withJSONObject: ["returnCode": 1, "content": ["networkConfig": network]])
        return try BackendNetworkConfiguration.parse(data, serverScope: bound ? (scope ?? self.scope) : nil, accessToken: bound ? token : nil)
    }
    private func prepare(_ configuration: BackendNetworkConfiguration, session: BackendAuthenticationSession? = nil, now: Int64 = 1000) throws -> OpenVPNHandshakeInput {
        try BackendHandshakePreparation.prepare(session: session ?? self.session(), configuration: configuration,
                                                profile: profile, locale: "en_GB", nowMilliseconds: now)
    }
    func testPreparationUsesRawCodeScopeAndExactMetadataThroughPrivatePipe() async throws {
        let input = try prepare(configuration())
        var rendered = ""; dump(input, to: &rendered)
        XCTAssertFalse(rendered.contains(token)); XCTAssertFalse(rendered.contains(scope))
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("fixture.py")
        let script = #"""
        #!/usr/bin/env python3
        import base64, json, sys
        value = json.load(sys.stdin)
        text = value['config']
        scope = base64.b64encode(bytes([7])*256).decode()
        expected = ['remote 192.0.2.1 443', 'remote 192.0.2.1 444', 'proto udp', 'push-peer-info',
                    'setenv UV_ENCPASS 1', 'setenv UV_AUTH_TYPE 2', 'setenv UV_USERID 42',
                    'setenv UV_DEVICEID native-fixture', 'setenv UV_SL_VERSION 3.11.1', 'setenv UV_VERSION 3.11.1',
                    'setenv UV_LOCALE en_GB',
                    'setenv UV_EXTRA_PARAM_1 '+base64.b64encode(b'{"system":3}').decode(),
                    'setenv UV_EXTRA_PARAM_2 '+base64.b64encode(b'{"authType":7}').decode()]
        valid = (all(line in text.splitlines() for line in expected)
                 and 'RAW-TOKEN-SENTINEL' not in text and 'setenv UV_CODE' not in text
                 and 'UV_EXTRA_PARAM_3' not in text and 'UV_EXTRA_PARAM_4' not in text and 'UV_EXTRA_PARAM_5' not in text
                 and value['peerInfo'] == {'UV_CODE':'RAW-TOKEN-SENTINEL','UV_SL_SERVERTYPE':scope}
                 and 'setenv UV_SL_SERVERTYPE' not in text
                 and value['username'] == 'fixture-user' and value['password'] == '-')
        result = dict(mode='bounded-handshake-probe', reason='input-validated' if valid else 'invalid-input', events=[])
        result.update({key:False for key in ['connectCalled','socketObserved','tunnelSetupRequested','tunnelStarted','connected','routesChanged','dnsChanged','deadlineReached','unexpectedConnected','eventsDropped','vendorConfusion','clientCertificateSuppressed','activeShapingNotExercised','gmsslRenegotiationNotExercised']})
        print(json.dumps(result))
        sys.exit(0 if valid else 3)
        """#
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let receipt = try await OpenVPNHandshake.perform(input, executable: executable)
        XCTAssertEqual(receipt.reason, "input-validated")
        XCTAssertFalse(receipt.connectCalled)
    }
    func testUnavailableOrExpiredIdentityAndScopeCannotPrepare() throws {
        let config = try configuration()
        XCTAssertThrowsError(try prepare(config, session: session(metadata: false)))
        XCTAssertThrowsError(try prepare(config, now: 5000))
        let cancelled = try session(); cancelled.cancel()
        XCTAssertThrowsError(try prepare(config, session: cancelled))
        XCTAssertThrowsError(try prepare(configuration(bound: false)))
        XCTAssertThrowsError(try prepare(configuration(scope: "SECRET-invalid\n")))
        let other = try BackendNetworkConfiguration.parse(JSONSerialization.data(withJSONObject: ["returnCode": 1, "content": ["networkConfig": [:]]]), serverScope: scope, accessToken: "OTHER")
        XCTAssertThrowsError(try prepare(other))
    }
    func testUnsupportedModesAndUnsafeCandidatesAreRejected() throws {
        let changes: [[String: Any]] = [
            ["portHideEnable": 1], ["portHideEnable": NSNull()], ["ipv6DnsResolve": 99],
            ["clientCert": [:]], ["clientCert": ["gmtls": 1]],
            ["clientFlowRedirect": ["clientModeSwitch": 1]],
            ["clientConf": "client\ngmtls\n"], ["clientConf": "client\ntls-proxy\n"],
            ["clientConf": "client\nblack-hole-route\n"], ["clientConf": "client\nSECRET-UNKNOWN value\n"],
            ["clientConf": "client\n<enc_cert>\nSECRET\n</enc_cert>"], ["clientConf": "client\nca /SECRET/path\n"],
            ["clientConf": "client\nhttp-proxy SECRET 443\n"], ["clientConf": "client\nup /SECRET/script\n"], ["clientConf": "client%ZZ"],
            ["clientConf": "client\nsetenv opt gmtls\n"], ["clientConf": "client\n<connection>\ngmtls\n</connection>"],
            ["priorServers": [["ip": "192.0.2.1\nINJECT", "ports": [443]]]],
            ["priorServers": [["ip": "192.0.2.1", "ports": [0]]]],
            ["priorServers": [["ip": "192.0.2.1", "ports": [443], "accessMode": 99]]]
        ]
        for change in changes { XCTAssertThrowsError(try prepare(configuration(change))) }
        for mode in [0, 1, 2] {
            XCTAssertNoThrow(try prepare(configuration(["priorServers": [["ip": "192.0.2.1", "ports": [443], "accessMode": mode]]])))
        }
        XCTAssertNoThrow(try prepare(configuration(["priorServers": [], "alternateServers": [["ip": "2001:db8::1", "ports": [443]]]])))
    }
    func testAdmissionWhitelistReportsOnlyFixedCategories() throws {
        let trusted = "client\nproto udp\nauth-user-pass\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        let cases: [(String, String)] = [
            ("SECRET-UNKNOWN x", "unsupportedDirective"), ("ca /SECRET/path", "externalReference"),
            ("up /SECRET/script", "externalReference"), ("http-proxy SECRET 443", "externalReference"),
            ("<sign_cert>\nSECRET\n</sign_cert>", "unsupportedInlineMaterial"),
            ("remote 192.0.2.99 443", "invalidConfiguration")
        ]
        for (suffix, category) in cases {
            XCTAssertThrowsError(try prepare(configuration(["clientConf": trusted + suffix]))) { error in
                XCTAssertEqual(String(describing: error), category)
                XCTAssertFalse(String(reflecting: error).contains("SECRET"))
            }
        }
        XCTAssertThrowsError(try prepare(configuration(["clientConf": "client\nproto udp\n"])))
        XCTAssertEqual(try configuration().receipt.modes["selectedAccessMode"], .nearby)
    }
    func testPublicEntryRejectsMissingMetadataBeforeReadingArtifactsOrHardware() throws {
        XCTAssertThrowsError(try BackendHandshakePreparation.prepare(session: session(metadata: false), configuration: configuration(),
                             identityDirectory: URL(fileURLWithPath: "/nonexistent-fixture-identity"), nowMilliseconds: 1000)) { error in
            guard case BackendSessionError.handshakeMetadataUnavailable = error else { return XCTFail("Identity must be checked before artifact access") }
        }
    }
    func testActualSourceHelperOnlyValidatesPreparedSyntheticInput() async throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let executable = root.appendingPathComponent("out/openvpn3/build/szu-openvpn3-handshake")
        guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw XCTSkip("Source helper not built") }
        let receipt = try await OpenVPNHandshake.perform(prepare(configuration()), executable: executable)
        XCTAssertEqual(receipt.reason, "input-validated")
        XCTAssertFalse(receipt.connectCalled); XCTAssertFalse(receipt.socketObserved)
        let trust = "\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        let positive = try configuration(["clientConf": "client\nproto tcp" + trust + "enable-confusion-proto 1\nshaper 100\ntls-reneg-sec 60\nignore-unknown-option enable-confusion-proto"])
        let probe = try await OpenVPNHandshake.perform(prepare(positive), executable: executable)
        XCTAssertEqual(probe.reason, "input-validated")
        XCTAssertTrue(probe.vendorConfusion); XCTAssertTrue(probe.clientCertificateSuppressed)
        XCTAssertTrue(probe.activeShapingNotExercised); XCTAssertTrue(probe.gmsslRenegotiationNotExercised)
        XCTAssertFalse(probe.connectCalled); XCTAssertFalse(probe.socketObserved)
    }
    func testExplicitScopeIsReusedAndForbiddenOnOtherEndpoints() throws {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048, kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]]
        let key = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
        let der = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil)) as Data
        let material = BackendPublicMaterial(publicDER: der, iv: Data(repeating: 1, count: 16), certID: "fixture", locale: "en_GB", emptyPasswordEnvelope: "fixture")
        let request = try BackendDiscovery.preparedRequest(material: material, operation: .networkConfig, payload: ["system": 3], key: Data(repeating: 2, count: 16), timestamp: "1000", nonce: "fixture", credential: nil, accessToken: token, serverScope: scope)
        XCTAssertEqual(request.value(forHTTPHeaderField: "SlServerType"), scope)
        XCTAssertThrowsError(try BackendDiscovery.preparedRequest(material: material, operation: .logout, payload: [:], key: Data(repeating: 2, count: 16), timestamp: "1000", nonce: "fixture", credential: nil, accessToken: token, serverScope: scope))
    }
    func testModeFailuresExposeFixedSpecificCategories() throws {
        let cases: [([String: Any], String)] = [
            (["portHideEnable": 1], "unsupportedPortHiding"),
            (["ipv6DnsResolve": 1], "unsupportedIPv6DNS"),
            (["clientFlowRedirect": ["clientModeSwitch": 1, "caCert": "SECRET"]], "unsupportedFlowRedirection"),
            (["clientFlowRedirect": ["caCert": "SECRET"]], "unsupportedFlowRedirection"),
            (["appaAccConf": ["host": "SECRET"]], "unsupportedAcceleration"),
            (["clientCert": [:]], "unsupportedTLSProfile"),
            (["priorServers": [["ip": "192.0.2.1", "ports": [443], "accessMode": 99]]], "unsupportedGatewaySelection"),
            (["clientConf": "proto SECRET"], "unsupportedProtocol"),
            (["clientConf": "dev tap"], "unsupportedDeviceType"),
            (["clientConf": "remote-cert-tls client"], "unsupportedTLSProfile"),
            (["clientConf": "tls-cert-profile SECRET"], "unsupportedTLSProfile")
        ]
        for (fields, category) in cases {
            XCTAssertThrowsError(try prepare(configuration(fields))) {
                XCTAssertEqual(String(describing: $0), category)
            }
        }
        let disabled = try configuration(["clientFlowRedirect": ["clientModeSwitch": 0, "caCert": "SECRET-INACTIVE-CA"]])
        XCTAssertNoThrow(try prepare(disabled))
        XCTAssertEqual(disabled.receipt.present["clientFlowRedirect.caCert"], true)
        let receipt = String(decoding: try JSONEncoder().encode(disabled.receipt), as: UTF8.self)
        XCTAssertFalse(receipt.contains("SECRET"))
        for (value, expected) in [(0, BackendNetworkConfiguration.ModeEvidence.zero), (1, .nearby), (2, .specifiedGateway), (99, .nonzeroUnverified)] {
            XCTAssertEqual(try configuration(["priorServers": [["ip": "192.0.2.1", "ports": [443], "accessMode": value]]]).receipt.modes["selectedAccessMode"], expected)
        }
    }
    func testTemplateDiagnosticsNeverExposeUnknownNamesArgumentsOrInlineContents() throws {
        let text = "# proto udp\n  proto tcp\ndev tun\n<ca>\nSECRET-CA\nproto udp\n</ca>\n<cert>\nSECRET-CERT\n</cert>\n<key>\nSECRET-KEY\n</key>\nSECRET-DIRECTIVE SECRET-ARG\n"
        let escaped = try XCTUnwrap(text.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        for input in [text, escaped] {
            let evidence = BackendNetworkConfiguration.templateEvidence(input)
            XCTAssertEqual(evidence["proto"], "tcp")
            XCTAssertEqual(evidence["dev"], "tun")
            XCTAssertEqual(evidence["inline.ca"], "true")
            XCTAssertEqual(evidence["inline.cert"], "true")
            XCTAssertEqual(evidence["inline.key"], "true")
            XCTAssertEqual(evidence["unknownDirectiveCount"], "1")
            XCTAssertEqual(evidence["directive.proto"], "true")
            XCTAssertFalse(String(describing: evidence).contains("SECRET"))
        }
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("proto SECRET")["proto"], "unknown")
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("proto udp\nproto tcp")["proto"], "multiple")
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("proto%ZZ")["analysisComplete"], "false")
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence(String(repeating: "SECRET x\n", count: 101))["unknownDirectiveCount"], "100")
    }

    func testStandardTCPClientAliasesPreserveProtocolWithoutEnablingServerModes() throws {
        let trust = "\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        for proto in ["tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client", "udp", "udp4", "udp6"] {
            let config = try configuration(["clientConf": "client\nproto " + proto + trust])
            XCTAssertNoThrow(try prepare(config))
            XCTAssertEqual(config.receipt.template["proto"], proto)
        }
        for proto in ["tcp-server", "tcp4-server", "tcp6-server", "tls", "SECRET"] {
            XCTAssertThrowsError(try prepare(configuration(["clientConf": "client\nproto " + proto + trust]))) {
                guard case BackendHandshakePreparationError.unsupportedProtocol = $0 else { return XCTFail("Expected unsupported client transport") }
            }
        }
    }

    func testTLSClientAndBoundedResolverRetryAdmission() throws {
        let base = "tls-client\npull\nproto udp\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        for value in ["infinite", "0", "10", "0001"] {
            let config = try configuration(["clientConf": base + "resolv-retry " + value])
            XCTAssertNoThrow(try prepare(config))
            XCTAssertEqual(config.receipt.template["directive.tls-client"], "true")
            XCTAssertEqual(config.receipt.template["directive.resolv-retry"], "true")
            XCTAssertEqual(config.receipt.template["resolvRetryBehavior"], "engineIgnored")
        }
        for value in ["", "SECRET", "-1", "%2B1", "1.5", "infinite extra", "9999999999999999999999999999999999"] {
            let config = try configuration(["clientConf": base + "resolv-retry " + value])
            XCTAssertThrowsError(try prepare(config))
            XCTAssertEqual(config.receipt.template["resolvRetryBehavior"], "invalid")
            XCTAssertFalse(String(describing: config.receipt.template).contains("SECRET"))
        }
        XCTAssertThrowsError(try prepare(configuration(["clientConf": base + "tls-client extra"])))
        XCTAssertThrowsError(try prepare(configuration(["clientConf": base + "keepalive 10 60"])))
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence(base)["resolvRetryBehavior"], "absent")
    }

    func testExpandedDiagnosticVocabularyDoesNotExpandAdmission() throws {
        let base = "client\nproto udp\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        for name in ["auth-retry", "tls-exit", "comp-lzo", "fast-io", "key-method", "ns-cert-type", "keepalive", "tls-server", "management", "no-replay"] {
            let config = try configuration(["clientConf": base + name + " SECRET-ARG"])
            XCTAssertEqual(config.receipt.template["directive." + name], "true")
            XCTAssertEqual(config.receipt.template["unknownDirectiveCount"], "0")
            XCTAssertThrowsError(try prepare(config), "Diagnostic recognition never permits an option")
            XCTAssertFalse(String(describing: config.receipt.template).contains("SECRET"))
        }
        let vocabulary = BackendOpenVPNDiagnosticOptions.names
        XCTAssertEqual(vocabulary.count, 243)
        let evidence = BackendNetworkConfiguration.templateEvidence(vocabulary.sorted().joined(separator: "\n"))
        for name in vocabulary { XCTAssertEqual(evidence["directive." + name], "true") }
        XCTAssertEqual(evidence["unknownDirectiveCount"], "0")
        let unknown = BackendNetworkConfiguration.templateEvidence("auth-retry-SECRET SECRET\nSECRET-OPTION SECRET")
        XCTAssertEqual(unknown["unknownDirectiveCount"], "2")
        XCTAssertFalse(String(describing: unknown).contains("SECRET"))
        let inline = BackendNetworkConfiguration.templateEvidence("<ca>\nfast-io\nauth-retry SECRET\n</ca>")
        XCTAssertEqual(inline["directive.fast-io"], "false")
        XCTAssertEqual(inline["directive.auth-retry"], "false")
    }

    func testIgnoredOptionAndShaperDiagnosticsAreValueFreeAndDoNotPermitExecution() throws {
        let base = "client\nproto udp\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        let config = try configuration(["clientConf": base + "ignore-unknown-option shaper auth-retry SECRET\nshaper 12345"])
        XCTAssertEqual(config.receipt.template["ignoreUnknownOption.knownArguments"], "auth-retry,shaper")
        XCTAssertEqual(config.receipt.template["ignoreUnknownOption.unknownArgumentCount"], "1")
        XCTAssertEqual(config.receipt.template["shaper.argumentCount"], "1")
        XCTAssertEqual(config.receipt.template["shaper.argumentShape"], "positive")
        let diagnostic = String(describing: config.receipt.template)
        XCTAssertFalse(diagnostic.contains("SECRET"))
        XCTAssertFalse(diagnostic.contains("12345"))
        XCTAssertThrowsError(try prepare(config))
        for value in ["", "1.5", "SECRET", "1 2", "99999999999999999999999999"] {
            XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("shaper " + value)["shaper.argumentShape"], "invalid")
        }
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("shaper 0")["shaper.argumentShape"], "zero")
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("shaper -1")["shaper.argumentShape"], "negative")
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("shaper 1\nshaper 2")["shaper.argumentShape"], "multiple")
        let escaped = BackendNetworkConfiguration.templateEvidence("ignore-unknown-option \"shaper\" SECRET")
        XCTAssertEqual(escaped["ignoreUnknownOption.argumentAnalysisComplete"], "false")
        XCTAssertEqual(escaped["ignoreUnknownOption.knownArguments"], "")
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("ignore-unknown-option " + String(repeating: "SECRET ", count: 101))["ignoreUnknownOption.unknownArgumentCount"], "100")
        let inline = BackendNetworkConfiguration.templateEvidence("<ca>\nignore-unknown-option shaper\nshaper 12345\n</ca>")
        XCTAssertEqual(inline["ignoreUnknownOption.knownArguments"], "")
        XCTAssertEqual(inline["shaper.argumentShape"], "absent")
    }

    func testVendorCandidateShapesNeverAuthorizeUnknownSemantics() throws {
        let base = "client\nproto udp\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        for name in BackendOpenVPNDiagnosticOptions.vendorNames {
            let numeric = ["tls-reneg-sec", "tls-reneg-bytes"].contains(name)
            for (suffix, flagShape) in [("", "noArgument"), (" 0", "zero"), (" 1", "one"), (" SECRET", "other"), (" 01", "other"), (" 1 2", "other")] {
                let config = try configuration(["clientConf": base + name + suffix])
                let integer = [" 0", " 1", " 01"].contains(suffix)
                let signedSwitch = ["disable-set-dns", "enable-confusion-proto"].contains(name)
                let signShape = suffix == " 0" ? "zero" : (suffix == " 1" || suffix == " 01" ? "positive" : flagShape)
                XCTAssertEqual(config.receipt.template["vendorArgumentShape." + name], numeric ? (integer ? "nonnegativeInteger" : "other") : (signedSwitch ? signShape : flagShape))
                XCTAssertEqual(config.receipt.template["directive." + name], "true")
                XCTAssertEqual(config.receipt.template["unknownDirectiveCount"], "0")
                XCTAssertFalse(String(describing: config.receipt.template).contains("SECRET"))
                if signedSwitch && suffix == " 0" { XCTAssertNoThrow(try prepare(config)) }
                else { XCTAssertThrowsError(try prepare(config)) }
            }
            XCTAssertEqual(BackendNetworkConfiguration.templateEvidence(base)["vendorArgumentShape." + name], "absent")
        }
        XCTAssertEqual(BackendNetworkConfiguration.templateEvidence("enable-confusion-proto 0\nenable-confusion-proto 0")["vendorArgumentShape.enable-confusion-proto"], "other")
        for name in ["disable-set-dns", "enable-confusion-proto"] {
            XCTAssertEqual(BackendNetworkConfiguration.templateEvidence(name + " -2")["vendorArgumentShape." + name], "negative")
            XCTAssertEqual(BackendNetworkConfiguration.templateEvidence(name + " 2")["vendorArgumentShape." + name], "positive")
        }
        let inline = BackendNetworkConfiguration.templateEvidence("<sign_cert>\nSECRET\n</sign_cert>")
        XCTAssertEqual(inline["inline.sign_cert"], "true")
        XCTAssertFalse(String(describing: inline).contains("SECRET"))
    }

    func testOnlyExplicitSingleInactiveVendorValuesAndBoundIgnoreNamesAreAdmitted() throws {
        let base = "client\nproto udp\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        let inactive = "shaper 0\nenable-confusion-proto 0\ndisable-set-dns 0\n"
        for suffix in [inactive, "ignore-unknown-option shaper enable-confusion-proto disable-set-dns\n" + inactive,
                       inactive + "ignore-unknown-option enable-confusion-proto disable-set-dns"] {
            let config = try configuration(["clientConf": base + suffix])
            XCTAssertNoThrow(try prepare(config))
            XCTAssertEqual(config.receipt.vendorOptionCompatibility, "no-tun-probe-only-tcp-confusion")
            XCTAssertFalse(config.receipt.vendorActiveFeaturesImplemented)
            try config.withHandshakeProbeCandidate(accessToken: token) { text, _, _, _ in
                XCTAssertTrue(text.contains(suffix), "Original options are preserved for engine evaluation")
            }
        }
        for name in ["shaper", "enable-confusion-proto", "disable-set-dns"] {
            for value in ["", " 1", " -1", " -0", " 00", " 0 0", " SECRET", " 0\n" + name + " 0"] {
                XCTAssertThrowsError(try prepare(configuration(["clientConf": base + name + value])))
            }
            XCTAssertThrowsError(try prepare(configuration(["clientConf": base + "ignore-unknown-option " + name])))
        }
        for invalid in ["ignore-unknown-option", "ignore-unknown-option SECRET", "ignore-unknown-option auth-retry",
                        "ignore-unknown-option shaper shaper", "ignore-unknown-option shaper\nignore-unknown-option shaper",
                        "ignore-unknown-option shaper SECRET", "ignore-unknown-option \"shaper\""] {
            XCTAssertThrowsError(try prepare(configuration(["clientConf": base + inactive + invalid])))
        }
        XCTAssertThrowsError(try prepare(configuration(["clientConf": base + inactive + "ignore-unknown-option shaper\nSECRET 0"])))
        XCTAssertThrowsError(try prepare(configuration(["clientConf": base + "ignore-unknown-option shaper\n<ca>\nshaper 0\n</ca>"])))
    }

    func testPositiveConfusionRequiresExplicitSingleTCPAndRetainsTrustAndVendorGates() throws {
        let trust = "\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        for proto in ["tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client"] {
            for value in ["1", "2", "2147483647"] {
                let config = try configuration(["clientConf": "client\nproto " + proto + trust + "enable-confusion-proto " + value + "\nignore-unknown-option enable-confusion-proto"])
                XCTAssertNoThrow(try prepare(config))
                try config.withHandshakeProbeCandidate(accessToken: token) { _, _, _, enabled in XCTAssertTrue(enabled.vendorConfusion) }
            }
        }
        for suffix in ["proto udp", "proto udp4", "proto tcp\nproto tcp", "proto tcp\nproto udp", "proto tcp-server"] {
            XCTAssertThrowsError(try prepare(configuration(["clientConf": "client\n" + suffix + trust + "enable-confusion-proto 1"])))
        }
        for bad in ["-1", "2147483648", "1.0", "SECRET", "", "1\nenable-confusion-proto 1"] {
            XCTAssertThrowsError(try prepare(configuration(["clientConf": "client\nproto tcp" + trust + "enable-confusion-proto " + bad])))
        }
        for extra in ["gmtls", "tls-proxy", "ignore-unknown-option SECRET", "ignore-unknown-option shaper"] {
            XCTAssertThrowsError(try prepare(configuration(["clientConf": "client\nproto tcp" + trust + "enable-confusion-proto 1\n" + extra])))
        }
        XCTAssertThrowsError(try prepare(configuration(["clientConf": "client\nproto tcp\nenable-confusion-proto 1"])))
        try configuration().withHandshakeProbeCandidate(accessToken: token) { _, _, _, enabled in XCTAssertFalse(enabled.vendorConfusion) }
    }

    func testNoTUNProbeDeclaresUnexercisedShapingAndGMSSLTimerWithoutRemapping() throws {
        let trust = "\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        for value in ["0", "1", "2147483647"] {
            let original = "client\nproto tcp" + trust + "shaper " + value + "\ntls-reneg-sec " + value + "\nreneg-sec 60\n"
            let config = try configuration(["clientConf": original])
            XCTAssertNoThrow(try prepare(config))
            try config.withHandshakeProbeCandidate(accessToken: token) { text, _, _, options in
                XCTAssertEqual(options.activeShapingNotExercised, value != "0")
                XCTAssertTrue(options.gmsslRenegotiationNotExercised)
                XCTAssertFalse(options.vendorConfusion)
                XCTAssertTrue(text.contains("shaper " + value + "\n"))
                XCTAssertTrue(text.contains("reneg-sec 60\n"))
                XCTAssertFalse(text.contains("tls-reneg-sec " + value))
            }
        }
        let all = "client\nproto tcp" + trust + "enable-confusion-proto 1\nshaper 100\ntls-reneg-sec 60\nignore-unknown-option enable-confusion-proto shaper tls-reneg-sec"
        XCTAssertNoThrow(try prepare(configuration(["clientConf": all])))
        for name in ["shaper", "tls-reneg-sec"] {
            for value in ["-1", "2147483648", "", "1.5", "SECRET", "1\n" + name + " 1"] {
                XCTAssertThrowsError(try prepare(configuration(["clientConf": "client\nproto tcp" + trust + name + " " + value])))
            }
            for proto in ["udp", "udp6", "tcp-server"] {
                XCTAssertThrowsError(try prepare(configuration(["clientConf": "client\nproto " + proto + trust + name + " 1"])))
            }
        }
        for bad in ["tls-proxy", "gmtls", "http-proxy SECRET 443", "ignore-unknown-option SECRET", "ignore-unknown-option tls-reneg-sec tls-reneg-sec"] {
            XCTAssertThrowsError(try prepare(configuration(["clientConf": all + "\n" + bad])))
        }
        let inline = try configuration(["clientConf": "client\nproto tcp\n<ca>\ntls-reneg-sec 999\n</ca>\ntls-reneg-sec 60\n"])
        try inline.withHandshakeProbeCandidate(accessToken: token) { text, _, _, _ in
            XCTAssertTrue(text.contains("<ca>\ntls-reneg-sec 999\n</ca>"))
            XCTAssertFalse(text.contains("tls-reneg-sec 60"))
        }
    }

    func testProbeOnlyFlagsAndFilteredConfigurationReachHelperThroughPrivatePipe() async throws {
        let trust = "\npeer-fingerprint " + Array(repeating: "00", count: 32).joined(separator: ":") + "\n"
        let config = try configuration(["clientConf": "client\nproto tcp" + trust + "enable-confusion-proto 1\nshaper 100\ntls-reneg-sec 60\nreneg-sec 90\nignore-unknown-option enable-confusion-proto"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let helper = directory.appendingPathComponent("fixture.py")
        let script = #"""
        #!/usr/bin/env python3
        import json,sys
        value=json.load(sys.stdin)
        valid=(value['vendorConfusion'] is True and value['activeShapingNotExercised'] is True
               and value['gmsslRenegotiationNotExercised'] is True
               and 'tls-reneg-sec' not in value['config'] and 'reneg-sec 90' in value['config']
               and 'shaper 100' in value['config'])
        result=dict(mode='bounded-handshake-probe',reason='input-validated' if valid else 'invalid-input',events=[])
        result.update({key:False for key in ['connectCalled','socketObserved','tunnelSetupRequested','tunnelStarted','connected','routesChanged','dnsChanged','deadlineReached','unexpectedConnected','eventsDropped']})
        result.update({key:True for key in ['vendorConfusion','clientCertificateSuppressed','activeShapingNotExercised','gmsslRenegotiationNotExercised']})
        print(json.dumps(result))
        sys.exit(0 if valid else 3)
        """#
        try Data(script.utf8).write(to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        let receipt = try await OpenVPNHandshake.perform(prepare(config), executable: helper)
        XCTAssertEqual(receipt.reason, "input-validated")
        XCTAssertTrue(receipt.vendorConfusion)
        XCTAssertTrue(receipt.activeShapingNotExercised)
        XCTAssertTrue(receipt.gmsslRenegotiationNotExercised)
        XCTAssertFalse(receipt.connectCalled)
    }

}
