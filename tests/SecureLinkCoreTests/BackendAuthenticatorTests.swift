import Foundation
import Security
import XCTest
@testable import SecureLinkCore
@testable import SecureLinkTransport

private final class FailingAuthenticationProtocol: URLProtocol, @unchecked Sendable {
    final class Attempts: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        func reset() { lock.lock(); defer { lock.unlock() }; value = 0 }
        func increment() { lock.lock(); defer { lock.unlock() }; value += 1 }
        func count() -> Int { lock.lock(); defer { lock.unlock() }; return value }
    }
    static let attempts = Attempts()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.attempts.increment()
        client?.urlProtocol(self, didFailWithError: URLError(.timedOut))
    }
    override func stopLoading() { }
}

final class BackendAuthenticatorTests: XCTestCase {
    private let secret = "SECRET-SENTINEL"
    private func credential() throws -> PendingCASCredential {
        var gate = CASCallbackGate()
        gate.begin()
        return try gate.consume(URL(string: "securelink://sso_login?projectLabel=szu&authToken=" + secret)!)
    }
    private func material() throws -> (BackendPublicMaterial, SecKey) {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048,
                                          kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]]
        let key = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
        let der = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil)) as Data
        let emptyPassword = try SessionCipher(key: Data(repeating: 7, count: 16), iv: Data(repeating: 8, count: 16)).encrypt(Data()).base64EncodedString()
        return (BackendPublicMaterial(publicDER: der, iv: Data(repeating: 9, count: 16), certID: "fixture-id", locale: "zh_CN", emptyPasswordEnvelope: emptyPassword), key)
    }
    private var profile: NativeDeviceProfile {
        NativeDeviceProfile(deviceID: "fixture-native-id", deviceName: "fixture-name", deviceModel: "fixture-model",
                            systemModel: "macOS fixture", architecture: "arm64", deviceMac: "-", serialNumber: "fixture-serial")
    }
    func testProductionRequestHasBearerButNoBodyTokenAndEncryptsEmptyPassword() throws {
        let (material, rsa) = try material()
        let payload = BackendAuthenticator.loginPayload(profile: profile, emptyPasswordEnvelope: material.emptyPasswordEnvelope)
        let key = Data(repeating: 1, count: 16)
        let request = try BackendDiscovery.preparedRequest(material: material, operation: .ssoLogin, payload: payload,
                                                          key: key, timestamp: "1700000000000", nonce: "fixture-nonce", credential: credential())
        XCTAssertEqual(request.url?.absoluteString, "https://sheetaapi.wangsu.com/authApi/is/sso/login?locale=zh_CN")
        XCTAssertNil(request.value(forHTTPHeaderField: "SlServerType"))
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.timeoutInterval, 20)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer " + secret)
        XCTAssertEqual(request.value(forHTTPHeaderField: "apiVersion"), "5.18.0.0")
        let encrypted = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request.httpBody)))
        let plain = try SessionCipher(key: key, iv: material.iv).decrypt(encrypted)
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: plain) as? [String: Any])
        XCTAssertNil(body["authToken"])
        XCTAssertNil(body["username"])
        XCTAssertNil(body["authConfigId"])
        XCTAssertEqual(body["org"] as? String, "szu")
        XCTAssertEqual(body["system"] as? String, "3")
        XCTAssertEqual(body["archType"] as? Int, 11)
        XCTAssertEqual(body["deviceId"] as? String, "fixture-native-id")
        let password = try XCTUnwrap(body["password"] as? String)
        XCTAssertFalse(password.isEmpty)
        XCTAssertEqual(try SessionCipher(key: Data(repeating: 7, count: 16), iv: Data(repeating: 8, count: 16)).decrypt(XCTUnwrap(Data(base64Encoded: password))), Data())
        let wrappedKey = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request.value(forHTTPHeaderField: "secret"))))
        let unwrappedKey = try XCTUnwrap(SecKeyCreateDecryptedData(rsa, .rsaEncryptionPKCS1, wrappedKey as CFData, nil)) as Data
        XCTAssertEqual(unwrappedKey, key)
        XCTAssertFalse(String(decoding: plain, as: UTF8.self).contains(secret))
    }
    func testCredentialCannotBeAttachedToDiscoveryOrOmittedFromSSO() throws {
        let (material, _) = try material()
        XCTAssertThrowsError(try BackendDiscovery.preparedRequest(material: material, operation: .authURL, payload: [:], key: Data(repeating: 1, count: 16), timestamp: "1", nonce: "n", credential: credential()))
        XCTAssertThrowsError(try BackendDiscovery.preparedRequest(material: material, operation: .ssoLogin, payload: [:], key: Data(repeating: 1, count: 16), timestamp: "1", nonce: "n", credential: nil))
    }
    func testFailedAuthenticationRequestMakesOneAttemptAndReturnsFixedError() async throws {
        let (material, _) = try material()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [FailingAuthenticationProtocol.self]
        FailingAuthenticationProtocol.attempts.reset()
        do {
            _ = try await BackendDiscovery.request(material: material, operation: .ssoLogin,
                    payload: BackendAuthenticator.loginPayload(profile: profile, emptyPasswordEnvelope: material.emptyPasswordEnvelope),
                    credential: credential(), configuration: configuration)
            XCTFail("Expected bounded transport failure")
        } catch let error as BackendDiscoveryError {
            guard case .transport = error else { return XCTFail("Expected fixed transport failure") }
            XCTAssertFalse(String(reflecting: error).contains(secret))
        }
        XCTAssertEqual(FailingAuthenticationProtocol.attempts.count(), 1)
    }
    func testPrivateReplyAndCredentialNeverReflectPayloadAndCannotReviveCancelledSession() throws {
        let response = Data("{\"returnCode\":2041,\"content\":{\"tempToken\":\"\(secret)\",\"loginMessage\":{}}}".utf8)
        let reply = BackendAuthenticationReply(response: response)
        let credential = try credential()
        var replyDump = "", credentialDump = ""
        dump(reply, to: &replyDump)
        dump(credential, to: &credentialDump)
        for value in [String(reflecting: reply), replyDump, String(reflecting: credential), credentialDump] {
            XCTAssertFalse(value.contains(secret))
        }
        let session = BackendAuthenticationSession()
        session.begin()
        reply.apply(to: session, nowMilliseconds: 1_700_000_000_000)
        XCTAssertEqual(session.state, .requiresSecondFactor)
        let cancelled = BackendAuthenticationSession()
        cancelled.begin(); cancelled.cancel()
        reply.apply(to: cancelled, nowMilliseconds: 1_700_000_000_000)
        XCTAssertEqual(cancelled.state, .cancelled)
    }
    func testLogoutUsesEmptyJSONStringAndCurrentAccessBearer() throws {
        let (material, _) = try material()
        let key = Data(repeating: 1, count: 16)
        let request = try BackendDiscovery.preparedRequest(material: material, operation: .logout, payload: [:],
                            key: key, timestamp: "1700000000000", nonce: "fixture-nonce", credential: nil, accessToken: secret)
        XCTAssertEqual(request.url?.path, "/authApi/is/logout")
        XCTAssertEqual(request.value(forHTTPHeaderField: "apiVersion"), "4.25.0.0")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer " + secret)
        let encrypted = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request.httpBody)))
        XCTAssertEqual(try SessionCipher(key: key, iv: material.iv).decrypt(encrypted), Data([34, 34]))
        XCTAssertThrowsError(try BackendDiscovery.preparedRequest(material: material, operation: .logout, payload: ["org": "szu"],
                            key: key, timestamp: "1", nonce: "n", credential: nil, accessToken: secret))
    }
    func testLogoutReceiptDiscardsDeviceTokensAndDoesNotClaimRevocation() throws {
        let data = Data("{\"returnCode\":1,\"content\":{\"accessToken\":\"\(secret)\",\"refreshToken\":\"\(secret)\"}}".utf8)
        let receipt = try BackendLogoutAttempt.receipt(data)
        XCTAssertTrue(receipt.userLogoutAccepted)
        XCTAssertTrue(receipt.deviceSessionMayRemain)
        XCTAssertFalse(receipt.serverRevocationVerified)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(receipt), as: UTF8.self).contains(secret))
        XCTAssertFalse(try BackendLogoutAttempt.receipt(Data(#"{"returnCode":2005}"#.utf8)).userLogoutAccepted)
        XCTAssertThrowsError(try BackendLogoutAttempt.receipt(Data(#"{"returnCode":true}"#.utf8)))
    }
    func testLogoutAttemptIsPrivateAndCannotRetryAfterCancellation() async throws {
        let session = BackendAuthenticationSession()
        session.begin()
        let data = try JSONSerialization.data(withJSONObject: ["returnCode": 1, "content": [
            "creditFlag": 1, "username": "fixture", "loginMessage": [
                "accessToken": secret, "accessTokenExpire": 5000, "refreshToken": secret, "refreshTokenExpire": 6000
            ]
        ]])
        session.receive(data, nowMilliseconds: 1000)
        let attempt = try BackendLogoutAttempt.prepare(from: session, nowMilliseconds: 1000)
        session.cancel()
        var rendered = ""
        dump(attempt, to: &rendered)
        XCTAssertFalse(rendered.contains(secret))
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await attempt.perform()
        }
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch is CancellationError { }
        catch { XCTFail("Expected cancellation before artifact access or network") }
        do {
            _ = try await attempt.perform()
            XCTFail("Attempt cannot be replayed")
        } catch BackendSessionError.unavailable { }
        catch { XCTFail("Consumed attempt must fail before material or network") }
        XCTAssertThrowsError(try BackendLogoutAttempt.prepare(from: session, nowMilliseconds: 1000))
    }

    func testNetworkRequestUsesAccessBearerNumericSystemAndFlatExplicitFields() throws {
        let (material, rsa) = try material()
        let key = Data(repeating: 1, count: 16)
        let input = BackendNetworkInput(intranetIP: "192.0.2.10;2001:db8::1", dns: "192.0.2.53", wifiSSIDs: [secret])
        let request = try BackendDiscovery.preparedRequest(material: material, operation: .networkConfig, payload: input.payload,
                            key: key, timestamp: "1", nonce: "n", credential: nil, accessToken: secret)
        let scopeCipher = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request.value(forHTTPHeaderField: "SlServerType"))))
        let scopePlain = try XCTUnwrap(SecKeyCreateDecryptedData(rsa, .rsaEncryptionPKCS1, scopeCipher as CFData, nil)) as Data
        let scope = try XCTUnwrap(JSONSerialization.jsonObject(with: scopePlain) as? [String: String])
        XCTAssertEqual(scope, ["serverType": "SDP", "timestamp": "1"])
        XCTAssertFalse(String(decoding: scopePlain, as: UTF8.self).contains(secret))
        XCTAssertEqual(request.url?.path, "/networkApi/is/network/initConfig")
        XCTAssertEqual(request.value(forHTTPHeaderField: "apiVersion"), "5.0.0.0")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer " + secret)
        let encrypted = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request.httpBody)))
        let plain = try SessionCipher(key: key, iv: material.iv).decrypt(encrypted)
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: plain) as? [String: Any])
        XCTAssertEqual(Set(fields.keys), ["system", "intranetIp", "dns", "wifiSsid"])
        XCTAssertEqual(fields["system"] as? Int, 3)
        XCTAssertNil(fields["system"] as? String)
        XCTAssertEqual(fields["intranetIp"] as? String, "192.0.2.10;2001:db8::1")
        XCTAssertEqual(BackendNetworkInput().payload.count, 1)
        var rendered = ""; dump(input, to: &rendered)
        XCTAssertFalse(rendered.contains(secret))
        XCTAssertThrowsError(try BackendDiscovery.preparedRequest(material: material, operation: .networkConfig, payload: input.payload,
                            key: key, timestamp: "1", nonce: "n", credential: nil))
    }
    func testGetApplicationsRequestMatchesOfficialSheetaWireContract() throws {
        let (material, rsa) = try material()
        let key = Data(repeating: 2, count: 16)
        let payload: [String: Any] = ["org": "szu", "username": "fixture-user", "deviceId": "030123456789abcdef01234567abcdef", "system": "3"]
        let request = try BackendDiscovery.preparedRequest(
            material: material, operation: .getApplications, payload: payload,
            key: key, timestamp: "1700000000000", nonce: "fixture-nonce", credential: nil, accessToken: secret
        )
        XCTAssertEqual(request.url?.path, "/networkApi/gcable/getApplications")
        XCTAssertEqual(request.value(forHTTPHeaderField: "apiVersion"), "5.18.0.0")
        XCTAssertEqual(request.value(forHTTPHeaderField: "slTokenType"), "vpn")
        XCTAssertEqual(request.value(forHTTPHeaderField: "twoFactorType"), "vpn")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer " + secret)
        let scopeCipher = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request.value(forHTTPHeaderField: "SlServerType"))))
        let scopePlain = try XCTUnwrap(SecKeyCreateDecryptedData(rsa, .rsaEncryptionPKCS1, scopeCipher as CFData, nil)) as Data
        let scope = try XCTUnwrap(JSONSerialization.jsonObject(with: scopePlain) as? [String: String])
        XCTAssertEqual(scope, ["serverType": "SDP", "timestamp": "1700000000000"])
        let encrypted = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request.httpBody)))
        let plain = try SessionCipher(key: key, iv: material.iv).decrypt(encrypted)
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: plain) as? [String: String])
        XCTAssertEqual(fields, [
            "org": "szu",
            "username": "fixture-user",
            "deviceId": "030123456789abcdef01234567abcdef",
            "system": "3"
        ])
    }
    func testNetworkParserKeepsSensitiveFieldsPrivateAndUnknownModesUnsupported() throws {
        let data = try JSONSerialization.data(withJSONObject: ["returnCode": 1, "content": ["networkConfig": [
            "clientConf": secret, "clientCert": ["signPrivateKey": secret, "caCert": secret, "gmtls": 99, "enable": true],
            "priorServers": [["ip": secret, "ports": [443], "accessMode": 999]],
            "spaKey": secret, "spaHmacKey": secret, "portHideEnable": 44, secret: secret
        ]]])
        let config = try BackendNetworkConfiguration.parse(data)
        var rendered = ""; dump(config, to: &rendered)
        let receipt = String(decoding: try JSONEncoder().encode(config.receipt), as: UTF8.self)
        XCTAssertFalse(rendered.contains(secret))
        XCTAssertFalse(String(reflecting: config).contains(secret))
        XCTAssertFalse(receipt.contains(secret))
        XCTAssertFalse(config.receipt.tunnelSupported)
        XCTAssertEqual(config.receipt.modes["gmtls"], .nonzeroUnverified)
        XCTAssertEqual(config.receipt.fieldTypes["priorServers"], "array")
        XCTAssertEqual(config.receipt.present["clientConf"], true)
        XCTAssertEqual(config.receipt.present["clientCert.signPrivateKey"], true)
        XCTAssertEqual(config.receipt.present["clientCert.encryptCert"], false)
        XCTAssertFalse(try BackendNetworkConfiguration.parse(Data(#"{"returnCode":1,"content":{"networkConfig":{}}}"#.utf8)).receipt.tunnelSupported)
    }
    func testNetworkParserRejectsMalformedKnownFieldsAndMissingContent() {
        for json in [
            #"{"returnCode":true,"content":{"networkConfig":{}}}"#,
            #"{"returnCode":1}"#,
            #"{"returnCode":1,"content":{"networkConfig":{"clientConf":false}}}"#,
            #"{"returnCode":1,"content":{"networkConfig":{"clientCert":{"enable":1}}}}"#,
            #"{"returnCode":1,"content":{"networkConfig":{"portHideEnable":true}}}"#,
            #"{"returnCode":1,"content":{"networkConfig":{"priorServers":[{"ports":["443"]}]}}}"#,
            #"{"returnCode":2041}"#
        ] { XCTAssertThrowsError(try BackendNetworkConfiguration.parse(Data(json.utf8))) }
    }

    func testNetworkAttemptIsConsumedOnCancellationAndRejectsExpiredSession() async throws {
        let session = BackendAuthenticationSession()
        session.begin()
        let data = try JSONSerialization.data(withJSONObject: ["returnCode": 1, "content": [
            "creditFlag": 1, "username": "fixture", "loginMessage": [
                "accessToken": secret, "accessTokenExpire": 5000, "refreshToken": secret, "refreshTokenExpire": 6000
            ]
        ]])
        session.receive(data, nowMilliseconds: 1000)
        let attempt = try BackendNetworkConfigurationAttempt.prepare(from: session, nowMilliseconds: 1000, input: BackendNetworkInput())
        var rendered = ""; dump(attempt, to: &rendered)
        XCTAssertFalse(rendered.contains(secret))
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await attempt.perform()
        }
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch is CancellationError { }
        catch { XCTFail("Expected cancellation before artifact or network") }
        do { _ = try await attempt.perform(); XCTFail("No retry") }
        catch BackendSessionError.unavailable { }
        catch { XCTFail("Expected consumed attempt") }
        XCTAssertThrowsError(try BackendNetworkConfigurationAttempt.prepare(from: session, nowMilliseconds: 5000, input: BackendNetworkInput()))
    }

    func testPublicEnvelopeChunksLongTokenPayloadWithoutTruncation() throws {
        let (_, privateKey) = try material()
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        let plain = try JSONSerialization.data(withJSONObject: ["serverType": "SDP", "token": String(repeating: "fixture", count: 200)])
        let encrypted = try XCTUnwrap(Data(base64Encoded: BackendPublicEnvelope.encrypt(plain, using: publicKey)))
        let size = SecKeyGetBlockSize(privateKey)
        XCTAssertGreaterThan(encrypted.count, size)
        XCTAssertEqual(encrypted.count % size, 0)
        var recovered = Data()
        for offset in stride(from: 0, to: encrypted.count, by: size) {
            let block = encrypted.subdata(in: offset..<offset + size)
            recovered.append(try XCTUnwrap(SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, block as CFData, nil)) as Data)
        }
        XCTAssertEqual(recovered, plain)
        XCTAssertThrowsError(try BackendPublicEnvelope.encrypt(Data(repeating: 65, count: 65537), using: publicKey))
    }

}
