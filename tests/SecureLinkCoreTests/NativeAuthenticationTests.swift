import XCTest
@testable import SecureLinkCore

final class NativeAuthenticationTests: XCTestCase {
    private func settings() throws -> NativeSettings {
        try NativeSettings(certificateID: "synthetic-id", certificateKey: "synthetic-key", publicKey: "-----BEGIN PUBLIC KEY-----\nsynthetic\n-----END PUBLIC KEY-----", pid: 123, logPath: "/tmp/synthetic-szu/log")
    }
    private func cipher() throws -> SessionCipher {
        try SessionCipher(key: Data(repeating: 7, count: 16), iv: Data(repeating: 8, count: 16))
    }
    private func session() throws -> NativeProtocolSession {
        var gate = CASCallbackGate(); gate.begin()
        let credential = try gate.consume(URL(string: "securelink://sso_login?projectLabel=szu&authToken=synthetic-only")!)
        return NativeProtocolSession(cipher: try cipher(), settings: try settings(), credential: credential)
    }
    private func frame(_ command: UInt32, _ json: String) throws -> Data {
        let bytes = try cipher().encrypt(PlainFrame.encode(Message(command: command, payload: Data(json.utf8))))
        let length = UInt32(bytes.count)
        return Data([0,8,16,24].map { UInt8(truncatingIfNeeded: length >> $0) }) + bytes
    }
    private func decode(_ frame: Data) throws -> Message {
        var decoder = EncryptedStreamDecoder()
        let encrypted = try XCTUnwrap(decoder.append(frame).first)
        try decoder.finish()
        return try PlainFrame.decode(cipher().decrypt(encrypted))
    }
    func testSettingsUsesNativeIntegerFieldsAndNoUserPassword() throws {
        let value = try settings()
        XCTAssertFalse(String(reflecting: value).contains("synthetic-key"))
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: value.message().payload) as? [String: Any])
        for name in ["autoReconnect", "autoAdjustTime", "dot1PreAuthType", "pid", "publishType"] {
            let number = try XCTUnwrap(fields[name] as? NSNumber)
            XCTAssertNotEqual(CFGetTypeID(number), CFBooleanGetTypeID())
        }
        XCTAssertEqual(fields["password"] as? String, "")
        XCTAssertEqual(fields["username"] as? String, "")
        XCTAssertTrue(fields["authConfigId"] is NSNull)
        XCTAssertNil(fields["authToken"])
        XCTAssertEqual(fields["sheetaApiUrl"] as? String, "https://sheetaapi.wangsu.com")
    }
    func testEncryptedAuthenticationWaitsForPreConfigAndNeverConnects() throws {
        var engine = try session()
        let initial = try engine.receive(frame(18, "{}"), elapsed: .zero)
        XCTAssertEqual(try initial.outgoing.map(decode).map(\.command), [35])
        XCTAssertTrue(try engine.receive(frame(18, "{}"), elapsed: .seconds(1)).outgoing.isEmpty)
        let configured = try engine.receive(frame(35, #"{"returnCode":1}"#), elapsed: .seconds(2))
        let requests = try configured.outgoing.map(decode)
        XCTAssertEqual(requests.map(\.command), [5, 10])
        let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: requests[1].payload) as? [String: Any])
        XCTAssertEqual(payload["authToken"] as? String, "synthetic-only")
        XCTAssertEqual(engine.authenticationState, .awaitingReply)
        let rejected = try engine.receive(frame(10, #"{"returnCode":1,"content":{"rejectedByNonCredit":true}}"#), elapsed: .seconds(3))
        XCTAssertTrue(rejected.outgoing.isEmpty)
        XCTAssertEqual(engine.authenticationState, .deviceRejected)
        XCTAssertTrue(engine.authenticationComplete)
        XCTAssertThrowsError(try engine.receive(frame(18, "{}"), elapsed: .seconds(4)))
    }
    func testPreConfigErrorOrTimeoutEmitsNoSettingsOrCredential() throws {
        for response in [#"{"returnCode":3003}"#, #"{"returnCode":true}"#, "{}"] {
            var engine = try session()
            _ = try engine.receive(frame(18, "{}"), elapsed: .zero)
            XCTAssertThrowsError(try engine.receive(frame(35, response), elapsed: .seconds(1)))
            XCTAssertThrowsError(try engine.receive(frame(35, #"{"returnCode":1}"#), elapsed: .seconds(2)))
        }
        var engine = try session()
        _ = try engine.receive(frame(18, "{}"), elapsed: .zero)
        XCTAssertThrowsError(try engine.advanceAuthentication(elapsed: .seconds(20)))
        XCTAssertThrowsError(try engine.receive(frame(35, #"{"returnCode":1}"#), elapsed: .seconds(21)))
    }
    func testPreauthenticationTimeoutAndEOFStopWithoutConnect() throws {
        var engine = try session()
        _ = try engine.receive(frame(18, "{}"), elapsed: .zero)
        _ = try engine.receive(frame(35, #"{"returnCode":1}"#), elapsed: .seconds(1))
        try engine.advanceAuthentication(elapsed: .seconds(16))
        XCTAssertEqual(engine.authenticationState, .timedOut)
        XCTAssertTrue(engine.authenticationComplete)
        var closed = try session()
        try closed.finish()
        XCTAssertEqual(closed.authenticationState, .cancelled)
        XCTAssertThrowsError(try closed.receive(frame(18, "{}"), elapsed: .zero))
    }
    func testValidatedPreauthenticationStillDoesNotIssueConnectOrClaimPolicyReady() throws {
        var engine = try session()
        _ = try engine.receive(frame(18, "{}"), elapsed: .zero)
        _ = try engine.receive(frame(35, #"{"returnCode":1}"#), elapsed: .seconds(1))
        let result = try engine.receive(frame(10, #"{"returnCode":1,"content":{"rejectedByNonCredit":false,"userInfoCompletion":false,"creditFlag":1}}"#), elapsed: .seconds(2))
        XCTAssertTrue(result.outgoing.isEmpty)
        XCTAssertTrue(result.statuses.isEmpty)
        XCTAssertNil(result.policy)
        XCTAssertEqual(engine.authenticationState, .responseValidated(creditFlag: 1))
    }

    func testConnectionUsesRealSendOrderAndKeepsMonitoringAfterInitialization() throws {
        var gate = CASCallbackGate(); gate.begin()
        let credential = try gate.consume(URL(string: "securelink://sso_login?projectLabel=szu&authToken=synthetic-only")!)
        var engine = NativeProtocolSession(cipher: try cipher(), settings: try settings(), credential: credential, connectsTunnel: true)
        _ = try engine.receive(frame(18, "{}"), elapsed: .zero)
        let configured = try engine.receive(frame(35, #"{"returnCode":1}"#), elapsed: .seconds(1))
        XCTAssertEqual(configured.outgoingCommands, [5,10])
        let connected = try engine.receive(frame(10, #"{"returnCode":1,"content":{"username":"synthetic","creditFlag":1}}"#), elapsed: .seconds(2))
        XCTAssertEqual(connected.outgoingCommands, [11,16])
        XCTAssertEqual(try connected.outgoing.map(decode).map(\.command), [11,16])
        let load = try engine.receive(frame(16, #"{"systemBits":64,"deviceId":"not-forwarded","intranetIp":"","wifiSsid":[]}"#), elapsed: .seconds(3))
        let request = try decode(XCTUnwrap(load.outgoing.first))
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: request.payload) as? [String: Any])
        let loadID = try XCTUnwrap(fields["id"] as? String)
        let body = try XCTUnwrap(fields["body"] as? [String: Any])
        XCTAssertNil(body["systemBits"]); XCTAssertNil(body["deviceId"])
        let post = try engine.receive(frame(28, "{\"id\":\"\(loadID)\",\"returnCode\":1,\"content\":{}}") + frame(20, #"{"content":{"checkStatus":1,"healthStatus":0}}"#), elapsed: .seconds(4))
        XCTAssertEqual(post.outgoingCommands, [28,5,20,73])
        XCTAssertNil(post.policy)
        for command in post.outgoingCommands { engine.didSend(command: command, elapsed: .seconds(5)) }
        let extra = try decode(XCTUnwrap(post.outgoing.first))
        let extraFields = try XCTUnwrap(JSONSerialization.jsonObject(with: extra.payload) as? [String: Any])
        let extraID = try XCTUnwrap(extraFields["id"] as? String)
        _ = try engine.receive(frame(28, "{\"id\":\"\(extraID)\",\"returnCode\":1,\"content\":{\"vpnConfig\":{\"idleDisconnectEnable\":0,\"forceDisconnectEnable\":0,\"renewalMethod\":0}}}"), elapsed: .seconds(6))
        XCTAssertEqual(engine.connectionState, .initialized)
        XCTAssertFalse(engine.authenticationComplete)
        let healthy = try engine.receive(frame(20, #"{"content":{"checkStatus":1,"healthStatus":0}}"#) + frame(1, "{}"), elapsed: .seconds(7))
        XCTAssertEqual(healthy.policy?.endpointCheck, .healthy)
        XCTAssertEqual(healthy.outgoingCommands, [1])
        try engine.finish()
        XCTAssertEqual(engine.connectionState, .cancelled)
        XCTAssertThrowsError(try engine.receive(frame(1, "{}"), elapsed: .seconds(8)))
    }

}
