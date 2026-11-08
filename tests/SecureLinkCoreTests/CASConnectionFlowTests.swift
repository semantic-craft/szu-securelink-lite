import XCTest
@testable import SecureLinkCore

final class CASConnectionFlowTests: XCTestCase {
    private func start() throws -> CASConnectionFlow {
        var gate = CASCallbackGate(); gate.begin()
        let credential = try gate.consume(URL(string: "securelink://sso_login?projectLabel=szu&authToken=synthetic-only&username=untrusted")!)
        let settings = try NativeSettings(certificateID: "test", certificateKey: "test", publicKey: "-----BEGIN PUBLIC KEY-----test", pid: 1, logPath: "/tmp/test")
        let flow = CASConnectionFlow(settings: settings)
        XCTAssertEqual(try flow.begin(credential, elapsed: .zero)?.command, 10)
        XCTAssertNil(try flow.begin(credential, elapsed: .zero))
        return flow
    }
    private func reply(_ command: UInt32, _ json: String) -> Message { Message(command: command, payload: Data(json.utf8)) }
    private func object(_ message: Message) throws -> [String: Any] { try XCTUnwrap(JSONSerialization.jsonObject(with: message.payload) as? [String: Any]) }
    private func accepted(_ flag: Int = 1) -> Message { reply(10, "{\"creditFlag\":\(flag),\"username\":\"verified\",\"authConfigId\":\"12\"}") }
    private func apiReply(_ request: Message, content: String = "{}", code: String = "1") throws -> Message {
        let id = try XCTUnwrap(object(request)["id"] as? String)
        return reply(28, "{\"id\":\"\(id)\",\"returnCode\":\(code),\"content\":\(content)}")
    }
    func testOrderedContinuationWithoutCommand11Reply() throws {
        for flag in 0...2 {
            let flow = try start()
            let output = try flow.receive(accepted(flag), elapsed: .seconds(1))
            XCTAssertEqual(output.map(\.command), [11,16])
            XCTAssertEqual(try object(output[0])["creditType"] as? Int, flag == 1 ? 1 : 0)
            XCTAssertTrue(try flow.receive(accepted(), elapsed: .seconds(2)).isEmpty)
            let load = try XCTUnwrap(flow.receive(reply(16, #"{"deviceId":"synthetic","intranetIp":"","dns":"","wifiSsid":[],"ignored":"x"}"#), elapsed: .seconds(3)).first)
            let fields = try object(load)
            let body = try XCTUnwrap(fields["body"] as? [String: Any])
            XCTAssertEqual(body["system"] as? String, "3")
            XCTAssertNil(body["deviceId"]); XCTAssertEqual(Set(body.keys), ["system", "intranetIp", "dns", "wifiSsid"]); XCTAssertNil(body["ignored"]); XCTAssertNil(body["authToken"]); XCTAssertNil(body["username"])
            XCTAssertEqual(fields["tokenType"] as? Int, 2)
            let post = try flow.receive(apiReply(load), elapsed: .seconds(4))
            XCTAssertEqual(post.map(\.command), [28,5,20,73])
            XCTAssertEqual(try object(post[1])["username"] as? String, "verified")
            XCTAssertEqual(try object(post[1])["authConfigId"] as? Int, 12)
            XCTAssertEqual(try object(post[1])["autoReconnect"] as? Int, 0)
            XCTAssertEqual(try object(post[2])["system"] as? Int, 3)
            XCTAssertEqual(try object(post[3])["authType"] as? Int, 11)
            XCTAssertTrue(try flow.receive(apiReply(load), elapsed: .seconds(5)).isEmpty)
            let health = reply(20, #"{"content":{"checkStatus":1,"healthStatus":0}}"#)
            _ = try flow.receive(health, elapsed: .seconds(5))
            XCTAssertEqual(flow.policy?.observation.endpointCheck, .unknown)
            flow.didSend(command: 20, elapsed: .seconds(6))
            _ = try flow.receive(health, elapsed: .seconds(7))
            XCTAssertEqual(flow.policy?.observation.endpointCheck, .healthy)
            _ = try flow.receive(apiReply(post[0], content: #"{"vpnConfig":{"idleDisconnectEnable":1,"idleDisconnectTime":2,"forceDisconnectEnable":0,"renewalMethod":0}}"#), elapsed: .seconds(8))
            XCTAssertEqual(flow.state, .initialized)
            XCTAssertEqual(flow.policy?.vpnConfiguration?.idleDisconnectSeconds, 120)
            XCTAssertFalse(flow.isTerminalFailure)
            flow.advance(elapsed: .seconds(1000))
            XCTAssertEqual(flow.state, .initialized)
        }
    }
    func testMalformedDeviceAndMissingIdentityFailClosed() throws {
        let empty = try start()
        XCTAssertTrue(try empty.receive(reply(10, #"{"creditFlag":1}"#), elapsed: .seconds(1)).isEmpty)
        XCTAssertEqual(empty.state, .unsupportedResponse)
        for json in ["{}", #"{"returnCode":1}"#, #"{"content":{"deviceId":"x"}}"#, #"{"intranetIp":[]}"#, #"{"dns":{}}"#, #"{"wifiSsid":"x"}"#, #"{"deviceId":"x","error":5}"#] {
            let flow = try start(); _ = try flow.receive(accepted(), elapsed: .seconds(1))
            XCTAssertTrue(try flow.receive(reply(16, json), elapsed: .seconds(2)).isEmpty)
            XCTAssertEqual(flow.state, .unsupportedResponse)
        }
    }
    func testWrongIDsErrorsCancellationAndTimeout() throws {
        for outcome in 0...3 {
            let flow = try start(); _ = try flow.receive(accepted(), elapsed: .seconds(1))
            let load = try XCTUnwrap(flow.receive(reply(16, #"{"deviceId":"synthetic"}"#), elapsed: .seconds(2)).first)
            _ = try flow.receive(reply(28, #"{"id":"wrong","returnCode":0}"#), elapsed: .seconds(3))
            XCTAssertEqual(flow.state, .initializingPolicy)
            if outcome == 0 { flow.cancel() }
            if outcome == 1 { flow.advance(elapsed: .seconds(93)) }
            if outcome == 2 { _ = try flow.receive(apiReply(load, code: "0"), elapsed: .seconds(4)) }
            if outcome == 3 { _ = try flow.receive(apiReply(load, code: "true"), elapsed: .seconds(4)) }
            XCTAssertTrue(flow.isTerminalFailure)
            XCTAssertTrue(try flow.receive(apiReply(load), elapsed: .seconds(94)).isEmpty)
        }
    }
    func testPreauthenticationRejectionAndDeadlineRemainTerminal() throws {
        for json in [#"{"returnCode":2005}"#, #"{"rejectedByNonCredit":true}"#, #"{"userInfoCompletion":true}"#, #"{"creditFlag":9}"#] {
            let flow = try start()
            XCTAssertTrue(try flow.receive(reply(10, json), elapsed: .seconds(1)).isEmpty)
            XCTAssertTrue(flow.isTerminalFailure)
            XCTAssertTrue(try flow.receive(accepted(), elapsed: .seconds(2)).isEmpty)
        }
        for time in [Duration.seconds(-1), .seconds(15)] {
            let flow = try start()
            flow.advance(elapsed: time)
            XCTAssertEqual(flow.state, .timedOut)
            XCTAssertTrue(try flow.receive(accepted(), elapsed: .seconds(16)).isEmpty)
        }
    }
    func testMissingConfigurationDoesNotMeanUnlimitedAndDuplicateCannotReplaceIt() throws {
        let flow = try start(); _ = try flow.receive(accepted(), elapsed: .seconds(1))
        let load = try XCTUnwrap(flow.receive(reply(16, #"{"deviceId":"synthetic"}"#), elapsed: .seconds(2)).first)
        let post = try flow.receive(apiReply(load), elapsed: .seconds(3))
        flow.didSend(command: 20, elapsed: .seconds(4))
        _ = try flow.receive(apiReply(post[0]), elapsed: .seconds(5))
        XCTAssertEqual(flow.state, .initialized)
        XCTAssertNil(flow.policy?.vpnConfiguration)
        _ = try flow.receive(apiReply(post[0], content: #"{"vpnConfig":{"forceDisconnectTime":10}}"#), elapsed: .seconds(6))
        XCTAssertNil(flow.policy?.vpnConfiguration)
        flow.cancel()
        _ = try flow.receive(reply(20, #"{"content":{"checkStatus":1,"healthStatus":0}}"#), elapsed: .seconds(7))
        XCTAssertEqual(flow.policy?.observation.endpointCheck, .unknown)
    }
    func testAPIAllowsOmittedReturnCodeButRejectsExplicitNull() throws {
        for code in ["", ",\"returnCode\":null"] {
            let flow = try start(); _ = try flow.receive(accepted(), elapsed: .seconds(1))
            let load = try XCTUnwrap(flow.receive(reply(16, #"{"deviceId":"synthetic"}"#), elapsed: .seconds(2)).first)
            let id = try XCTUnwrap(object(load)["id"] as? String)
            let output = try flow.receive(reply(28, "{\"id\":\"\(id)\",\"content\":{}\(code)}"), elapsed: .seconds(3))
            if code.isEmpty { XCTAssertEqual(output.map(\.command), [28,5,20,73]) }
            else { XCTAssertEqual(flow.state, .unsupportedResponse) }
        }
    }
    func testConfigurationUnknownAndBoolNumbers() throws {
        for config in ["{}", #"{"forceDisconnectEnable":true}"#, #"{"forceDisconnectTime":true}"#, #"{"forceDisconnectTime":-1}"#] {
            let flow = try start(); _ = try flow.receive(accepted(), elapsed: .seconds(1))
            let load = try XCTUnwrap(flow.receive(reply(16, #"{"deviceId":"synthetic"}"#), elapsed: .seconds(2)).first)
            let post = try flow.receive(apiReply(load), elapsed: .seconds(3))
            _ = try flow.receive(apiReply(post[0], content: "{\"vpnConfig\":\(config)}"), elapsed: .seconds(4))
            if config == "{}" {
                XCTAssertEqual(flow.state, .initializingPolicy)
                XCTAssertEqual(flow.policy?.vpnConfiguration?.isVerified, false)
                flow.didSend(command: 20, elapsed: .seconds(5))
                XCTAssertEqual(flow.state, .initialized)
            } else { XCTAssertEqual(flow.state, .unsupportedResponse) }
        }
    }
}
