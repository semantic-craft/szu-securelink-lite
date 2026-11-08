import XCTest
@testable import SecureLinkCore

final class PolicyObservationTests: XCTestCase {
    private func message(_ command: UInt32, _ json: String) -> Message { Message(command: command, payload: Data(json.utf8)) }
    func testSecondaryAuthRequirementSurvivesHealthyAndConnectedMessages() {
        var policy = PolicyObservation()
        policy.receive(message(21, "{\"content\":{\"type\":3,\"clientMessage\":{\"needTwoFactor\":true}}}"))
        policy.receive(message(20, "{\"content\":{\"checkStatus\":2,\"healthStatus\":0}}"))
        policy.receive(message(3, "{\"content\":{\"state\":\"CONNECTED\"}}"))
        XCTAssertTrue(policy.requiresReauthentication)
        XCTAssertEqual(policy.endpointCheck, .healthy)
    }
    func testSecurityRequestAndMissingOrFailedResultsNeverReportHealthy() {
        var policy = PolicyObservation()
        policy.receive(message(21, "{\"content\":{\"type\":2}}"))
        XCTAssertEqual(policy.endpointCheck, .requested)
        for input in ["{}", "{\"content\":{\"checkStatus\":2}}", "{\"content\":{\"checkStatus\":2,\"healthStatus\":true}}", "{\"returnCode\":0,\"content\":{\"checkStatus\":2,\"healthStatus\":0}}", "{\"content\":{\"checkStatus\":0,\"healthStatus\":0}}"] {
            policy.receive(message(20, input))
            XCTAssertNotEqual(policy.endpointCheck, .healthy)
        }
    }
    func testEncodedResultsDisabledChecksAndErrorsStayDistinct() throws {
        for content in [#"{"enable":1,"checkStatus":1,"healthStatus":0}"#,
                        #"{"enable":0,"checkStatus":1,"healthStatus":null}"#,
                        #"{"enable":1,"checkStatus":1,"healthStatus":1}"#] {
            let direct = "{\"returnCode\":1,\"content\":" + content + "}"
            let encoded = try JSONSerialization.data(withJSONObject: ["returnCode":1, "content":content])
            var a = PolicyObservation(); var b = PolicyObservation()
            a.receive(message(20, direct)); b.receive(Message(command:20, payload:encoded))
            XCTAssertEqual(a, b)
            XCTAssertNotEqual(a.endpointCheck, .unknown)
            if content.contains("null") { XCTAssertEqual(a.endpointCheck, .notRequired) }
        }
        var policy = PolicyObservation()
        policy.receive(message(20, #"{"returnCode":0,"content":"private error details"}"#))
        XCTAssertEqual(policy.endpointCheck, .failed)
        for content in ["not-json", "null", "[]", #"{"enable":true}"#, #"{"enable":2}"#, #"{"enable":1,"checkStatus":"1","healthStatus":0}"#] {
            let data = try JSONSerialization.data(withJSONObject: ["returnCode":1, "content":content])
            policy.receive(Message(command:20, payload:data))
            XCTAssertEqual(policy.endpointCheck, .unknown)
        }
        let notification = try JSONSerialization.data(withJSONObject: ["content":#"{"type":3,"clientMessage":"{\"needTwoFactor\":true}"}"#])
        policy.receive(Message(command:21, payload:notification))
        XCTAssertTrue(policy.requiresReauthentication)
    }
    func testStatusErrorCannotClaimConnected() {
        for input in ["{\"returnCode\":0,\"content\":{\"state\":\"CONNECTED\"}}", "{\"returnCode\":true,\"content\":{\"state\":\"CONNECTED\"}}"] {
            XCTAssertEqual(TunnelStatus.decode(Data(input.utf8)), .unknown)
        }
    }
}
