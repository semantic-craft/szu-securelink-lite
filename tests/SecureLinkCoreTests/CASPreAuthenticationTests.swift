import XCTest
@testable import SecureLinkCore

final class CASPreAuthenticationTests: XCTestCase {
    private func start() throws -> CASPreAuthentication {
        var gate = CASCallbackGate()
        gate.begin()
        let credential = try gate.consume(URL(string: "securelink://sso_login?projectLabel=szu&authToken=synthetic-only")!)
        let session = CASPreAuthentication()
        let request = try XCTUnwrap(session.begin(credential, elapsed: .seconds(1)))
        XCTAssertEqual(request.command, 10)
        XCTAssertNil(try session.begin(credential, elapsed: .seconds(2)))
        return session
    }
    private func reply(_ json: String, command: UInt32 = 10) -> Message {
        Message(command: command, payload: Data(json.utf8))
    }
    private let accepted = #"{"returnCode":1,"content":{"rejectedByNonCredit":false,"userInfoCompletion":false,"creditFlag":1}}"#

    func testSeparatesDeviceRejectionCompletionAndValidation() throws {
        for (json, expected) in [
            (#"{"returnCode":1,"content":{"rejectedByNonCredit":true,"userInfoCompletion":true}}"#, CASPreAuthentication.State.deviceRejected),
            (#"{"returnCode":1,"content":{"userInfoCompletion":true}}"#, .informationRequired),
            (accepted, .responseValidated(creditFlag: 1)),
            (#"{"returnCode":2005}"#, .serviceRejected)
        ] {
            let session = try start()
            session.receive(reply(json), elapsed: .seconds(2))
            XCTAssertEqual(session.state, expected)
            session.receive(reply(accepted), elapsed: .seconds(3))
            XCTAssertEqual(session.state, expected)
        }
    }
    func testNumericFlagsFollowOfficialBranchesWithoutBypassingRejection() throws {
        let allowed = try start()
        allowed.receive(reply(#"{"returnCode":1,"content":{"userInfoCompletion":0,"creditFlag":1,"username":"synthetic","authConfigId":0}}"#), elapsed: .seconds(2))
        XCTAssertEqual(allowed.state, .responseValidated(creditFlag: 1))
        for number in [-1, 1, 2] {
            let completion = try start()
            completion.receive(reply("{\"userInfoCompletion\":\(number)}"), elapsed: .seconds(2))
            XCTAssertEqual(completion.state, .informationRequired)
            let rejection = try start()
            rejection.receive(reply("{\"rejectedByNonCredit\":\(number)}"), elapsed: .seconds(2))
            XCTAssertEqual(rejection.state, .deviceRejected)
        }
        for invalid in ["null", "\"0\"", "[]", "0.5"] {
            let unknown = try start()
            unknown.receive(reply("{\"userInfoCompletion\":\(invalid),\"creditFlag\":1}"), elapsed: .seconds(2))
            XCTAssertEqual(unknown.state, .unsupportedResponse)
        }
    }
    func testUnknownOrMissingFieldsCannotAuthorizeProgress() throws {
        for json in [#"{}"#, #"{"returnCode":true}"#, #"{"returnCode":1}"#,
                     #"{"returnCode":1,"content":{"rejectedByNonCredit":"false","userInfoCompletion":false,"creditFlag":1}}"#,
                     #"{"returnCode":1,"content":{"rejectedByNonCredit":false,"userInfoCompletion":false,"creditFlag":9}}"#] {
            let session = try start()
            session.receive(reply(json), elapsed: .seconds(2))
            XCTAssertEqual(session.state, .unsupportedResponse)
        }
    }
    func testOptionalFlagsIdentityAndStrictTypes() throws {
        for config in ["12", "\"12\"", "null", "0"] {
            let session = try start()
            session.receive(reply("{\"creditFlag\":1,\"username\":\"synthetic\",\"authConfigId\":\(config)}"), elapsed: .seconds(2))
            XCTAssertEqual(session.state, .responseValidated(creditFlag: 1))
            XCTAssertEqual(session.identity?.authConfigId, config == "null" || config == "0" ? nil : 12)
        }
        for field in ["\"returnCode\":null", "\"rejectedByNonCredit\":null", "\"authConfigId\":true", "\"authConfigId\":1.2", "\"authConfigId\":-1", "\"authConfigId\":\"x\"", "\"creditFlag\":true", "\"rejectedByNonCredit\":0.5"] {
            let session = try start()
            let prefix = field.hasPrefix("\"creditFlag\"") ? "" : "\"creditFlag\":1,"
            session.receive(reply("{\(prefix)\(field)}"), elapsed: .seconds(2))
            XCTAssertEqual(session.state, .unsupportedResponse)
        }
    }
    func testHeartbeatDoesNotExtendDeadlineOrAcceptLateReply() throws {
        let session = try start()
        session.receive(reply(accepted, command: 1), elapsed: .seconds(15))
        XCTAssertEqual(session.state, .awaitingReply)
        session.receive(reply(accepted), elapsed: .seconds(16))
        XCTAssertEqual(session.state, .timedOut)
    }
    func testCancellationAndClockRegressionFailClosed() throws {
        let cancelled = try start()
        cancelled.cancel()
        cancelled.receive(reply(accepted), elapsed: .seconds(2))
        XCTAssertEqual(cancelled.state, .cancelled)
        let regressed = try start()
        regressed.advance(elapsed: .zero)
        XCTAssertEqual(regressed.state, .timedOut)
    }
}
