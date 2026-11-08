import XCTest
@testable import SecureLinkCore

final class BackendAuthenticationSessionTests: XCTestCase {
    private let now: Int64 = 1_700_000_000_000
    private let secret = "SECRET-SENTINEL"
    private func response(_ overrides: [String: Any] = [:], code: Any = 1) throws -> Data {
        var content: [String: Any] = [
            "rejectedByNonCredit": false, "userInfoCompletion": 0, "creditFlag": 1,
            "username": "fixture-user", "authConfigId": "12",
            "loginMessage": ["accessToken": secret + "-access", "accessTokenExpire": now + 1000,
                             "refreshToken": secret + "-refresh", "refreshTokenExpire": now + 5000,
                             "inUsed": ["server": secret + "-mapping"]]
        ]
        for (key, value) in overrides { content[key] = value }
        return try JSONSerialization.data(withJSONObject: ["returnCode": code, "content": content])
    }
    private func started() -> BackendAuthenticationSession {
        let session = BackendAuthenticationSession()
        XCTAssertTrue(session.begin())
        XCTAssertFalse(session.begin())
        return session
    }
    func testReadyRequiresPolicyIdentityAndTokens() throws {
        let session = started()
        session.receive(try response(), nowMilliseconds: now)
        XCTAssertEqual(session.state, .ready)
        XCTAssertEqual(session.identity?.username, "fixture-user")
        XCTAssertEqual(session.identity?.authConfigId, 12)
        XCTAssertEqual(session.creditFlag, 1)
        XCTAssertEqual(try session.withAccessToken(nowMilliseconds: now) { $0 }, secret + "-access")
        XCTAssertEqual(try session.withRefreshToken(nowMilliseconds: now) { $0 }, secret + "-refresh")
        var dumpOutput = ""
        dump(session, to: &dumpOutput)
        for output in [String(describing: session), String(reflecting: session), dumpOutput] {
            XCTAssertFalse(output.contains(secret))
            XCTAssertFalse(output.contains("fixture-user"))
        }
        session.receive(try response(["rejectedByNonCredit": true]), nowMilliseconds: now)
        XCTAssertEqual(session.state, .ready, "One response per attempt")
    }
    func testPolicyFailuresCannotInstallOtherwiseValidTokens() throws {
        for (field, state) in [("rejectedByNonCredit", BackendAuthenticationSession.State.deviceRejected),
                               ("userInfoCompletion", .informationRequired)] {
            for value: Any in [true, -1, 2] {
                let session = started()
                session.receive(try response([field: value]), nowMilliseconds: now)
                XCTAssertEqual(session.state, state)
                XCTAssertNil(session.identity)
                XCTAssertThrowsError(try session.withAccessToken(nowMilliseconds: now) { $0 })
                XCTAssertThrowsError(try session.withRefreshToken(nowMilliseconds: now) { $0 })
            }
        }
    }
    func testBothChallengeShapesPreventTokenUse() throws {
        for (code, field) in [(1, "twoFactorToken"), (2041, "tempToken")] {
            let session = started()
            session.receive(try response([field: secret], code: code), nowMilliseconds: now)
            XCTAssertEqual(session.state, .requiresSecondFactor)
            XCTAssertThrowsError(try session.withAccessToken(nowMilliseconds: now) { $0 })
            XCTAssertThrowsError(try session.withRefreshToken(nowMilliseconds: now) { $0 })
            XCTAssertFalse(String(reflecting: session).contains(secret))
        }
    }
    func testChallengeAndPolicyRejectionDoNotRequireUsableTokenBundle() throws {
        for (code, fields, expected) in [
            (2041, ["tempToken": secret, "loginMessage": [:]] as [String: Any], BackendAuthenticationSession.State.requiresSecondFactor),
            (1, ["twoFactorToken": secret, "loginMessage": [:]], .requiresSecondFactor),
            (1, ["loginMessage": [:]], .unsupportedResponse),
            (1, ["rejectedByNonCredit": true, "loginMessage": "malformed"], .deviceRejected),
            (1, ["userInfoCompletion": 1, "loginMessage": ["accessToken": 9]], .informationRequired)
        ] {
            let session = started()
            session.receive(try response(fields, code: code), nowMilliseconds: now)
            XCTAssertEqual(session.state, expected)
            XCTAssertNil(session.identity)
            XCTAssertThrowsError(try session.withAccessToken(nowMilliseconds: now) { $0 })
            XCTAssertThrowsError(try session.withRefreshToken(nowMilliseconds: now) { $0 })
        }
    }
    func testUnknownAndMissingDataNeverBecomeReady() throws {
        let invalid: [[String: Any]] = [
            ["creditFlag": 9], ["creditFlag": true], ["creditFlag": NSNull()],
            ["username": ""], ["username": NSNull()], ["authConfigId": true],
            ["userInfoCompletion": "0"], ["userInfoCompletion": 0.5],
            ["loginMessage": NSNull()], ["loginMessage": [:]], ["twoFactorToken": 2]
        ]
        for fields in invalid {
            let session = started()
            session.receive(try response(fields), nowMilliseconds: now)
            XCTAssertEqual(session.state, .unsupportedResponse)
            XCTAssertThrowsError(try session.withAccessToken(nowMilliseconds: now) { $0 })
        }
        for data in [Data("{}".utf8), try response(code: true), Data(repeating: 65, count: 2 * 1024 * 1024 + 1)] {
            let session = started()
            session.receive(data, nowMilliseconds: now)
            XCTAssertEqual(session.state, .unsupportedResponse)
        }
        let rejected = started()
        rejected.receive(try response(code: 2005), nowMilliseconds: now)
        XCTAssertEqual(rejected.state, .rejected)
    }
    func testEpochMillisecondsAndIndependentRefreshExpiry() throws {
        let session = started()
        session.receive(try response(), nowMilliseconds: now)
        XCTAssertNoThrow(try session.withAccessToken(nowMilliseconds: now + 999) { _ in })
        XCTAssertThrowsError(try session.withAccessToken(nowMilliseconds: now + 1000) { $0 })
        XCTAssertEqual(session.state, .accessExpired)
        XCTAssertNoThrow(try session.withRefreshToken(nowMilliseconds: now + 4999) { _ in })
        XCTAssertThrowsError(try session.withRefreshToken(nowMilliseconds: now + 5000) { $0 })
        XCTAssertEqual(session.state, .expired)
        XCTAssertNil(session.identity)
    }
    func testRefreshExpiryDoesNotExtendOrShortenAccessExpiry() throws {
        let session = started()
        session.receive(try response(["loginMessage": [
            "accessToken": secret, "accessTokenExpire": now + 5000,
            "refreshToken": secret, "refreshTokenExpire": now + 1000,
            "inUsed": [:]
        ]]), nowMilliseconds: now)
        XCTAssertThrowsError(try session.withRefreshToken(nowMilliseconds: now + 1000) { $0 })
        XCTAssertNoThrow(try session.withAccessToken(nowMilliseconds: now + 4999) { _ in })
        XCTAssertThrowsError(try session.withAccessToken(nowMilliseconds: now + 5000) { $0 })
        XCTAssertEqual(session.state, .expired)
    }
    func testExpiredInitialResponseAndClockRegressionFailClosed() throws {
        let expired = started()
        expired.receive(try response(), nowMilliseconds: now + 5000)
        XCTAssertEqual(expired.state, .expired)
        let regressed = started()
        regressed.receive(try response(), nowMilliseconds: now)
        XCTAssertThrowsError(try regressed.withAccessToken(nowMilliseconds: now - 1) { $0 })
        XCTAssertEqual(regressed.state, .expired)
        XCTAssertThrowsError(try regressed.withRefreshToken(nowMilliseconds: now + 1) { $0 })
    }
    func testCancellationAndTransportFailureRejectLateSuccess() throws {
        let cancelled = started()
        cancelled.cancel()
        cancelled.receive(try response(), nowMilliseconds: now)
        XCTAssertEqual(cancelled.state, .cancelled)
        let ready = started()
        ready.receive(try response(), nowMilliseconds: now)
        ready.cancel()
        XCTAssertNil(ready.identity)
        XCTAssertThrowsError(try ready.withAccessToken(nowMilliseconds: now) { $0 })
        XCTAssertThrowsError(try ready.withRefreshToken(nowMilliseconds: now) { $0 })
        let failed = started()
        failed.transportFailed()
        failed.receive(try response(), nowMilliseconds: now)
        XCTAssertEqual(failed.state, .transportFailed)
    }
    func testHandshakeIdentityUsesInternalAuthTypeAndCannotOutliveSession() throws {
        let missing = started()
        missing.receive(try response(["authType": 9, "terminalUserId": 123]), nowMilliseconds: now)
        XCTAssertEqual(missing.state, .ready)
        try missing.withHandshakeIdentity(nowMilliseconds: now) { _, userID, authType in
            XCTAssertEqual(userID, 123)
            XCTAssertEqual(authType, 0, "Missing internal auth type retains the fresh Go struct zero, not authType alias")
        }
        XCTAssertEqual(missing.handshakeMetadataShape["content.authTypeInternal.type"], "missing")
        XCTAssertEqual(missing.handshakeMetadataShape["content.authTypeInternal.parsed"], "false")
        let valid = started()
        valid.receive(try response(["authTypeInternal": 9, "terminalUserId": 123]), nowMilliseconds: now)
        try valid.withHandshakeIdentity(nowMilliseconds: now) { username, userID, authType in
            XCTAssertEqual(username, "fixture-user")
            XCTAssertEqual(userID, 123)
            XCTAssertEqual(authType, 9)
        }
        valid.cancel()
        XCTAssertThrowsError(try valid.withHandshakeIdentity(nowMilliseconds: now) { _, _, _ in })
    }

    func testMetadataShapeIsTypedAndNeverCoercesOrDisclosesValues() throws {
        let cases: [(Any, String, String, String)] = [
            (NSNull(), "null", "false", "false"), (secret, "string", "false", "false"),
            ("123", "string", "false", "false"), (true, "other", "false", "false"),
            (1.5, "other", "false", "false"), ([], "other", "false", "false"),
            (0, "integer", "true", "false"), (-1, "integer", "true", "false"),
            (123, "integer", "true", "true")
        ]
        for (value, type, parsed, positive) in cases {
            let session = started()
            session.receive(try response(["terminalUserId": value, "authTypeInternal": value]), nowMilliseconds: now)
            XCTAssertEqual(session.state, .ready)
            for field in ["terminalUserId", "authTypeInternal"] {
                XCTAssertEqual(session.handshakeMetadataShape["content." + field + ".type"], type)
                XCTAssertEqual(session.handshakeMetadataShape["content." + field + ".parsed"], parsed)
                XCTAssertEqual(session.handshakeMetadataShape["content." + field + ".positive"], positive)
            }
            if positive != "true" {
                XCTAssertThrowsError(try session.withHandshakeIdentity(nowMilliseconds: now) { _, _, _ in }) {
                    guard case BackendSessionError.handshakeMetadataUnavailable = $0 else { return XCTFail("Expected metadata failure") }
                }
            }
            let encoded = try JSONEncoder().encode(session.handshakeMetadataShape)
            XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains(secret))
            let shape = session.handshakeMetadataShape
            session.cancel()
            XCTAssertEqual(session.handshakeMetadataShape, shape)
        }
    }
    func testNestedMetadataIsDiagnosedButNeverUsedAsFallback() throws {
        let data = try response()
        var root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        var content = try XCTUnwrap(root["content"] as? [String: Any])
        var login = try XCTUnwrap(content["loginMessage"] as? [String: Any])
        login["terminalUserId"] = 123
        login["authTypeInternal"] = 9
        content["loginMessage"] = login
        root["content"] = content
        let session = started()
        session.receive(try JSONSerialization.data(withJSONObject: root), nowMilliseconds: now)
        XCTAssertEqual(session.handshakeMetadataShape["content.terminalUserId.type"], "missing")
        XCTAssertEqual(session.handshakeMetadataShape["loginMessage.terminalUserId.type"], "integer")
        XCTAssertEqual(session.handshakeMetadataShape["loginMessage.authTypeInternal.parsed"], "true")
        XCTAssertThrowsError(try session.withHandshakeIdentity(nowMilliseconds: now) { _, _, _ in }) {
            guard case BackendSessionError.handshakeMetadataUnavailable = $0 else { return XCTFail("Expected metadata failure") }
        }
    }
    func testHandshakeErrorsSeparateExpiredFromUnavailableSession() throws {
        let session = started()
        session.receive(try response(["terminalUserId": 123, "authTypeInternal": 0]), nowMilliseconds: now)
        XCTAssertNoThrow(try session.withHandshakeIdentity(nowMilliseconds: now) { _, _, _ in })
        XCTAssertThrowsError(try session.withHandshakeIdentity(nowMilliseconds: now + 1000) { _, _, _ in }) {
            guard case BackendSessionError.handshakeExpired = $0 else { return XCTFail("Expected expiry") }
        }
        session.cancel()
        XCTAssertThrowsError(try session.withHandshakeIdentity(nowMilliseconds: now + 1000) { _, _, _ in }) {
            guard case BackendSessionError.handshakeSessionUnavailable = $0 else { return XCTFail("Expected unavailable session") }
        }
    }

    func testMetadataDiagnosticsSurviveRejectedPolicyButIgnoreLateResponses() throws {
        let session = started()
        session.receive(try response(["rejectedByNonCredit": true, "terminalUserId": secret]), nowMilliseconds: now)
        XCTAssertEqual(session.state, .deviceRejected)
        XCTAssertEqual(session.handshakeMetadataShape["content.terminalUserId.type"], "string")
        let shape = session.handshakeMetadataShape
        session.receive(try response(["terminalUserId": 123]), nowMilliseconds: now)
        XCTAssertEqual(session.handshakeMetadataShape, shape)
        let oversized = started()
        oversized.receive(Data(repeating: 65, count: 2 * 1024 * 1024 + 1), nowMilliseconds: now)
        XCTAssertTrue(oversized.handshakeMetadataShape.isEmpty)
        XCTAssertEqual(oversized.state, .unsupportedResponse)
    }

    func testOnlyAbsentInternalAuthTypeUsesVerifiedGoZeroValue() throws {
        for value: Any in [NSNull(), "0", "9", true, 1.5, [], ["value": 0]] {
            let session = started()
            session.receive(try response(["terminalUserId": 123, "authTypeInternal": value]), nowMilliseconds: now)
            XCTAssertEqual(session.state, .ready)
            XCTAssertThrowsError(try session.withHandshakeIdentity(nowMilliseconds: now) { _, _, _ in }) {
                guard case BackendSessionError.handshakeMetadataUnavailable = $0 else { return XCTFail("Expected metadata failure") }
            }
        }
        for fields: [String: Any] in [[:], ["terminalUserId": 0], ["terminalUserId": -1], ["terminalUserId": "123"]] {
            let session = started()
            session.receive(try response(fields), nowMilliseconds: now)
            XCTAssertThrowsError(try session.withHandshakeIdentity(nowMilliseconds: now) { _, _, _ in })
        }
    }

}
