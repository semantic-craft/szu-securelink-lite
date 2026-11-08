import XCTest
@testable import SecureLinkCore

final class NativeProtocolSessionTests: XCTestCase {
    private func cipher() throws -> SessionCipher {
        try SessionCipher(key: Data(repeating: 7, count: 16), iv: Data(repeating: 8, count: 16))
    }
    private func frame(_ command: UInt32, _ json: String) throws -> Data {
        let encrypted = try cipher().encrypt(PlainFrame.encode(Message(command: command, payload: Data(json.utf8))))
        let length = UInt32(encrypted.count)
        return Data([0,8,16,24].map { UInt8(truncatingIfNeeded: length >> $0) }) + encrypted
    }
    private func decode(_ framed: Data) throws -> Message {
        var decoder = EncryptedStreamDecoder()
        let frames = try decoder.append(framed)
        try decoder.finish()
        return try PlainFrame.decode(cipher().decrypt(XCTUnwrap(frames.first)))
    }
    func testHeartbeatTrafficCannotKeepStaleConnectedStatusAlive() throws {
        var session = NativeProtocolSession(cipher: try cipher())
        XCTAssertEqual(try session.receive(frame(3, "{\"content\":{\"state\":\"CONNECTED\"}}"), elapsed: .zero).statuses, [.connected])
        let heartbeat = "{\"fixture\":\"synthetic-heartbeat\"}"
        let early = try session.receive(frame(1, heartbeat), elapsed: .seconds(9))
        XCTAssertTrue(early.statuses.isEmpty)
        XCTAssertEqual(try decode(XCTUnwrap(early.outgoing.first)), Message(command: 1, payload: Data(heartbeat.utf8)))
        let expired = try session.receive(frame(1, heartbeat), elapsed: .seconds(10))
        XCTAssertEqual(expired.statuses, [.unavailable])
        XCTAssertEqual(expired.heartbeatReplies, 1)
        XCTAssertEqual(try session.receive(frame(3, "{\"content\":{\"state\":\"CONNECTED\"}}"), elapsed: .seconds(11)).statuses, [.connected])
    }
    func testPartialTrafficAndIdleTicksExpireStatusExactlyOnce() throws {
        var session = NativeProtocolSession(cipher: try cipher())
        _ = try session.receive(frame(3, "{\"content\":{\"state\":\"CONNECTED\"}}"), elapsed: .zero)
        XCTAssertEqual(try session.receive(Data([16]), elapsed: .seconds(12)).statuses, [.unavailable])
        XCTAssertTrue(session.tick(elapsed: .seconds(13)).isEmpty)
        XCTAssertThrowsError(try session.finish())
        XCTAssertThrowsError(try session.receive(frame(1, "{}"), elapsed: .seconds(14)))
    }
    func testMalformedFramePermanentlyFailsThisSession() throws {
        var session = NativeProtocolSession(cipher: try cipher())
        XCTAssertThrowsError(try session.receive(Data([0,0,0,0]), elapsed: .zero))
        XCTAssertThrowsError(try session.receive(frame(3, "{\"content\":{\"state\":\"CONNECTED\"}}"), elapsed: .seconds(1)))
    }
    func testFragmentedAndCoalescedMessagesPreserveRepliesAndPolicy() throws {
        let stream = try frame(1, "{\"n\":1}") + frame(21, "{\"content\":{\"type\":3,\"clientMessage\":{\"needTwoFactor\":true}}}")
        for split in 0...stream.count {
            var session = NativeProtocolSession(cipher: try cipher())
            let first = try session.receive(stream.prefix(split), elapsed: .zero)
            let second = try session.receive(stream.dropFirst(split), elapsed: .seconds(1))
            XCTAssertEqual(first.outgoing.count + second.outgoing.count, 1)
            XCTAssertEqual(first.policy?.requiresReauthentication == true || second.policy?.requiresReauthentication == true, true)
            try session.finish()
        }
    }
    func testDiscoveryOnlyEmitsNoTokenDiscoveryCommands() throws {
        var session = NativeProtocolSession(cipher: try cipher(), discoverCAS: true)
        let first = try session.receive(frame(18, "{}"), elapsed: .zero)
        let request = try decode(XCTUnwrap(first.outgoing.first))
        XCTAssertEqual(request.command, 28)
        let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: request.payload) as? [String: Any])
        XCTAssertEqual(payload["tokenType"] as? Int, 0)
        XCTAssertEqual(payload["path"] as? String, "/authApi/sso/authConfig/getAuthConfig?locale=zh_CN")
        let id = try XCTUnwrap(payload["id"] as? String)
        let response = try JSONSerialization.data(withJSONObject: ["id": id, "returnCode": 1, "content": ["list": [["name": "test-cas", "reportType": 9]]]])
        let second = try session.receive(frame(28, String(decoding: response, as: UTF8.self)), elapsed: .seconds(1))
        let next = try decode(XCTUnwrap(second.outgoing.first))
        XCTAssertEqual(next.command, 28)
        let nextPayload = try XCTUnwrap(JSONSerialization.jsonObject(with: next.payload) as? [String: Any])
        XCTAssertEqual(nextPayload["path"] as? String, "/authApi/sso/authConfig/getAuthUrl?locale=zh_CN")
    }
}
