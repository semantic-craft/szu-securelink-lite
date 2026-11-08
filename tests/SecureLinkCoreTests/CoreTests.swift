import XCTest
@testable import SecureLinkCore

final class CoreTests: XCTestCase {
    func testGoldenFrameUsesUTF8ByteLength() throws {
        let message = Message(command: 1, payload: Data("\"深\"".utf8))
        let expected = Data([0,0,0,1,0,0,0,5,34,0xE6,0xB7,0xB1,34])
        XCTAssertEqual(try PlainFrame.encode(message), expected)
        XCTAssertEqual(try PlainFrame.decode(expected), message)
    }
    func testInvalidJSONAndLengthRejected() {
        XCTAssertThrowsError(try PlainFrame.encode(Message(command: 1, payload: Data([0xFF]))))
        XCTAssertThrowsError(try PlainFrame.decode(Data([0,0,0,1,0,0,0,9,123,125])))
        XCTAssertThrowsError(try PlainFrame.decode(Data([0,0,0,1,255,255,255,255])))
    }
    func testEverySplitAndCoalescedFrames() throws {
        let bytes = Data([3,0,0,0,10,11,12,2,0,0,0,21,22])
        for split in 0...bytes.count {
            var stream = EncryptedStreamDecoder()
            let a = try stream.append(bytes.prefix(split))
            let b = try stream.append(bytes.dropFirst(split))
            XCTAssertEqual(a+b, [Data([10,11,12]),Data([21,22])])
            try stream.finish()
        }
    }
    func testByteAtATime() throws {
        var stream = EncryptedStreamDecoder()
        var result: [Data] = []
        for byte in [UInt8(1),0,0,0,55] { result += try stream.append(Data([byte])) }
        XCTAssertEqual(result, [Data([55])]); try stream.finish()
    }
    func testOversizeAndZeroFailClosed() {
        for header: [UInt8] in [[255,255,255,255], [0,0,0,0]] {
            var stream = EncryptedStreamDecoder()
            XCTAssertThrowsError(try stream.append(Data(header)))
            XCTAssertThrowsError(try stream.append(Data([1,0,0,0,1])))
        }
    }
    func testTruncatedFrameFailsOnEnd() throws {
        for bytes: [UInt8] in [[1], [2,0,0,0], [2,0,0,0,1]] {
            var stream = EncryptedStreamDecoder()
            _ = try stream.append(Data(bytes))
            XCTAssertThrowsError(try stream.finish())
        }
    }
    func testTransportOrLoginAloneIsNotConnected() {
        var state = ConnectionState()
        state.transportConnected = true; state.authenticated = true
        XCTAssertFalse(state.canAttemptCampusResource)
        state.receiveTunnelState("CONNECTED"); XCTAssertTrue(state.canAttemptCampusResource)
        state.receiveTunnelState("FUTURE_UNKNOWN_STATE"); XCTAssertFalse(state.canAttemptCampusResource)
        state.receiveTunnelState("CONNECTED"); state.transportClosed()
        XCTAssertFalse(state.canAttemptCampusResource); XCTAssertEqual(state.tunnel, .unknown)
    }
}
