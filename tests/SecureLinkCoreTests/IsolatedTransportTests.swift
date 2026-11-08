import XCTest
import Foundation
import Darwin
@testable import SecureLinkCore

final class IsolatedTransportTests: XCTestCase {
    private func pair() throws -> [Int32] {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw POSIXError(.EIO) }
        for fd in fds {
            var timeout = timeval(tv_sec: 1, tv_usec: 0)
            guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
                for fd in fds { close(fd) }; throw POSIXError(.EIO)
            }
        }
        return fds
    }
    private func send(_ bytes: Data, to fd: Int32) throws {
        let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        guard count == bytes.count else { throw POSIXError(.EIO) }
    }
    private func receive(from fd: Int32, decoder: inout EncryptedStreamDecoder) throws -> [Data] {
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = Darwin.read(fd, &bytes, bytes.count)
        guard count > 0 else { throw POSIXError(.EIO) }
        return try decoder.append(Data(bytes.prefix(count)))
    }
    func testIndependentChannelsAndCloseIsolation() throws {
        let a = try pair(), b = try pair()
        defer { for fd in a+b { close(fd) } }
        var decoderA = EncryptedStreamDecoder(), decoderB = EncryptedStreamDecoder()
        try send(Data([2,0]), to: a[0])
        XCTAssertEqual(try receive(from: a[1], decoder: &decoderA), [])
        try send(Data([1,0,0,0,44]), to: b[0])
        XCTAssertEqual(try receive(from: b[1], decoder: &decoderB), [Data([44])])
        try send(Data([0,0,11,22]), to: a[0])
        XCTAssertEqual(try receive(from: a[1], decoder: &decoderA), [Data([11,22])])
        XCTAssertEqual(shutdown(a[0], SHUT_WR), 0)
        var byte: UInt8 = 0
        XCTAssertEqual(Darwin.read(a[1], &byte, 1), 0)
        try send(Data([1,0,0,0,55]), to: b[0])
        XCTAssertEqual(try receive(from: b[1], decoder: &decoderB), [Data([55])])
        try decoderA.finish(); try decoderB.finish()
    }
    func testEncryptedFrameTraversesOwnedSocketPair() throws {
        let fds = try pair()
        defer { for fd in fds { close(fd) } }
        let cipher = try SessionCipher(key: Data(repeating: 7, count: 16), iv: Data(repeating: 8, count: 16))
        let message = Message(command: 1, payload: Data("{\"fixture\":true}".utf8))
        let ciphertext = try cipher.encrypt(PlainFrame.encode(message))
        let length = UInt32(ciphertext.count)
        let envelope = Data([0,8,16,24].map { UInt8(truncatingIfNeeded: length >> $0) }) + ciphertext
        try send(envelope, to: fds[0])
        var decoder = EncryptedStreamDecoder()
        let frames = try receive(from: fds[1], decoder: &decoder)
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(try PlainFrame.decode(cipher.decrypt(XCTUnwrap(frames.first))), message)
        try decoder.finish()
    }
}
