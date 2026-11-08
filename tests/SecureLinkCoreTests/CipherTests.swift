import XCTest
import Foundation
@testable import SecureLinkCore

final class CipherTests: XCTestCase {
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    func testNISTCBCFirstBlockAndPKCS7RoundTrip() throws {
        let cipher = try SessionCipher(key: hex("2b7e151628aed2a6abf7158809cf4f3c"), iv: hex("000102030405060708090a0b0c0d0e0f"))
        let plain = hex("6bc1bee22e409f96e93d7e117393172a")
        let encrypted = try cipher.encrypt(plain)
        XCTAssertEqual(encrypted.prefix(16), hex("7649abac8119b246cee98e9b12e9197d"))
        XCTAssertEqual(encrypted.count, 32)
        XCTAssertEqual(try cipher.decrypt(encrypted), plain)
    }
    func testInvalidKeyIVAndCiphertextFail() throws {
        XCTAssertThrowsError(try SessionCipher(key: Data(count: 15), iv: Data(count: 16)))
        XCTAssertThrowsError(try SessionCipher(key: Data(count: 16), iv: Data(count: 15)))
        let cipher = try SessionCipher(key: Data(repeating: 1, count: 16), iv: Data(repeating: 2, count: 16))
        XCTAssertThrowsError(try cipher.decrypt(Data([1])))
        XCTAssertThrowsError(try cipher.decrypt(Data()))
        var encrypted = try cipher.encrypt(Data(repeating: 7, count: 16))
        encrypted[15] ^= 1
        XCTAssertThrowsError(try cipher.decrypt(encrypted))
    }
    func testEmptyAndUnicodePayloads() throws {
        let cipher = try SessionCipher(key: Data(repeating: 3, count: 16), iv: Data(repeating: 4, count: 16))
        for plain in [Data(), Data("深圳大学".utf8), Data(repeating: 1, count: 1024)] {
            XCTAssertEqual(try cipher.decrypt(cipher.encrypt(plain)), plain)
        }
    }
}
