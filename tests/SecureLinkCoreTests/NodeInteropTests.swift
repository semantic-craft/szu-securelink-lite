import XCTest
import Foundation
@testable import SecureLinkCore
final class NodeInteropTests: XCTestCase {
    func testIndependentNodeCryptoVectors() throws {
        let cipher = try SessionCipher(key: Data(repeating: 3, count: 16), iv: Data(repeating: 4, count: 16))
        let vectors: [(String, String)] = [
            ("", "6623c4b5a00d3b7425e49e1133f23c6c"),
            ("00", "c744db948134b26f2b04e935e6426b47"),
            ("414141414141414141414141414141", "26f57610a0dfaf54a3c1642e95152368"),
            ("41414141414141414141414141414141", "2d79f487aae73703c28611370a2592fdf5d97d431b9f6e3736fd089ea72be8a6"),
            ("4141414141414141414141414141414141", "2d79f487aae73703c28611370a2592fd46e2d04caf13ed5d428e16b4d2915ae4"),
            ("e6b7b1e59cb3e5a4a7e5ada6", "fd7eecf2fe64634ee190661849c393d8")
        ]
        func data(_ hex: String) -> Data {
            Data(stride(from: 0, to: hex.count, by: 2).map { offset in
                let start = hex.index(hex.startIndex, offsetBy: offset)
                return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
            })
        }
        for (plainHex, cipherHex) in vectors {
            XCTAssertEqual(try cipher.encrypt(data(plainHex)), data(cipherHex))
            XCTAssertEqual(try cipher.decrypt(data(cipherHex)), data(plainHex))
        }
    }
}
