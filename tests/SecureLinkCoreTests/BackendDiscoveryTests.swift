import XCTest
import SecureLinkCore
@testable import SecureLinkTransport

final class BackendDiscoveryTests: XCTestCase {
    let key = Data(repeating: 7, count: 16)
    let iv = Data(repeating: 9, count: 16)
    func wire(_ text: String) throws -> Data {
        Data(try SessionCipher(key: key, iv: iv).encrypt(Data(text.utf8)).base64EncodedString().utf8)
    }
    func testSignatureUsesHexThenPaddedBase64AndPreservesPlus() {
        XCTAssertEqual(BackendDiscovery.signature(certID: "fixture-id", timestamp: "1700000000000", nonce: "fixture-nonce", body: "abc+def/=="), "ZDMYZTJKOWZINGE3MWYXZTQ0MWJHMGZJMDU0N2EWOWRKMDUYMWQWNG==")
        XCTAssertNotEqual(BackendDiscovery.signature(certID: "id", timestamp: "1", nonce: "n", body: "a+b"), BackendDiscovery.signature(certID: "id", timestamp: "1", nonce: "n", body: "a%2Bb"))
    }
    func testRawStandardBase64BodyRoundTripIncludesPlus() throws {
        var sawPlus = false
        for value in 0..<256 {
            let key = Data(repeating: UInt8(value), count: 16)
            let body = try BackendDiscovery.body(payload: ["org": "szu"], key: key, iv: iv)
            sawPlus = sawPlus || body.contains("+")
            XCTAssertFalse(body.contains("%"))
            XCTAssertEqual(try SessionCipher(key: key, iv: iv).decrypt(XCTUnwrap(Data(base64Encoded: body))), Data(#"{"org":"szu"}"#.utf8))
        }
        XCTAssertTrue(sawPlus)
    }
    func testReceiptNeverCopiesServerSecretsOrKeys() throws {
        let data = try wire(#"{"returnCode":1,"content":{"algorithmType":1,"clientCert":{"signPrivateKey":"SECRET-SENTINEL"},"apiAddress":"SECRET-SENTINEL","SECRET-SENTINEL":"SECRET-SENTINEL"}}"#)
        let receipt = try BackendDiscovery.receipt(response: data, status: 200, key: key, iv: iv)
        let output = String(decoding: try JSONEncoder().encode(receipt), as: UTF8.self)
        XCTAssertFalse(output.contains("SECRET-SENTINEL"))
        XCTAssertEqual(receipt.fieldTypes["clientCert"], "object")
        XCTAssertFalse(receipt.uninstallReady)
    }
    func testAlreadyCancelledDiscoveryDoesNotReadMaterialOrStartNetwork() async {
        for cas in [false, true] {
            let task = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                if cas { _ = try await BackendDiscovery.discoverCAS() }
                else { _ = try await BackendDiscovery.run() }
            }
            do {
                try await task.value
                XCTFail("Expected cancellation")
            } catch is CancellationError { }
            catch { XCTFail("Cancellation must not become a material or transport error") }
        }
    }
    func testCASProviderAndURLFailClosed() throws {
        let provider = Data(#"{"returnCode":1,"content":{"list":[{"reportType":9,"name":"fixture"}]}}"#.utf8)
        XCTAssertEqual(try BackendDiscovery.providerName(provider), "fixture")
        for value in [#"{"returnCode":1,"content":{"list":[]}}"#, #"{"returnCode":1,"content":{"list":[{"reportType":9,"name":"a"},{"reportType":9,"name":"b"}]}}"#] {
            XCTAssertThrowsError(try BackendDiscovery.providerName(Data(value.utf8)))
        }
        let valid = #"{"returnCode":1,"content":{"action":2,"loginUrl":"https://authserver.szu.edu.cn/authserver/login?service=https%3A%2F%2Fsecurelinksso.wangsu.com%2Ffixture"}}"#
        XCTAssertNoThrow(try BackendDiscovery.validateCASResponse(Data(valid.utf8)))
        XCTAssertThrowsError(try BackendDiscovery.validateCASResponse(Data(valid.replacingOccurrences(of: "authserver.szu.edu.cn", with: "attacker.example").utf8)))
        XCTAssertThrowsError(try BackendDiscovery.validateCASResponse(Data(valid.replacingOccurrences(of: "\"action\":2", with: "\"action\":true").utf8)))
    }
    func testRejectedMalformedAndOversizedResponses() throws {
        for raw in [#"{"returnCode":true,"content":{}}"#, #"{"returnCode":0,"message":"SECRET-SENTINEL"}"#, #"{"returnCode":1,"content":[]}"#, #"[]"#] {
            XCTAssertThrowsError(try BackendDiscovery.receipt(response: wire(raw), status: 200, key: key, iv: iv))
        }
        for status in [301, 401, 500] {
            XCTAssertThrowsError(try BackendDiscovery.receipt(response: wire(#"{"returnCode":1,"content":{}}"#), status: status, key: key, iv: iv))
        }
        XCTAssertThrowsError(try BackendDiscovery.receipt(response: Data(repeating: 65, count: BackendDiscovery.maximumResponse + 1), status: 200, key: key, iv: iv))
        XCTAssertThrowsError(try BackendDiscovery.receipt(response: Data("SECRET-SENTINEL".utf8), status: 200, key: key, iv: iv))
    }
}
