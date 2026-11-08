import Foundation
import XCTest
@testable import SecureLinkTransport

final class BackendNetworkFailureTests: XCTestCase {
    private func failure(_ json: String) throws -> BackendNetworkConfigurationFailure {
        do { _ = try BackendNetworkConfiguration.parse(Data(json.utf8)); throw NSError(domain: "Expected failure", code: 1) }
        catch let failure as BackendNetworkConfigurationFailure { return failure }
    }
    func testStringWrappedContentHasSafeShapeAndPath() throws {
        let error = try failure(#"{"returnCode":1,"content":"SECRET-SENTINEL"}"#)
        XCTAssertEqual(error.shape["content"], "string")
        XCTAssertEqual(error.shape["decodePath"], "content")
        XCTAssertEqual(error.shape["returnCodeValue"], "1")
        var dumpText = ""; dump(error, to: &dumpText)
        for text in [dumpText, String(reflecting: error), String(describing: error), String(decoding: try JSONEncoder().encode(error.shape), as: UTF8.self)] {
            XCTAssertFalse(text.contains("SECRET"))
        }
    }
    func testKnownNestedMismatchAndArrayIndexAreWhitelisted() throws {
        let nested = try failure(#"{"returnCode":1,"content":{"networkConfig":{"clientCert":{"enable":"SECRET"}}}}"#)
        XCTAssertEqual(nested.shape["content.networkConfig.clientCert.enable"], "string")
        XCTAssertEqual(nested.shape["decodePath"], "content.networkConfig.clientCert.enable")
        let array = try failure(#"{"returnCode":1,"content":{"networkConfig":{"priorServers":[{"ports":["SECRET"]}]}}}"#)
        XCTAssertEqual(array.shape["decodePath"], "content.networkConfig.priorServers.[].ports.[]")
    }
    func testReturnCodeBoundsAndBooleanAreNotCoerced() throws {
        XCTAssertEqual(try failure(#"{"returnCode":2041}"#).shape["returnCodeValue"], "2041")
        XCTAssertNil(try failure(#"{"returnCode":true}"#).shape["returnCodeValue"])
        XCTAssertEqual(try failure(#"{"returnCode":1000001}"#).shape["returnCodeValue"], "outside-safe-integer-range")
        XCTAssertEqual(try failure(#"{"returnCode":1.5}"#).shape["returnCodeValue"], "outside-safe-integer-range")
        XCTAssertEqual(try failure("SECRET not JSON").shape["root"], "missing")
    }
    func testUnknownCodingKeysAndDescriptionsCannotLeak() throws {
        struct Key: CodingKey { let stringValue: String; let intValue: Int? = nil; init?(intValue: Int) { return nil }; init(stringValue: String) { self.stringValue = stringValue } }
        let context = DecodingError.Context(codingPath: [Key(stringValue: "SECRET-KEY")], debugDescription: "SECRET-DEBUG")
        let error = BackendNetworkConfigurationFailure.make(Data(#"{"SECRET-KEY":"SECRET"}"#.utf8), reason: .invalidResponse, decodingError: DecodingError.dataCorrupted(context))
        XCTAssertEqual(error.shape["decodePath"], "unknown")
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(error.shape), as: UTF8.self).contains("SECRET"))
    }
}
