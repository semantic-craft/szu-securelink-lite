import XCTest
import Foundation
@testable import SecureLinkTransport

final class VendorDistributionTests: XCTestCase {
    private func source(duplicate: Bool = false, missing: Bool = false) throws -> String {
        func field(_ key: String, _ value: String) throws -> String {
            let hex = value.utf8.map { String(format: "%02x", $0) }.joined().map(String.init)
            let array = String(decoding: try JSONSerialization.data(withJSONObject: hex), as: UTF8.self)
            return "\(key):Buffer.from(\(array).join(\"\")||\"\",\"hex\").toString()"
        }
        var fields = [try field("sheetaApiCertId", "test-id"), try field("sheetaApiCertKey", "test-only-key")]
        if !missing { fields.append(try field("sheetaApiPublicKey", "-----BEGIN PUBLIC KEY-----\nsynthetic\n-----END PUBLIC KEY-----")) }
        if duplicate { fields.append(fields[0]) }
        return "getClientConf:()=>({" + fields.joined(separator: ",") + "})"
    }
    func testParsesOnlyLiteralHexMaterialWithoutExecutingSource() throws {
        let settings = try VendorDistribution.settingsFromPinnedSource(source(), pid: 123, logPath: "/tmp/synthetic/log")
        XCTAssertFalse(String(reflecting: settings).contains("test-only-key"))
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: settings.message().payload) as? [String: Any])
        XCTAssertEqual(fields["sheetaApiCertKey"] as? String, "test-only-key")
    }
    func testRejectsDuplicateMissingAndNonLiteralFields() throws {
        for value in [try source(duplicate: true), try source(missing: true), "getClientConf:()=>({sheetaApiCertId:runCode()})"] {
            XCTAssertThrowsError(try VendorDistribution.settingsFromPinnedSource(value, pid: 123, logPath: "/tmp/synthetic/log"))
        }
    }
}
