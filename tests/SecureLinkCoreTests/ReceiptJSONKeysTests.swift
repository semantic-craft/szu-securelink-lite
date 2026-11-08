import Foundation
import XCTest
@testable import SecureLinkTransport

final class ReceiptJSONKeysTests: XCTestCase {
    private func check(_ json: String) throws { try ReceiptJSONKeys.validate(Data(json.utf8)) }
    private func rejects(_ json: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try check(json), file: file, line: line) { error in
            XCTAssertEqual(String(describing: error), "invalidReceipt", file: file, line: line)
        }
    }
    private var receipt: String {
        #"{"mode":"bounded-handshake-probe","reason":"input-validated","connectCalled":false,"socketObserved":false,"tunnelSetupRequested":false,"tunnelStarted":false,"connected":false,"routesChanged":false,"dnsChanged":false,"deadlineReached":false,"unexpectedConnected":false,"eventsDropped":false,"events":[],"vendorConfusion":false,"clientCertificateSuppressed":false,"activeShapingNotExercised":false,"gmsslRenegotiationNotExercised":false}"#
    }
    func testDuplicateKeysCannotBeErasedByDecoding() throws {
        for value in [
            #"{"ctrlOptionCount":0,"ctrlOptionCount":1}"#,
            #"{"plan":{"ctrlMappings":[],"ctrlMappings":["SECRET"]}}"#,
            #"{"items":[{"x":1,"x":2}]}"#,
            #"{"unknown":{"SECRET":1,"SECRET":2}}"#,
            #"{"domain":1,"\u0064omain":2}"#,
            #"{"😀":1,"\uD83D\uDE00":2}"#,
            #"{"a\"b":1,"a\u0022b":2}"#
        ] { rejects(value) }
        let poisoned = String(receipt.dropLast()) + #", "reason":"SECRET"}"#
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(Data(poisoned.utf8), status: 0, allowNetwork: false)) { error in
            XCTAssertEqual(String(describing: error), "invalidReceipt")
        }
        let nested = String(receipt.dropLast()) + #", "unknown":{"ctrlMappings":[],"ctrlMappings":["SECRET"]}}"#
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(Data(nested.utf8), status: 0, allowNetwork: false))
    }
    func testNormalUnknownFieldsAndIndependentObjectScopesRemainAccepted() throws {
        try check(#"{"a":{"x":1},"b":{"x":2},"strings":["SECRET: not a key", "a\"b", "\\"],"number":-1.2e+30,"values":[null,true,false]}"#)
        let extended = String(receipt.dropLast()) + #", "unknown":{"items":[{"x":1},{"x":2}],"note":"SECRET"}}"#
        let result = try OpenVPNHandshake.receipt(Data(extended.utf8), status: 0, allowNetwork: false)
        let encoded = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
        XCTAssertFalse(encoded.contains("SECRET"))
        XCTAssertFalse(encoded.contains("unknown"))
    }
    func testResourceAndSyntaxBoundariesFailWithFixedError() throws {
        try check(String(repeating: "[", count: 64) + "0" + String(repeating: "]", count: 64))
        rejects(String(repeating: "[", count: 65) + "0" + String(repeating: "]", count: 65))
        try check("[" + Array(repeating: "0", count: 8191).joined(separator: ",") + "]")
        rejects("[" + Array(repeating: "0", count: 8192).joined(separator: ",") + "]")
        try check("{}" + String(repeating: " ", count: 65_534))
        rejects("{}" + String(repeating: " ", count: 65_535))
        for invalid in ["", "{}{}", "{", "[1,]", "{\"x\":1,}", "{\"x\" 1}", "01", "1.", "NaN", "\"\\uD800\"", "\"SECRET\n\""] {
            rejects(invalid)
        }
        XCTAssertThrowsError(try ReceiptJSONKeys.validate(Data([34, 255, 34]))) { error in
            XCTAssertEqual(String(describing: error), "invalidReceipt")
        }
    }
    func testControlPolicyRejectedMustBeAnUncompletedConnectedAttempt() throws {
        let rejected = receipt.replacingOccurrences(of: "input-validated", with: "control-policy-rejected")
            .replacingOccurrences(of: "\"connectCalled\":false", with: "\"connectCalled\":true")
        let parsed = try OpenVPNHandshake.receipt(Data(rejected.utf8), status: 2, allowNetwork: true)
        XCTAssertEqual(parsed.reason, "control-policy-rejected")
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(Data(rejected.utf8), status: 0, allowNetwork: true))
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(Data(rejected.utf8), status: 3, allowNetwork: true))
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(Data(rejected.utf8), status: 2, allowNetwork: false))
        let disconnected = rejected.replacingOccurrences(of: "\"connectCalled\":true", with: "\"connectCalled\":false")
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(Data(disconnected.utf8), status: 2, allowNetwork: true))
        let complete = String(rejected.dropLast()) + #", "planComplete":true}"#
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(Data(complete.utf8), status: 2, allowNetwork: true))
    }
}
