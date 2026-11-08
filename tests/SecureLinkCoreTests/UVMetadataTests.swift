import XCTest
@testable import SecureLinkCore

final class UVMetadataTests: XCTestCase {
    private var fields: [UVMetadata.Field: String] {
        Dictionary(uniqueKeysWithValues: UVMetadata.Field.allCases.map { ($0, "x") })
    }
    private func input(_ values: [UVMetadata.Field: String], budget: Int = 1900,
                       code: String = "CODE", v4: String = "", v6: String = "") throws -> UVMetadata {
        try UVMetadata(vpnInitInfo: String(repeating: "i", count: 2006 - budget), username: "u",
                       password: "p", openVPNBase: "b", codeForBudget: code, values: values,
                       ipv4Encoded: v4, ipv6Encoded: v6)
    }
    func testOrderAndBudgetCodeNeverExposed() throws {
        let result = try input(fields).build()
        result.withDirectives { text in
            XCTAssertEqual(text, UVMetadata.Field.allCases.map { "setenv \($0.rawValue) x\n" }.joined())
            XCTAssertFalse(text.contains("CODE"))
            XCTAssertFalse(text.contains("UV_CODE"))
        }
    }
    func testMissingRequiredValuesAndInjection() throws {
        var values = fields; values[.deviceID] = nil
        XCTAssertThrowsError(try input(values)) { XCTAssertEqual($0 as? UVMetadata.BuildError, .missingField(.deviceID)) }
        for unsafe in ["x\nremote attacker", "x\r", "x\0", "x\t", "x\u{2028}", "x\\", "x\""] {
            values = fields; values[.extra3] = unsafe
            XCTAssertThrowsError(try input(values)) { XCTAssertEqual($0 as? UVMetadata.BuildError, .unsafeValue) }
        }
    }
    func testOversizedFieldSkippedAndLaterFieldRetained() throws {
        var values = fields; values[.deviceModel] = String(repeating: "z", count: 2000)
        let result = try input(values).build()
        XCTAssertTrue(result.omittedFields.contains(.deviceModel))
        result.withDirectives { text in
            XCTAssertFalse(text.contains("UV_DEVICE_MODEL"))
            XCTAssertTrue(text.contains("setenv UV_EXTRA_PARAM_3 x\n"))
        }
    }
    func testTwoIndependentLengthChecks() throws {
        XCTAssertThrowsError(try input(fields, budget: 5).build()) {
            XCTAssertEqual($0 as? UVMetadata.BuildError, .fixedPartsTooLarge)
        }
        // Internal KEY=value lines can fit while emitted setenv text cannot.
        XCTAssertThrowsError(try input(fields, budget: 400).build()) {
            XCTAssertEqual($0 as? UVMetadata.BuildError, .emittedTextTooLarge)
        }
    }
    func testEmptyFullPayloadDoesNotUseFamilyFallbacks() throws {
        for full in [String?.none, ""] {
            var values = fields; values[.extra5] = full
            let result = try input(values, v4: "short4", v6: "short6").build()
            XCTAssertTrue(result.omittedFields.contains(.extra5))
            result.withDirectives { text in
                XCTAssertFalse(text.contains("UV_EXTRA_PARAM_5"))
                XCTAssertFalse(text.contains("short4"))
                XCTAssertFalse(text.contains("short6"))
            }
        }
    }
    func testFamilyFallbackSelectsByPresenceNotByFit() throws {
        var values = fields; values[.extra5] = String(repeating: "f", count: 2200)
        let result = try input(values, v4: String(repeating: "4", count: 2200), v6: "short6").build()
        XCTAssertTrue(result.omittedFields.contains(.extra5))
        result.withDirectives { text in XCTAssertFalse(text.contains("short6")) }
        try input(values, v6: "short6").build().withDirectives { text in
            XCTAssertTrue(text.contains("setenv UV_EXTRA_PARAM_5 short6\n"))
        }
        try input(values, v4: "short4", v6: "short6").build().withDirectives { text in
            XCTAssertTrue(text.contains("setenv UV_EXTRA_PARAM_5 short4\n"))
        }
    }
    func testUTF8LengthsAndExactFinalBoundary() throws {
        var values = fields; values[.deviceName] = "校园"
        let bytes = UVMetadata.Field.allCases.map { "setenv \($0.rawValue) \(values[$0]!)\n" }.joined().utf8.count
        XCTAssertNoThrow(try input(values, budget: bytes).build())
        XCTAssertThrowsError(try input(values, budget: bytes - 1).build()) {
            XCTAssertEqual($0 as? UVMetadata.BuildError, .emittedTextTooLarge)
        }
    }
    func testDescriptionsAndReflectionRedactValues() throws {
        var values = fields; values[.extra3] = "SENTINEL"
        let metadata = try input(values, code: "SENTINEL")
        let result = try metadata.build()
        for text in [String(describing: metadata), String(reflecting: metadata), String(describing: result), String(reflecting: result)] {
            XCTAssertFalse(text.contains("SENTINEL"))
        }
        XCTAssertEqual(Mirror(reflecting: metadata).children.first?.value as? String, "redacted")
        XCTAssertEqual(Mirror(reflecting: result).children.first?.value as? String, "redacted")
    }
}
