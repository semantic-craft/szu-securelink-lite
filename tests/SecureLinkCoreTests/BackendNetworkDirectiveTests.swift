import Foundation
import XCTest
@testable import SecureLinkTransport

final class BackendNetworkDirectiveTests: XCTestCase {
    func testPlainDirectivesRespectWhitespaceAndComments() {
        let input = "  gmtls\n\ttls-proxy SECRET\nblack-hole-route\n# gmtls\n; tls-proxy\nunknown-secret value"
        XCTAssertEqual(BackendNetworkConfiguration.directives(input), ["gmtls": true, "tls-proxy": true, "black-hole-route": true])
        XCTAssertEqual(BackendNetworkConfiguration.directives("# gmtls\n ; tls-proxy\nremote gmtls\ngmtls-extra"), ["gmtls": false, "tls-proxy": false, "black-hole-route": false])
    }
    func testQueryEscapesAndPlusSpacesAreDecodedOnce() {
        let input = "%20gmtls%0A%09tls-proxy+SECRET%0Ablack-hole-route%0A"
        XCTAssertEqual(BackendNetworkConfiguration.directives(input), ["gmtls": true, "tls-proxy": true, "black-hole-route": true])
        XCTAssertEqual(BackendNetworkConfiguration.directives("%2567mtls")["gmtls"], false)
        XCTAssertEqual(BackendNetworkConfiguration.directives("gmtls%ZZ")["gmtls"], false)
    }
    func testInlineCertificatesAndUnknownPayloadBlocksAreOpaque() {
        let input = "<ca>\ngmtls\ntls-proxy\nblack-hole-route\n</ca>\n<unknown>\ngmtls\n</unknown>\n  tls-proxy"
        XCTAssertEqual(BackendNetworkConfiguration.directives(input), ["gmtls": false, "tls-proxy": true, "black-hole-route": false])
        XCTAssertEqual(BackendNetworkConfiguration.directives("<ca>\ngmtls\n</wrong>\nblack-hole-route")["black-hole-route"], false)
    }
    func testUnreliableSyntaxAndInvalidEscapeRemainUnknown() {
        XCTAssertFalse(BackendNetworkConfiguration.analyzeDirectives("gmtls%ZZ").complete)
        XCTAssertFalse(BackendNetworkConfiguration.analyzeDirectives("\"gmtls\"").complete)
        XCTAssertFalse(BackendNetworkConfiguration.analyzeDirectives("<ca>\ngmtls").complete)
        for input in ["g\\mtls", "<broken", "</ca>", "config SECRET", "include SECRET", "gm\"tls\"", "gm'tls'"] {
            XCTAssertFalse(BackendNetworkConfiguration.analyzeDirectives(input).complete)
        }
        XCTAssertTrue(BackendNetworkConfiguration.analyzeDirectives("# comment\ngmtls").complete)
    }
    func testReceiptRetainsOnlyFixedNamesAndNoParameters() throws {
        let data = try JSONSerialization.data(withJSONObject: ["returnCode": 1, "content": ["networkConfig": ["clientConf": "tls-proxy SECRET-SENTINEL\nSECRET-NAME SECRET-SENTINEL"]]])
        let config = try BackendNetworkConfiguration.parse(data)
        let receipt = String(decoding: try JSONEncoder().encode(config.receipt), as: UTF8.self)
        XCTAssertTrue(config.receipt.directivePresence["tls-proxy"] == true)
        XCTAssertEqual(config.receipt.directivePresence.count, 3)
        XCTAssertFalse(receipt.contains("SECRET"))
        XCTAssertFalse(config.receipt.tunnelSupported)
    }
}
