import XCTest
@testable import SecureLinkCore

final class CASDiscoveryTests: XCTestCase {
    private let safe = "https://authserver.szu.edu.cn/authserver/login?service=https%3A%2F%2Fsecurelinksso.wangsu.com%2Fsynthetic"
    private func reply(_ id: String, _ content: [String: Any], code: Any = 1) throws -> Message {
        Message(command: 28, payload: try JSONSerialization.data(withJSONObject: ["id": id, "returnCode": code, "content": content]))
    }
    func testDiscoveryUsesServerProviderAndCorrelatesReplies() throws {
        var flow = CASDiscovery(identifier: "test")
        _ = try flow.begin()
        if case .ignored = try flow.receive(reply("unrelated", [:])) {} else { XCTFail() }
        guard case .request(let request) = try flow.receive(reply("test-config", ["list": [["name": "synthetic-cas", "reportType": 9]]])) else { return XCTFail() }
        let body = try JSONSerialization.jsonObject(with: request.payload) as! [String: Any]
        XCTAssertEqual((body["body"] as? [String: String])?["name"], "synthetic-cas")
        guard case .ready(let url) = try flow.receive(reply("test-url", ["action": 2, "loginUrl": safe])) else { return XCTFail() }
        XCTAssertEqual(url.host, "authserver.szu.edu.cn")
        XCTAssertThrowsError(try flow.receive(reply("test-url", ["action": 2, "loginUrl": safe])))
    }
    func testURLRejectsLookalikesPlainHTTPDuplicateServiceAndForeignRecipient() throws {
        _ = try CASDiscovery.validateLoginURL(safe)
        for url in [safe.replacingOccurrences(of: "authserver.szu.edu.cn", with: "authserver.szu.edu.cn.evil.test"), safe.replacingOccurrences(of: "https://", with: "http://"), safe + "&service=https://evil.test", safe.replacingOccurrences(of: "securelinksso.wangsu.com", with: "evil.test"), safe + "#fragment"] {
            XCTAssertThrowsError(try CASDiscovery.validateLoginURL(url))
        }
    }
    func testRejectsServerDenialAmbiguousProvidersAndBooleanCode() throws {
        for message in [try reply("test-config", [:], code: 3001), try reply("test-config", [:], code: true), try reply("test-config", ["list": [["name": "a", "reportType": 9], ["name": "b", "reportType": 9]]])] {
            var flow = CASDiscovery(identifier: "test")
            _ = try flow.begin()
            XCTAssertThrowsError(try flow.receive(message))
        }
    }
}
