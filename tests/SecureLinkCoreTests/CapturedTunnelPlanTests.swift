import Foundation
import XCTest
@testable import SecureLinkTransport

final class CapturedTunnelPlanTests: XCTestCase {
    private var fixture: [String: Any] { [
        "version": 2, "ctrlOptionsCaptured": true, "ctrlOptionCount": 0, "ctrlDuplicateKeys": 0, "ctrlDuplicateDomains": 0, "ctrlMappings": [], "domainOptionsCaptured": true, "domainOptions": [".example.edu"], "complete": true, "failure": NSNull(), "layer": 3, "mtu": 1500,
        "remote": ["address": "192.0.2.1", "ipv6": false],
        "addresses": [["address": "10.0.0.2", "prefixLength": 24, "gateway": "10.0.0.1", "ipv6": false, "net30": false]],
        "routes": [["address": "198.51.100.0", "prefixLength": 24, "metric": -1, "ipv6": false]],
        "excludedRoutes": [], "routeMetricDefault": -1, "redirect": NSNull(),
        "dns": ["fromDhcp": true, "searchDomains": [], "servers": [["priority": 0,
            "addresses": [["address": "10.0.0.53", "port": 0]], "domains": ["example.edu"]]]],
        "allowIPv4": true, "allowIPv6": false, "allowLocalDNS": false, "sessionNameDiscarded": true
    ] }
    private func decode(_ object: [String: Any]) throws -> CapturedTunnelPlan {
        let value = try JSONDecoder().decode(CapturedTunnelPlan.self, from: JSONSerialization.data(withJSONObject: object))
        try value.validate()
        return value
    }
    func testCapturePreservesPolicyButDropsUnrecognizedIdentityFields() throws {
        var value = fixture
        value["sessionName"] = "SECRET-USER"
        value["redirect"] = ["ipv4": true, "ipv6": false, "flags": 1]
        let plan = try decode(value)
        XCTAssertTrue(plan.complete)
        // Capturing a broad policy does not approve it for execution.
        XCTAssertEqual(plan.redirect?.ipv4, true)
        let output = String(decoding: try JSONEncoder().encode(plan), as: UTF8.self)
        let roundtrip = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(plan)) as? [String: Any])
        XCTAssertTrue(roundtrip["failure"] is NSNull)
        XCTAssertEqual(Set(roundtrip.keys), Set(fixture.keys))
        XCTAssertFalse(output.contains("SECRET"))
        XCTAssertFalse(output.contains("sessionName\""))
    }
    func testRejectsUnboundedOrUntrustedNetworkFields() throws {
        for (key, bad) in [("failure", "SECRET-ERROR" as Any), ("mtu", 65536), ("version", 1),
                           ("layer", 2), ("routeMetricDefault", Int64.max), ("domainOptionsCaptured", false), ("domainOptions", ["*"]),
                           ("remote", ["address": "server.example; command", "ipv6": false]),
                           ("routes", Array(repeating: ["address": "198.51.100.0", "prefixLength": 24, "metric": -1, "ipv6": false], count: 65))] {
            var value = fixture; value[key] = bad
            XCTAssertThrowsError(try decode(value), key)
        }
        for badDomain in ["", "secret\n.example", "-bad.example", "bad..example", String(repeating: "a", count: 64)] {
            var value = fixture
            value["dns"] = ["fromDhcp": true, "searchDomains": [badDomain], "servers": []]
            XCTAssertThrowsError(try decode(value))
        }
    }
    func testStaticControlMappingsStaySeparateFromDomainRulesAndRequireCompleteCapture() throws {
        var value = fixture
        value["ctrlOptionCount"] = 1
        value["ctrlMappings"] = [["domain": "portal.example.edu", "addresses": ["192.0.2.5"], "addressPolicy": "any"]]
        let plan = try decode(value)
        XCTAssertEqual(plan.ctrlMappings[0].domain, "portal.example.edu")
        XCTAssertEqual(plan.domainOptions, [".example.edu"])
        for change: [String: Any] in [["ctrlOptionsCaptured": false], ["ctrlOptionCount": 0],
                                     ["ctrlDuplicateDomains": 1], ["ctrlDuplicateKeys": -1],
                                     ["ctrlMappings": [["domain": "*.example.edu", "addresses": ["192.0.2.5"], "addressPolicy": "any"]]],
                                     ["ctrlMappings": [["domain": "portal.example.edu", "addresses": ["2001:db8::5"], "addressPolicy": "any"]]]] {
            XCTAssertThrowsError(try decode(value.merging(change) { _, new in new }))
        }
    }

    func testIncompleteCaptureCannotClaimComplete() throws {
        var value = fixture
        value["mtu"] = NSNull()
        XCTAssertTrue(try decode(value).complete) // callback completeness does not invent effective MTU
        value["addresses"] = []
        XCTAssertThrowsError(try decode(value))
        value["complete"] = false
        value["failure"] = "incomplete-plan"
        XCTAssertFalse(try decode(value).complete)
    }
}
