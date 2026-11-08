import Foundation
import XCTest
@testable import SecureLinkTransport

final class OpenVPNHandshakeTests: XCTestCase {
    func testRealHelperValidatesPrivateInputWithoutNetwork() async throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let executable = root.appendingPathComponent("out/openvpn3/build/szu-openvpn3-handshake")
        guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw XCTSkip("Optional source helper not built") }
        let input = try OpenVPNHandshakeInput(configuration: "client\ndev tun\nremote 192.0.2.1 1194 udp\nauth-user-pass\n",
                                             username: "SECRET-USER", password: "SECRET-PASSWORD", peerInfo: ["UV_CODE": "SECRET-TOKEN"])
        var rendered = ""; dump(input, to: &rendered)
        XCTAssertFalse(rendered.contains("SECRET"))
        let receipt = try await OpenVPNHandshake.perform(input, executable: executable)
        XCTAssertEqual(receipt.reason, "input-validated")
        XCTAssertFalse(receipt.connectCalled)
        XCTAssertFalse(receipt.socketObserved)
        XCTAssertFalse(receipt.tunnelStarted)
        XCTAssertFalse(receipt.vendorConfusion)
        XCTAssertFalse(receipt.clientCertificateSuppressed)
        let encoded = try JSONEncoder().encode(receipt)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        for field in ["connectCalled", "socketObserved", "tunnelStarted", "routesChanged", "dnsChanged"] {
            object[field] = true
            XCTAssertThrowsError(try OpenVPNHandshake.receipt(JSONSerialization.data(withJSONObject: object), status: 0, allowNetwork: false))
            object[field] = false
        }
        object["events"] = ["SECRET-UNKNOWN"]
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(JSONSerialization.data(withJSONObject: object), status: 0, allowNetwork: false))
        object["events"] = []
        object["clientCertificateSuppressed"] = true
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(JSONSerialization.data(withJSONObject: object), status: 0, allowNetwork: false))
    }
    func testConfusionInputKeepsProbeOnlyFeaturesExplicit() async throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let executable = root.appendingPathComponent("out/openvpn3/build/szu-openvpn3-handshake")
        guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw XCTSkip("Optional source helper not built") }
        let input = try OpenVPNHandshakeInput(configuration: "client\ndev tun\nremote 192.0.2.1 1194 tcp\nauth-user-pass\n",
            username: "SECRET-USER", password: "-", peerInfo: ["UV_CODE": "SECRET-TOKEN"], vendorConfusion: true,
            activeShapingNotExercised: true, gmsslRenegotiationNotExercised: true)
        let receipt = try await OpenVPNHandshake.perform(input, executable: executable)
        XCTAssertEqual(receipt.reason, "input-validated")
        XCTAssertTrue(receipt.vendorConfusion)
        XCTAssertTrue(receipt.clientCertificateSuppressed)
        XCTAssertTrue(receipt.activeShapingNotExercised)
        XCTAssertTrue(receipt.gmsslRenegotiationNotExercised)
        XCTAssertFalse(receipt.connectCalled)
        XCTAssertFalse(receipt.tunnelStarted)
        let capture = try await OpenVPNHandshake.perform(input, executable: executable, capturePlan: true)
        XCTAssertEqual(capture.reason, "input-validated")
        XCTAssertEqual(capture.planCaptureRequested, true)
        XCTAssertEqual(capture.planComplete, false)
        XCTAssertNil(capture.plan)
        let encoded = try JSONEncoder().encode(capture)
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(encoded, status: 0, allowNetwork: false))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object["planComplete"] = true
        XCTAssertThrowsError(try OpenVPNHandshake.receipt(JSONSerialization.data(withJSONObject: object), status: 0, allowNetwork: false, capturePlan: true))
    }
    func testPeerInformationMustUseKnownKeysAndSafeValues() {
        for peer in [["UNKNOWN": "SECRET"], ["UV_CODE": "x\ny"], ["UV_CODE": ""], ["UV_CODE": String(repeating: "x", count: 8193)]] {
            XCTAssertThrowsError(try OpenVPNHandshakeInput(configuration: "client", username: "fixture", password: "fixture", peerInfo: peer))
        }
    }
}
