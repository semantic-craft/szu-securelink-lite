import Foundation
import XCTest
@testable import SecureLinkTransport

final class OpenVPNDataSessionTests: XCTestCase {
    private var planFixture: [String: Any] { [
        "version": 2, "ctrlOptionsCaptured": true, "ctrlOptionCount": 0, "ctrlDuplicateKeys": 0, "ctrlDuplicateDomains": 0, "ctrlMappings": [], "domainOptionsCaptured": true, "domainOptions": [".example.edu"], "complete": true, "failure": NSNull(), "layer": 3, "mtu": 1500,
        "remote": ["address": "192.0.2.1", "ipv6": false],
        "addresses": [["address": "10.0.0.2", "prefixLength": 24, "gateway": "10.0.0.1", "ipv6": false, "net30": false]],
        "routes": [["address": "198.51.100.0", "prefixLength": 24, "metric": -1, "ipv6": false]],
        "excludedRoutes": [], "routeMetricDefault": -1, "redirect": NSNull(),
        "dns": ["fromDhcp": true, "searchDomains": [], "servers": [["priority": 0,
            "addresses": [["address": "10.0.0.53", "port": 0]], "domains": ["example.edu"]]]],
        "allowIPv4": true, "allowIPv6": false, "allowLocalDNS": false, "sessionNameDiscarded": true
    ] }

    private func receiptFixture(reason: String = "data-session-verified", status: Int32 = 0,
                                mutate: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
        var body: [String: Any] = [
            "mode": "bounded-data-session", "engine": "data-engine-1", "reason": reason,
            "phase": "active", "interface": "utun9", "fdAccepted": true,
            "connectCalled": true, "socketObserved": true, "tunnelSetupRequested": true,
            "tunnelStarted": true, "connectedInDataMode": true,
            "pingRan": true, "pingExitStatus": 0, "pingTransmitted": 3, "pingReceived": 3,
            "digRan": false, "digExitStatus": -1, "digStatus": NSNull(), "digAnswers": -1,
            "digServer": NSNull(), "digName": NSNull(),
            "ctrlPushesObserved": 0, "ctrlUpdatesSent": 0, "ctrlUpdatesFailed": 0,
            "ctrlRoutesPushed": [],
            "planCaptureRequested": true, "planComplete": true, "plan": planFixture,
            "holdMs": 60000, "heartbeatsSent": 42, "disconnectSent": true,
            "deadlineReached": false, "unexpectedConnected": false, "eventsDropped": false,
            "events": ["CONNECTING", "TUN_IFACE_CREATE", "CONNECTED"]
        ]
        mutate(&body)
        return try JSONSerialization.data(withJSONObject: body)
    }

    private func digFixture(status: String = "NOERROR", answers: Int = 2) throws -> Data {
        try receiptFixture { body in
            body["digRan"] = true
            body["digExitStatus"] = 0
            body["digStatus"] = status
            body["digAnswers"] = answers
            body["digServer"] = "192.168.247.6"
            body["digName"] = "szu.edu.cn"
        }
    }

    func testInTunnelDnsProbeEvidence() throws {
        let value = try decoded(try digFixture())
        XCTAssertTrue(value.dnsVerified)
        XCTAssertTrue(value.verified)
        // Echo comparison only binds when the caller configured the probe.
        let echoed = try OpenVPNDataSession.receipt(try digFixture(), status: 0, holdMs: 60000,
                                                    pingCount: 3, digServer: "192.168.247.6", digName: "szu.edu.cn")
        XCTAssertTrue(echoed.dnsVerified)
        // dig evidence without NOERROR or answers proves nothing.
        let servfail = try decoded(try digFixture(status: "SERVFAIL", answers: 0))
        XCTAssertFalse(servfail.dnsVerified)
        let empty = try decoded(try digFixture(answers: 0))
        XCTAssertFalse(empty.dnsVerified)
        let echoMismatch = try receiptFixture { body in
            body["digRan"] = true
            body["digExitStatus"] = 0
            body["digStatus"] = "NOERROR"
            body["digAnswers"] = 2
            body["digServer"] = "192.0.2.53"
            body["digName"] = "szu.edu.cn"
        }
        XCTAssertThrowsError(try OpenVPNDataSession.receipt(echoMismatch, status: 0, holdMs: 60000,
                                                            pingCount: 3, digServer: "192.168.247.6", digName: "szu.edu.cn"))
        let ranWithoutSession = try receiptFixture { body in
            body["digRan"] = true
            body["digExitStatus"] = 0
            body["digStatus"] = "NOERROR"
            body["digAnswers"] = 2
            body["digServer"] = "192.168.247.6"
            body["digName"] = "szu.edu.cn"
            body["connectedInDataMode"] = false
            body["tunnelStarted"] = false
            body["fdAccepted"] = false
            body["phase"] = "cleanup"
            body["interface"] = ""
            body["pingRan"] = false
            body["pingExitStatus"] = -1
            body["pingTransmitted"] = -1
            body["pingReceived"] = -1
            body["reason"] = "transaction-failed"
        }
        XCTAssertThrowsError(try decoded(ranWithoutSession, status: 2))
    }

    private func decoded(_ data: Data, status: Int32 = 0) throws -> OpenVPNDataSession.Receipt {
        try OpenVPNDataSession.receipt(data, status: status, holdMs: 60000, pingCount: 3)
    }

    func testVerifiedReceiptDecodesAndCarriesTunnelTruth() throws {
        let value = try decoded(try receiptFixture())
        XCTAssertTrue(value.verified)
        XCTAssertTrue(value.ran)
        XCTAssertEqual(value.pingReceived, 3)
        XCTAssertEqual(value.events.last, "CONNECTED")
    }

    func testTamperedSessionClaimsAreRefused() throws {
        for (key, replacement) in [("fdAccepted", false), ("tunnelStarted", false),
                                   ("connectedInDataMode", false), ("disconnectSent", false)] as [(String, Any)] {
            let data = try receiptFixture { body in body[key] = replacement }
            XCTAssertThrowsError(try decoded(data), key)
        }
        let unverifiedPing = try receiptFixture { body in
            body["pingReceived"] = 0
            body["reason"] = "data-session-ended"
        }
        let value = try decoded(unverifiedPing, status: 1)
        XCTAssertFalse(value.verified)
        XCTAssertTrue(value.ran)  // session ran even though the peer never answered
    }

    func testPingAccountingBoundsAreEnforced() throws {
        let inflated = try receiptFixture { body in body["pingTransmitted"] = 7 }
        XCTAssertThrowsError(try decoded(inflated))
        let negativePair = try receiptFixture { body in
            body["pingRan"] = false
            body["pingExitStatus"] = -1
            body["pingTransmitted"] = -1
            body["pingReceived"] = -1
            body["reason"] = "connection-ended"
            body["connectedInDataMode"] = false
        }
        XCTAssertNoThrow(try decoded(negativePair, status: 1))
        let ranWithoutCounts = try receiptFixture { body in body["pingReceived"] = -1 }
        XCTAssertThrowsError(try decoded(ranWithoutCounts))
    }

    func testSessionOutcomesImplyTransactionAndViceVersa() throws {
        let sessionWithoutTunnel = try receiptFixture { body in
            body["fdAccepted"] = false
            body["phase"] = "cleanup"
            body["interface"] = ""
            body["tunnelStarted"] = false
            body["connectedInDataMode"] = false
            body["reason"] = "transaction-failed"
        }
        XCTAssertThrowsError(try decoded(sessionWithoutTunnel, status: 2))  // pingRan without a session
        let failedTransaction = try receiptFixture(status: 2) { body in
            body["fdAccepted"] = false
            body["phase"] = "rejected-peer"
            body["interface"] = ""
            body["tunnelStarted"] = false
            body["connectedInDataMode"] = false
            body["pingRan"] = false
            body["pingExitStatus"] = -1
            body["pingTransmitted"] = -1
            body["pingReceived"] = -1
            body["disconnectSent"] = false
            body["heartbeatsSent"] = 0
            body["socketObserved"] = false
            body["events"] = ["CONNECTING"]
            body["reason"] = "transaction-failed"
        }
        let refused = try decoded(failedTransaction, status: 2)
        XCTAssertFalse(refused.ran)
        XCTAssertFalse(refused.verified)
    }

    func testCtrlPushEvidenceAccounting() throws {
        let pushBody = try receiptFixture { body in
            body["ctrlPushesObserved"] = 1
            body["ctrlUpdatesSent"] = 1
            body["ctrlRoutesPushed"] = ["10.10.27.0/24"]
        }
        let value = try decoded(pushBody)
        XCTAssertTrue(value.verified)
        XCTAssertEqual(value.ctrlRoutesPushed, ["10.10.27.0/24"])
        // Every observed push is sent or failed, never neither nor both.
        let unbalanced = try receiptFixture { body in
            body["ctrlPushesObserved"] = 1
            body["ctrlRoutesPushed"] = ["10.10.27.0/24"]
        }
        XCTAssertThrowsError(try decoded(unbalanced))
        let malformedRoute = try receiptFixture { body in
            body["ctrlPushesObserved"] = 1
            body["ctrlUpdatesSent"] = 1
            body["ctrlRoutesPushed"] = ["SECRET-NET/24"]
        }
        XCTAssertThrowsError(try decoded(malformedRoute))
        let badPrefix = try receiptFixture { body in
            body["ctrlPushesObserved"] = 1
            body["ctrlUpdatesSent"] = 1
            body["ctrlRoutesPushed"] = ["10.10.27.0/99"]
        }
        XCTAssertThrowsError(try decoded(badPrefix))
        // A push before the transaction exists fails the session closed; the
        // evidence still decodes against the rejection reason.
        let rejected = try receiptFixture(status: 2) { body in
            body["reason"] = "control-policy-rejected"
            body["phase"] = "idle"
            body["interface"] = ""
            body["fdAccepted"] = false
            body["tunnelStarted"] = false
            body["connectedInDataMode"] = false
            body["pingRan"] = false
            body["pingExitStatus"] = -1
            body["pingTransmitted"] = -1
            body["pingReceived"] = -1
            body["disconnectSent"] = false
            body["heartbeatsSent"] = 0
            body["socketObserved"] = false
            body["tunnelSetupRequested"] = false
            body["plan"] = NSNull()
            body["planComplete"] = false
            body["events"] = ["CONNECTING"]
            body["ctrlPushesObserved"] = 1
            body["ctrlUpdatesSent"] = 0
            body["ctrlUpdatesFailed"] = 1
            body["ctrlRoutesPushed"] = ["10.10.27.0/24"]
        }
        let refused = try decoded(rejected, status: 2)
        XCTAssertFalse(refused.ran)
        XCTAssertFalse(refused.verified)
    }

    func testExitStatusMustPairWithReason() throws {
        let data = try receiptFixture()
        XCTAssertThrowsError(try decoded(data, status: 1))
        XCTAssertThrowsError(try decoded(data, status: 2))
        XCTAssertThrowsError(try decoded(data, status: 3))
        let stranger = try receiptFixture(reason: "SECRET-REASON")
        XCTAssertThrowsError(try decoded(stranger))
        let strangerEvent = try receiptFixture { body in body["events"] = ["SECRET-EVENT"] }
        XCTAssertThrowsError(try decoded(strangerEvent))
        let duplicateKeys = Data(#"{"mode":"bounded-data-session","mode":"bounded-data-session"}"#.utf8)
        XCTAssertThrowsError(try ReceiptJSONKeys.validate(duplicateKeys))
    }

    func testPlanBookkeepingMustMatchCapture() throws {
        let missingPlan = try receiptFixture { body in body["plan"] = NSNull() }
        XCTAssertThrowsError(try decoded(missingPlan))
        let prematureComplete = try receiptFixture { body in
            body["plan"] = NSNull()
            body["planComplete"] = false
            body["reason"] = "transaction-failed"
        }
        // Receipt without a captured plan can only be an early transaction
        // failure; session claims would make the bookkeeping inconsistent.
        XCTAssertThrowsError(try decoded(prematureComplete, status: 2))
    }

    func testParseActiveLineExtractsInterfaceAndVirtualIPv4() {
        XCTAssertEqual(
            OpenVPNDataSession.parseActiveLine("engine: active on utun9 vip=1.1.105.34"),
            OpenVPNDataSession.ActiveState(interface: "utun9", virtualIPv4: "1.1.105.34")
        )
        XCTAssertEqual(
            OpenVPNDataSession.parseActiveLine("engine: active on utun12"),
            OpenVPNDataSession.ActiveState(interface: "utun12", virtualIPv4: nil)
        )
        XCTAssertEqual(
            OpenVPNDataSession.parseActiveLine("engine: active on utun9 vip=not-an-ip"),
            OpenVPNDataSession.ActiveState(interface: "utun9", virtualIPv4: nil)
        )
        XCTAssertNil(OpenVPNDataSession.parseActiveLine("engine: active on en0"))
        XCTAssertNil(OpenVPNDataSession.parseActiveLine("other log line"))
    }
}
