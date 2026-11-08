import XCTest
@testable import SecureLinkCore

final class CASCallbackTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1000)
    private let callback = URL(string: "securelink://sso_login?projectLabel=szu&authToken=synthetic-only")!
    func testRequiresIntentExpiresAndConsumesOnlyOnce() throws {
        var gate = CASCallbackGate()
        XCTAssertThrowsError(try gate.consume(callback, now: now))
        gate.begin(now: now)
        let credential = try gate.consume(callback, now: now.addingTimeInterval(5))
        XCTAssertFalse(String(describing: credential).contains("synthetic-only"))
        XCTAssertFalse(String(reflecting: credential).contains("synthetic-only"))
        let message = try credential.preAuthenticationRequest()
        XCTAssertEqual(message.command, 10)
        XCTAssertThrowsError(try gate.consume(callback, now: now.addingTimeInterval(6)))
        gate.begin(now: now)
        XCTAssertThrowsError(try gate.consume(callback, now: now.addingTimeInterval(300)))
    }
    func testRejectsWrongOrgDuplicateTokensOtherHostsAndRegistration() {
        for raw in ["securelink://sso_login?projectLabel=other&authToken=x", "securelink://sso_login?projectLabel=szu&authToken=x&authToken=y", "securelink://two_factor?projectLabel=szu&authToken=x", "securelink://sso_login?projectLabel=szu&authToken=x&selfRegistration=1", "securelink://sso_login?projectLabel=szu&authToken=", "securelink://evil@sso_login?projectLabel=szu&authToken=x"] {
            var gate = CASCallbackGate(); gate.begin(now: now)
            XCTAssertThrowsError(try gate.consume(URL(string: raw)!, now: now))
        }
    }
}
