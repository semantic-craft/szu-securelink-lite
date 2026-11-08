import Foundation
import XCTest
@testable import SecureLinkTransport

final class FinanceHomepageObservationTests: XCTestCase {
    private func fixture(_ overrides: [String: Any] = [:]) throws -> FinanceHomepageObservation {
        var body: [String: Any] = [
            "windowTitle": FinanceHomepageObservation.expectedTitle,
            "criteria": Dictionary(uniqueKeysWithValues: FinanceHomepageObservation.criteriaNames.map { ($0, true) }),
            "afterExplicitReload": true, "onCurrentSpace": true, "loggedIn": true,
            "loginFormPresent": false, "officialGUIRunning": false,
            "sensitiveFieldsRecorded": false, "observedAt": "2026-11-06T00:00:00Z"]
        for (key, value) in overrides { body[key] = value }
        return try JSONDecoder().decode(FinanceHomepageObservation.self, from: JSONSerialization.data(withJSONObject: body))
    }

    func testCompleteObservationValidates() throws {
        XCTAssertTrue(try fixture().validated)
    }

    func testEveryGateFieldIsIndividual() throws {
        XCTAssertFalse(try fixture(["windowTitle": "登录"]).validated)
        XCTAssertFalse(try fixture(["criteria": ["常用应用": true]]).validated)
        XCTAssertFalse(try fixture(["afterExplicitReload": false]).validated)
        XCTAssertFalse(try fixture(["onCurrentSpace": false]).validated)
        XCTAssertFalse(try fixture(["loggedIn": false]).validated)
        XCTAssertFalse(try fixture(["loginFormPresent": true]).validated)
        XCTAssertFalse(try fixture(["officialGUIRunning": true]).validated)
        XCTAssertFalse(try fixture(["sensitiveFieldsRecorded": true]).validated)
    }

    func testDecodeAndRoundTripKeepsCriteria() throws {
        let body: [String: Any] = [
            "windowTitle": FinanceHomepageObservation.expectedTitle,
            "criteria": ["常用应用": true, "个人信息": true],
            "afterExplicitReload": true, "onCurrentSpace": true, "loggedIn": true,
            "loginFormPresent": false, "officialGUIRunning": false,
            "sensitiveFieldsRecorded": false, "observedAt": "2026-11-06T00:00:00Z"]
        let data = try JSONSerialization.data(withJSONObject: body)
        let observation = try JSONDecoder().decode(FinanceHomepageObservation.self, from: data)
        XCTAssertFalse(observation.validated)  // partial criteria never validate
        XCTAssertEqual(Set(observation.criteria.keys), ["常用应用", "个人信息"])
    }
}
