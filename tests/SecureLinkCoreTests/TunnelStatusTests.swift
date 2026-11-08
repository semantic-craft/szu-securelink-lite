import XCTest
@testable import SecureLinkCore

final class TunnelStatusTests: XCTestCase {
    func testOnlyExplicitContentStateCanConnect() {
        for state in ["connected", "CONNECTED"] {
            XCTAssertEqual(TunnelStatus.decode(Data("{\"content\":{\"state\":\"\(state)\"}}".utf8)), .connected)
        }
        for payload in ["null", "[]", "{}", "{\"state\":\"CONNECTED\"}", "{\"content\":{\"state\":true}}", "{\"content\":{\"state\":\"NEW_STATE\"}}"] {
            XCTAssertEqual(TunnelStatus.decode(Data(payload.utf8)), .unknown)
        }
    }
    func testDisconnectIsNotConnected() {
        XCTAssertEqual(TunnelStatus.decode(Data("{\"content\":{\"state\":\"DISCONNECTED\",\"secret\":\"synthetic\"}}".utf8)), .disconnected)
    }
}
