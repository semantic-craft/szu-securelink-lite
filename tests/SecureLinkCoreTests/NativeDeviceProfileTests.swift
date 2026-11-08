import XCTest
@testable import SecureLinkTransport

final class NativeDeviceProfileTests: XCTestCase {
    func testOnlyRecognizedHardwarePortsContributeFullMacs() {
        let ports = [("Wi-Fi", "AA-BB-CC-DD-EE-02"), ("USB Ethernet", "aa:bb:cc:dd:ee:03"),
                     ("AirPort", "aa:bb:cc:dd:ee:01"), ("Thunderbolt Bridge", "aa:bb:cc:dd:ee:04"),
                     ("Ethernet", "N/A"), ("Wi-Fi", "partial")]
        XCTAssertEqual(NativeDeviceProfile.selectMacs(ports), "AA:BB:CC:DD:EE:02,aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:03")
        XCTAssertEqual(NativeDeviceProfile.selectMacs([]), "-")
    }
    func testHardwareInventoryCapAndProtocolTypes() {
        let wireless = (0..<25).map { String(format: "aa:bb:cc:dd:ee:%02x", $0) }
        let macs = NativeDeviceProfile.macList(wireless: wireless.reversed(), wired: ["ff:ee:dd:cc:bb:aa"])
        XCTAssertEqual(macs.split(separator: ",").count, 21)
        XCTAssertTrue(macs.hasSuffix("ff:ee:dd:cc:bb:aa"))
        let profile = NativeDeviceProfile(deviceID: "PRIVATE-ID", deviceName: "PRIVATE-NAME", deviceModel: "fixture",
                                          systemModel: "macOS fixture", architecture: "arm64", deviceMac: "-", serialNumber: "PRIVATE-SERIAL")
        XCTAssertEqual(profile.loginFields["system"] as? String, "3")
        XCTAssertEqual(profile.loginFields["archType"] as? Int, 11)
        XCTAssertEqual(profile.loginFields["systemName"] as? String, "macOS fixture(arm64)")
        XCTAssertFalse(String(describing: profile).contains("PRIVATE"))
        var rendered = ""
        dump(profile, to: &rendered)
        XCTAssertFalse(rendered.contains("PRIVATE"))
    }
}
