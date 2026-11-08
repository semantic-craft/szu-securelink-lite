import Foundation
import SystemConfiguration
import IOKit
import Darwin

public enum NativeDeviceProfileError: Error { case unavailable }

struct NativeDeviceProfile: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let deviceID: String
    let deviceName: String
    let deviceModel: String
    let systemModel: String
    let architecture: String
    let deviceMac: String
    let serialNumber: String
    var description: String { "NativeDeviceProfile(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: ["values": "redacted"], displayStyle: .struct) }

    static func collect(directory: URL) throws -> Self {
        let identity = try NativeDeviceIdentity.loadOrCreate(directory: directory)
        let plistURL = URL(fileURLWithPath: "/System/Library/CoreServices/SystemVersion.plist")
        guard let plist = try PropertyListSerialization.propertyList(from: Data(contentsOf: plistURL), format: nil) as? [String: Any],
              let product = plist["ProductName"] as? String, let version = plist["ProductVersion"] as? String,
              let name = Host.current().localizedName, !name.isEmpty else { throw NativeDeviceProfileError.unavailable }
        let architecture: String
        if systemInteger("hw.optional.arm64") == 1 { architecture = "arm64" }
        else if systemInteger("hw.optional.x86_64") == 1 { architecture = "x86_64" }
        else { throw NativeDeviceProfileError.unavailable }
        let platform = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard platform != 0 else { throw NativeDeviceProfileError.unavailable }
        defer { IOObjectRelease(platform) }
        guard let serial = IORegistryEntryCreateCFProperty(platform, "IOPlatformSerialNumber" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String,
              !serial.isEmpty else { throw NativeDeviceProfileError.unavailable }
        let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] ?? []
        let ports = interfaces.compactMap { interface -> (String, String)? in
            guard let name = SCNetworkInterfaceGetLocalizedDisplayName(interface) as String?,
                  let address = SCNetworkInterfaceGetHardwareAddressString(interface) as String? else { return nil }
            return (name, address)
        }
        return Self(deviceID: identity.value, deviceName: name, deviceModel: try systemString("hw.model"),
                    systemModel: product + " " + version, architecture: architecture,
                    deviceMac: selectMacs(ports), serialNumber: serial)
    }

    static func selectMacs(_ ports: [(String, String)]) -> String {
        var wireless: [String] = [], wired: [String] = []
        for (name, address) in ports {
            let mac = address.replacingOccurrences(of: "-", with: ":")
            guard mac.range(of: #"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"#, options: .regularExpression) != nil else { continue }
            if name.contains("Wi-Fi") || name.contains("AirPort") { wireless.append(mac) }
            else if name.contains("Ethernet") { wired.append(mac) }
        }
        return macList(wireless: wireless, wired: wired)
    }
    static func macList(wireless: [String], wired: [String]) -> String {
        let parts = [wireless, wired].map { $0.sorted().prefix(20).joined(separator: ",") }.filter { !$0.isEmpty }
        return parts.isEmpty ? "-" : parts.joined(separator: ",")
    }
    var loginFields: [String: Any] {
        ["version": "3.11.1", "system": "3", "systemName": systemModel + "(" + architecture + ")",
         "deviceId": deviceID, "deviceName": deviceName, "deviceModel": deviceModel,
         "systemModel": systemModel, "systemBits": architecture.contains("64") ? "64" : "32",
         "deviceMac": deviceMac, "archType": architecture == "arm64" ? 11 : 3, "serialNumber": serialNumber]
    }
    private static func systemString(_ name: String) throws -> String {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 1, size < 4096 else { throw NativeDeviceProfileError.unavailable }
        var bytes = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &bytes, &size, nil, 0) == 0 else { throw NativeDeviceProfileError.unavailable }
        return String(decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
    private static func systemInteger(_ name: String) -> Int32? {
        var value: Int32 = 0, size = MemoryLayout<Int32>.size
        return sysctlbyname(name, &value, &size, nil, 0) == 0 ? value : nil
    }
}

public enum NativeDeviceProfileProbe {
    public struct Receipt: Encodable {
        public let result = "native-device-profile-collected"
        public let officialArtifactRequired = false
        public let officialIdentityCopied = false
        public let networkRequestSent = false
        public let deviceTrustValidated = false
        public let privateValuesInReceipt = false
        public let deviceIdentityPersisted = true
    }
    public static func run(directory: URL) throws -> Receipt {
        _ = try NativeDeviceProfile.collect(directory: directory)
        return Receipt()
    }
}
