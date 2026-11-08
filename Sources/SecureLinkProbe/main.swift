import Foundation
import SecureLinkCore
import SecureLinkTransport

struct Report: Encodable {
    let mode: String
    let organization: String
    let innerCommand: UInt32
    let encryptedFrames: Int
    let campusValidated: Bool
    let blocker: String
}
do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments.count == 1, arguments[0] == "--backend-cas-discovery-test" {
        let report = try await BackendDiscovery.discoverCAS()
        FileHandle.standardOutput.write(try JSONEncoder().encode(report) + Data([10]))
        exit(0)
    }
    if arguments.count == 1, arguments[0] == "--backend-preconfig-test" {
        let report = try await BackendDiscovery.run()
        FileHandle.standardOutput.write(try JSONEncoder().encode(report) + Data([10]))
        exit(0)
    }
    if arguments.count == 2, arguments[0] == "--backend-device-profile-test" {
        let receipt = try NativeDeviceProfileProbe.run(directory: URL(fileURLWithPath: arguments[1]))
        FileHandle.standardOutput.write(try JSONEncoder().encode(receipt) + Data([10]))
        exit(0)
    }
    if arguments.count == 2, arguments[0] == "--verify-vendor-material" {
        _ = try VendorDistribution.settings(app: URL(fileURLWithPath: arguments[1]), pid: ProcessInfo.processInfo.processIdentifier, logPath: "/tmp/szu-material-verification-unused/gui.log")
        FileHandle.standardOutput.write(Data("{\"mode\":\"static-vendor-material-verification\",\"sourceHashMatched\":true,\"settingsParsed\":true,\"socketOpened\":false}\n".utf8))
        exit(0)
    }
    if arguments.count == 4, arguments[0] == "--live-handshake", arguments[1] == "--allow-session-interruption",
       let port = UInt16(arguments[2]), port >= 1024 {
        let publicKey = try Data(contentsOf: URL(fileURLWithPath: arguments[3]))
        let report = try runLiveProbe(publicKeyDER: publicKey, port: port)
        FileHandle.standardOutput.write(try JSONEncoder().encode(report) + Data([10]))
        exit(0)
    }
    guard CommandLine.arguments == [CommandLine.arguments[0], "--self-test"] else {
        FileHandle.standardError.write(Data("Usage: szu-securelink-probe --self-test\nDirect HTTPS discovery (no login): --backend-preconfig-test or --backend-cas-discovery-test. Read-only vendor check: --verify-vendor-material APP_PATH. Offline synthetic fixture only. Live probe requires --live-handshake --allow-session-interruption PORT PUBLIC_KEY_DER.\n".utf8))
        exit(2)
    }
    let fixture = Message(command: 1, payload: Data("{\"fixture\":true}".utf8))
    let cipher = try SessionCipher(key: Data(repeating: 1, count: 16), iv: Data(repeating: 2, count: 16))
    let encrypted = try cipher.encrypt(PlainFrame.encode(fixture))
    let decoded = try PlainFrame.decode(cipher.decrypt(encrypted))
    var stream = EncryptedStreamDecoder()
    let first = try stream.append(Data([3, 0]))
    let second = try stream.append(Data([0, 0, 0xAB, 0xCD, 0xEF]))
    try stream.finish()
    guard decoded == fixture, first.isEmpty, second == [Data([0xAB, 0xCD, 0xEF])] else { exit(1) }
    let report = Report(mode: "offline-synthetic", organization: "szu", innerCommand: decoded.command,
                        encryptedFrames: second.count, campusValidated: false,
                        blocker: "This run is synthetic only; no socket opened and no campus resource validated.")
    let output = try JSONEncoder().encode(report)
    FileHandle.standardOutput.write(output + Data([10]))
} catch {
    FileHandle.standardError.write(Data("Probe failed (no payload or credential logged)\n".utf8)); exit(1)
}
