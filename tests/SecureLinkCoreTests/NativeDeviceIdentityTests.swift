import Foundation
import XCTest
import Darwin
@testable import SecureLinkTransport

final class NativeDeviceIdentityTests: XCTestCase {
    func testGeneratedIdentityValidatesWithoutExposingValue() throws {
        let identity = NativeDeviceIdentity.generate()
        XCTAssertEqual(try NativeDeviceIdentity.validate(identity.value).value, identity.value)
        XCTAssertFalse(String(describing: identity).contains(identity.value))
        XCTAssertFalse(String(reflecting: identity).contains(identity.value))
        var rendered = ""
        dump(identity, to: &rendered)
        XCTAssertFalse(rendered.contains(identity.value))
        var tampered = Array(identity.value.utf8)
        tampered[18] = tampered[18] == 48 ? 49 : 48
        XCTAssertThrowsError(try NativeDeviceIdentity.validate(String(decoding: tampered, as: UTF8.self)))
    }
    func testPersistentIdentityIsReusedAndCorruptionIsNotOverwritten() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = try NativeDeviceIdentity.loadOrCreate(directory: directory)
        XCTAssertEqual(try NativeDeviceIdentity.loadOrCreate(directory: directory).value, first.value)
        let file = directory.appendingPathComponent("device-id")
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        try Data("corrupt".utf8).write(to: file)
        XCTAssertThrowsError(try NativeDeviceIdentity.loadOrCreate(directory: directory))
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "corrupt")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["device-id"])
    }
    func testIdentityFIFOIsRejectedWithoutWaitingForAWriter() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        XCTAssertEqual(mkfifo(directory.appendingPathComponent("device-id").path, 0o600), 0)
        let completion = expectation(description: "FIFO rejected")
        DispatchQueue.global().async {
            do { _ = try NativeDeviceIdentity.loadOrCreate(directory: directory); XCTFail("Expected FIFO rejection") }
            catch { }
            completion.fulfill()
        }
        wait(for: [completion], timeout: 1)
        let writer = open(directory.appendingPathComponent("device-id").path, O_WRONLY | O_NONBLOCK)
        if writer >= 0 { close(writer) }
    }
    func testIdentitySymlinkIsNotFollowed() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let target = directory.appendingPathComponent("other")
        let value = NativeDeviceIdentity.generate().value
        try Data(value.utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("device-id"), withDestinationURL: target)
        XCTAssertThrowsError(try NativeDeviceIdentity.loadOrCreate(directory: directory))
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), value)
    }
}
