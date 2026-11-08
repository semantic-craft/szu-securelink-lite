import XCTest
import Foundation
import Darwin
@testable import SecureLinkTransport

final class SessionLeaseTests: XCTestCase {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        addTeardownBlock { try FileManager.default.removeItem(at: url) }
        return url
    }
    func testConcurrentOwnerRejectedAndReleaseAllowsNextOwner() throws {
        let path = try directory().appendingPathComponent("session.lock").path
        let first = try SessionLease(path: path)
        XCTAssertThrowsError(try SessionLease(path: path)) { XCTAssertEqual($0 as? SessionLeaseError, .busy) }
        first.release(); first.release()
        let second = try SessionLease(path: path)
        second.release()
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)).count, 0)
    }
    func testRejectsSymlinkAndInsecureExistingFileWithoutModifyingIt() throws {
        let root = try directory()
        let target = root.appendingPathComponent("target")
        try Data("untouched".utf8).write(to: target)
        XCTAssertEqual(chmod(target.path, 0o644), 0)
        XCTAssertThrowsError(try SessionLease(path: target.path)) { XCTAssertEqual($0 as? SessionLeaseError, .unsafeFile) }
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertThrowsError(try SessionLease(path: link.path))
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "untouched")
    }
}
