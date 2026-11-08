import Foundation
import XCTest
@testable import SecureLinkTransport

final class OpenVPNEvaluationTests: XCTestCase {
    private func helper(_ body: String, readInput: Bool = true) throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("evaluator")
        try Data(("#!/usr/bin/python3\nimport sys, json, time\n" + (readInput ? "sys.stdin.buffer.read()\n" : "") + body).utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }
    func testAcceptedAndRejectedAreBoundedOfflineReceipts() async throws {
        for accepted in [true, false] {
            let json = "{\"accepted\":\(accepted),\"mode\":\"offline-config-evaluation\",\"networkOpened\":false,\"tunnelStarted\":false,\"reason\":\"\(accepted ? "accepted" : "rejected")\"}"
            let executable = try helper("print('\(json)')\nsys.exit(\(accepted ? 0 : 2))\n")
            let receipt = try await OpenVPNEvaluation.run(input: Data("SYNTHETIC-CONFIG".utf8), executable: executable)
            XCTAssertEqual(receipt.accepted, accepted)
            XCTAssertFalse(receipt.networkOpened)
        }
    }
    func testUnknownOutputCannotBecomeDiagnosticText() async throws {
        let executable = try helper("print('SECRET-SENTINEL')\n")
        do {
            _ = try await OpenVPNEvaluation.run(input: Data("fixture".utf8), executable: executable)
            XCTFail("Invalid output must fail")
        } catch OpenVPNEvaluationError.invalidReceipt { }
    }
    func testTimeoutReapsTheOwnedProcess() async throws {
        let executable = try helper("time.sleep(30)\n")
        let start = Date()
        do {
            _ = try await OpenVPNEvaluation.run(input: Data("fixture".utf8), executable: executable, timeout: 0.2)
            XCTFail("Expected timeout")
        } catch OpenVPNEvaluationError.timedOut { }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)
    }
    func testCancellationReapsTheOwnedProcess() async throws {
        let executable = try helper("time.sleep(30)\n")
        let task = Task { try await OpenVPNEvaluation.run(input: Data("fixture".utf8), executable: executable) }
        try await Task.sleep(for: .milliseconds(100))
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch is CancellationError { }
    }
    func testOversizedOutputIsRejectedAndReaped() async throws {
        let executable = try helper("sys.stdout.write('X' * 200000)\ntime.sleep(30)\n")
        let start = Date()
        do {
            _ = try await OpenVPNEvaluation.run(input: Data("fixture".utf8), executable: executable, timeout: 1)
            XCTFail("Output must be bounded")
        } catch OpenVPNEvaluationError.invalidReceipt { }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)
    }
    func testEarlyExitDoesNotDeliverSIGPIPEToApplication() async throws {
        let executable = try helper("sys.exit(3)\n", readInput: false)
        do {
            _ = try await OpenVPNEvaluation.run(input: Data(repeating: 65, count: 2 * 1024 * 1024), executable: executable, timeout: 1)
            XCTFail("Early exit must fail")
        } catch OpenVPNEvaluationError.unavailable { }
    }

    func testCandidateUsesOnlyReturnedIPAndPortsWithoutInventingProtocol() throws {
        func configuration(ip: String, ports: [Int]) throws -> BackendNetworkConfiguration {
            try BackendNetworkConfiguration.parse(JSONSerialization.data(withJSONObject: ["returnCode": 1, "content": ["networkConfig": [
                "clientConf": "client%0Adev+tun%0Aproto+tcp-client", "priorServers": [["ip": ip, "ports": ports]]
            ]]]))
        }
        let valid = try configuration(ip: "192.0.2.4", ports: [443, 8443])
        let text = String(decoding: try valid.candidateEvaluationInput(), as: UTF8.self)
        XCTAssertEqual(text, "client\ndev tun\nproto tcp-client\nremote 192.0.2.4 443\nremote 192.0.2.4 8443\n")
        for ip in ["192.0.2.1\nremote evil", "192.0.2.1\0SECRET", "example.invalid"] {
            XCTAssertThrowsError(try configuration(ip: ip, ports: [443]).candidateEvaluationInput())
        }
        for ports in [[], [0], [65536]] {
            XCTAssertThrowsError(try configuration(ip: "192.0.2.1", ports: ports).candidateEvaluationInput())
        }
    }

}
