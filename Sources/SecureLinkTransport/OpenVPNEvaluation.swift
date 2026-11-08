import Foundation
import Darwin

public enum OpenVPNEvaluationError: Error { case invalidInput, unavailable, timedOut, invalidReceipt }

public enum OpenVPNEvaluation {
    public struct Receipt: Codable, Sendable {
        public let accepted: Bool
        public let mode: String
        public let networkOpened: Bool
        public let tunnelStarted: Bool
        public let reason: String
        public var candidateRemoteAdded: Bool? = nil
    }

    public static func evaluate(_ configuration: BackendNetworkConfiguration, executable: URL) async throws -> Receipt {
        let initial = try await run(input: configuration.evaluationInput(), executable: executable)
        guard initial.reason == "missing-remote" else { return initial }
        var candidate = try await run(input: configuration.candidateEvaluationInput(), executable: executable)
        candidate.candidateRemoteAdded = true
        return candidate
    }

    static func run(input: Data, executable: URL, timeout: TimeInterval = 10) async throws -> Receipt {
        guard !input.isEmpty, input.count <= 2 * 1024 * 1024 else { throw OpenVPNEvaluationError.invalidInput }
        let child = PrivateEngineProcess()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let result = try await Task.detached {
                try child.run(input: input, executable: executable, timeout: timeout)
            }.value
            try Task.checkCancellation()
            guard let receipt = try? JSONDecoder().decode(Receipt.self, from: result.output),
                  receipt.mode == "offline-config-evaluation", !receipt.networkOpened, !receipt.tunnelStarted,
                  (receipt.accepted && receipt.reason == "accepted" && result.exitStatus == 0)
                    || (!receipt.accepted && ["rejected", "missing-remote"].contains(receipt.reason) && result.exitStatus == 2) else {
                throw OpenVPNEvaluationError.invalidReceipt
            }
            return receipt
        } onCancel: { child.stop() }
    }
}
