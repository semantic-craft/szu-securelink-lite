import Foundation
import Darwin

final class PrivateEngineProcess: @unchecked Sendable {
    private let lock = NSLock()
    private let process = Process()
    private var stopped = false
    private var timedOut = false

    func requestGracefulFinish() {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, process.isRunning else { return }
        kill(process.processIdentifier, SIGTERM)
    }

    func stop(timeout: Bool = false, graceful: Bool = false) {
        lock.lock(); defer { lock.unlock() }
        stopped = true
        timedOut = timedOut || timeout
        guard process.isRunning else { return }
        let pid = process.processIdentifier
        if graceful && !timeout {
            kill(pid, SIGTERM)
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) { [weak self] in
                guard let self else { return }
                self.lock.lock(); defer { self.lock.unlock() }
                if self.process.isRunning { kill(pid, SIGKILL) }
            }
        } else {
            kill(pid, SIGKILL)
        }
    }

    struct Result: Sendable {
        let output: Data
        let exitStatus: Int32
    }
    func run(input: Data, executable: URL, arguments: [String] = [], timeout: TimeInterval,
             onStderrLine: (@Sendable (String) -> Void)? = nil) throws -> Result {
        let incoming = Pipe(), outgoing = Pipe()
        let errorPipe: Pipe? = onStderrLine != nil ? Pipe() : nil
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = incoming
        process.standardOutput = outgoing
        process.standardError = errorPipe ?? FileHandle.nullDevice
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "C"]
        guard fcntl(incoming.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw OpenVPNEvaluationError.unavailable
        }
        lock.lock()
        guard !stopped else { lock.unlock(); throw CancellationError() }
        do { try process.run() }
        catch { lock.unlock(); throw OpenVPNEvaluationError.unavailable }
        lock.unlock()
        if let errorPipe, let onStderrLine {
            let errHandle = errorPipe.fileHandleForReading
            DispatchQueue.global().async {
                var buffer = Data()
                while true {
                    let chunk = errHandle.availableData
                    if chunk.isEmpty { break }
                    buffer.append(chunk)
                    while let newline = buffer.firstIndex(of: 0x0A) {
                        let lineData = buffer.subdata(in: 0..<newline)
                        buffer.removeSubrange(0...newline)
                        if let line = String(data: lineData, encoding: .utf8)?
                            .trimmingCharacters(in: .whitespacesAndNewlines), !line.isEmpty {
                            onStderrLine(line)
                        }
                    }
                    if buffer.count > 16384 { buffer.removeAll() }
                }
            }
        }
        let deadline = DispatchWorkItem { [self] in stop(timeout: true) }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)
        defer {
            deadline.cancel()
            try? incoming.fileHandleForWriting.close()
            try? outgoing.fileHandleForReading.close()
            try? errorPipe?.fileHandleForReading.close()
            stop()
            process.waitUntilExit()
        }
        do {
            try incoming.fileHandleForWriting.write(contentsOf: input)
            try incoming.fileHandleForWriting.close()
            var output = Data()
            while let bytes = try outgoing.fileHandleForReading.read(upToCount: 65537), !bytes.isEmpty {
                guard output.count + bytes.count <= 65536 else { throw OpenVPNEvaluationError.invalidReceipt }
                output.append(bytes)
            }
            process.waitUntilExit()
            lock.lock(); let expired = timedOut; let cancelled = stopped; lock.unlock()
            if expired { throw OpenVPNEvaluationError.timedOut }
            if cancelled { throw CancellationError() }
            return Result(output: output, exitStatus: process.terminationStatus)
        } catch let error as OpenVPNEvaluationError { throw error }
        catch is CancellationError { throw CancellationError() }
        catch {
            lock.lock(); let expired = timedOut; let cancelled = stopped; lock.unlock()
            if expired { throw OpenVPNEvaluationError.timedOut }
            if cancelled { throw CancellationError() }
            throw OpenVPNEvaluationError.unavailable
        }
    }
}
