import Foundation
import XCTest
@testable import SecureLinkTransport

private final class ControlledBackendProtocol: URLProtocol, @unchecked Sendable {
    final class State: @unchecked Sendable {
        let started = XCTestExpectation(description: "response started")
        let stopped = XCTestExpectation(description: "request stopped")
        let lock = NSLock()
        var delivered = 0
        func add(_ bytes: Int) -> Bool { lock.lock(); defer { lock.unlock() }; let first = delivered == 0; delivered += bytes; return first }
        func count() -> Int { lock.lock(); defer { lock.unlock() }; return delivered }
    }
    private let timerLock = NSLock()
    private var timer: DispatchSourceTimer?
    private var stopped = false
    private func stopTimer() {
        timerLock.lock()
        stopped = true
        let timer = self.timer
        self.timer = nil
        timerLock.unlock()
        timer?.cancel()
    }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let state = URLProtocol.property(forKey: "fixtureState", in: request) as? State else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL)); return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        let oversized = request.value(forHTTPHeaderField: "Fixture") == "oversized"
        let chunk = Data(repeating: 65, count: oversized ? 256 * 1024 : 16)
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "backend-controlled-stream"))
        timer.schedule(deadline: .now(), repeating: .milliseconds(10))
        let deadline = DispatchTime.now() + .seconds(3)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            guard DispatchTime.now() < deadline else {
                self.stopTimer()
                self.client?.urlProtocol(self, didFailWithError: URLError(.timedOut))
                return
            }
            let first = state.add(chunk.count)
            self.client?.urlProtocol(self, didLoad: chunk)
            if first { state.started.fulfill() }
        }
        timerLock.lock()
        self.timer = timer
        let alreadyStopped = stopped
        timer.resume()
        timerLock.unlock()
        if alreadyStopped { stopTimer() }
    }
    override func stopLoading() {
        stopTimer()
        (URLProtocol.property(forKey: "fixtureState", in: request) as? State)?.stopped.fulfill()
    }
}

final class BackendNetworkLifecycleTests: XCTestCase {
    private func fixture(_ mode: String) -> (URLRequest, URLSessionConfiguration, ControlledBackendProtocol.State) {
        let state = ControlledBackendProtocol.State()
        let mutable = NSMutableURLRequest(url: URL(string: "https://sheetaapi.wangsu.com/slAppApi/is/slapp/preConfig")!)
        mutable.setValue(mode, forHTTPHeaderField: "Fixture")
        mutable.setValue("SECRET-SENTINEL", forHTTPHeaderField: "secret")
        URLProtocol.setProperty(state, forKey: "fixtureState", in: mutable)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ControlledBackendProtocol.self]
        config.timeoutIntervalForRequest = 3; config.timeoutIntervalForResource = 3
        return (mutable as URLRequest, config, state)
    }
    func testChunkedResponseExceedsLimitAndStopsProducer() async throws {
        let (request, config, state) = fixture("oversized")
        let task = Task { try await BackendDiscovery.receive(request, configuration: config) }
        defer { task.cancel() }
        do { _ = try await task.value; XCTFail("Expected stream limit") }
        catch let error as BackendDiscoveryError {
            guard case .tooLarge = error else { return XCTFail("Expected stream limit") }
            XCTAssertFalse(String(describing: error).contains("SECRET-SENTINEL"))
        }
        catch { XCTFail("Expected fixed tooLarge error, without response or request content") }
        await fulfillment(of: [state.started, state.stopped], timeout: 4)
        XCTAssertGreaterThan(state.count(), BackendDiscovery.maximumResponse)
    }
    func testRunningCancellationStopsProducerAndPreservesCancellation() async throws {
        let (request, config, state) = fixture("slow")
        let task = Task { try await BackendDiscovery.receive(request, configuration: config) }
        defer { task.cancel() }
        await fulfillment(of: [state.started], timeout: 2)
        XCTAssertGreaterThan(state.count(), 0)
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch is CancellationError { }
        catch { XCTFail("Cancellation must remain CancellationError") }
        await fulfillment(of: [state.stopped], timeout: 4)
    }
}
