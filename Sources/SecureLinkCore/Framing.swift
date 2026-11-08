import Foundation

public enum FrameError: Error, Equatable { case invalidLength, invalidPayload, truncated, failedStream }
public struct Message: Equatable, Sendable {
    public let command: UInt32
    public let payload: Data
    public init(command: UInt32, payload: Data) { self.command = command; self.payload = payload }
}

public enum PlainFrame {
    public static let maximumSize = 2_097_152
    public static func encode(_ message: Message) throws -> Data {
        guard message.payload.count <= maximumSize - 8 else { throw FrameError.invalidLength }
        guard String(data: message.payload, encoding: .utf8) != nil,
              (try? JSONSerialization.jsonObject(with: message.payload, options: [.fragmentsAllowed])) != nil
        else { throw FrameError.invalidPayload }
        var bytes = Data()
        for value in [message.command, UInt32(message.payload.count)] {
            bytes.append(contentsOf: [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) })
        }
        bytes.append(message.payload)
        return bytes
    }
    public static func decode(_ data: Data) throws -> Message {
        let bytes = Array(data)
        guard bytes.count >= 8 else { throw FrameError.truncated }
        let command = readBE(bytes[0..<4])
        let length = Int(readBE(bytes[4..<8]))
        guard length <= maximumSize - 8 else { throw FrameError.invalidLength }
        guard bytes.count == 8 + length else { throw FrameError.invalidLength }
        let message = Message(command: command, payload: Data(bytes.dropFirst(8)))
        _ = try encode(message)
        return message
    }
    private static func readBE(_ bytes: ArraySlice<UInt8>) -> UInt32 {
        bytes.reduce(0) { ($0 << 8) | UInt32($1) }
    }
}

// The production envelope contains opaque ciphertext. No plaintext fallback exists.
public struct EncryptedStreamDecoder {
    public static let maximumCiphertextSize = 2_097_184
    private var pending = Data()
    private var expectedLength: Int?
    private var failed = false
    public init() {}
    public mutating func append(_ data: Data) throws -> [Data] {
        guard !failed else { throw FrameError.failedStream }
        var result: [Data] = []
        var index = data.startIndex
        while index < data.endIndex {
            let target = expectedLength ?? 4
            let count = min(target - pending.count, data.distance(from: index, to: data.endIndex))
            let end = data.index(index, offsetBy: count)
            pending.append(contentsOf: data[index..<end])
            index = end
            guard pending.count == target else { continue }
            if expectedLength == nil {
                let bytes = Array(pending)
                let length = bytes.enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << ($1.offset * 8) }
                guard length > 0, length <= Self.maximumCiphertextSize else {
                    failed = true; pending.removeAll(); throw FrameError.invalidLength
                }
                expectedLength = Int(length)
                pending.removeAll(keepingCapacity: true)
            } else {
                result.append(pending)
                pending = Data()
                expectedLength = nil
            }
        }
        return result
    }
    public func finish() throws {
        guard !failed else { throw FrameError.failedStream }
        guard pending.isEmpty && expectedLength == nil else { throw FrameError.truncated }
    }
}
