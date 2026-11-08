import Foundation

/// Check raw JSON before Codable can erase duplicate keys, including unknown
/// fields. Limits apply to the entire receipt; diagnostics never include input.
enum ReceiptJSONKeys {
    static func validate(_ data: Data) throws {
        guard !data.isEmpty, data.count <= 65_536 else { throw OpenVPNEvaluationError.invalidReceipt }
        var scanner = Scanner(bytes: Array(data))
        do {
            try scanner.value(depth: 0)
            scanner.whitespace()
            guard scanner.offset == scanner.bytes.count else { throw OpenVPNEvaluationError.invalidReceipt }
        } catch { throw OpenVPNEvaluationError.invalidReceipt }
    }

    private struct Scanner {
        let bytes: [UInt8]
        var offset = 0
        var values = 0
        mutating func whitespace() {
            while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 }
        }
        mutating func consume(_ byte: UInt8) -> Bool {
            whitespace()
            guard offset < bytes.count && bytes[offset] == byte else { return false }
            offset += 1
            return true
        }
        mutating func string() throws -> String {
            whitespace()
            let start = offset
            guard consume(34) else { throw OpenVPNEvaluationError.invalidReceipt }
            while offset < bytes.count {
                let byte = bytes[offset]
                offset += 1
                if byte == 34 {
                    // Decode escapes before comparing names ("a" == "\u0061").
                    return try JSONDecoder().decode(String.self, from: Data(bytes[start..<offset]))
                }
                if byte == 92 {
                    guard offset < bytes.count else { throw OpenVPNEvaluationError.invalidReceipt }
                    offset += 1
                }
            }
            throw OpenVPNEvaluationError.invalidReceipt
        }
        mutating func value(depth: Int) throws {
            guard depth <= 64, values < 8192 else { throw OpenVPNEvaluationError.invalidReceipt }
            values += 1
            whitespace()
            guard offset < bytes.count else { throw OpenVPNEvaluationError.invalidReceipt }
            switch bytes[offset] {
            case 123: // object
                offset += 1
                var names = Set<String>()
                if consume(125) { return }
                repeat {
                    let name = try string()
                    guard names.insert(name).inserted, consume(58) else { throw OpenVPNEvaluationError.invalidReceipt }
                    try value(depth: depth + 1)
                    if consume(125) { return }
                } while consume(44)
                throw OpenVPNEvaluationError.invalidReceipt
            case 91: // array
                offset += 1
                if consume(93) { return }
                repeat {
                    try value(depth: depth + 1)
                    if consume(93) { return }
                } while consume(44)
                throw OpenVPNEvaluationError.invalidReceipt
            case 34:
                _ = try string()
            default:
                let start = offset
                while offset < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[offset]) { offset += 1 }
                let token = String(decoding: bytes[start..<offset], as: UTF8.self)
                guard token == "true" || token == "false" || token == "null"
                    || token.range(of: #"\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\z"#, options: .regularExpression) != nil else {
                    throw OpenVPNEvaluationError.invalidReceipt
                }
            }
        }
    }
}
