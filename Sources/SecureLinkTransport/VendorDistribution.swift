import Foundation
import CryptoKit
import SecureLinkCore

public enum VendorDistributionError: Error { case invalidArchive, unexpectedSource, malformedMaterial }

public enum VendorDistribution {
    /// Reads only shipped static code; never reads the user's SecureLink config or keychain.
    public static func settings(app: URL, pid: Int32, logPath: String) throws -> NativeSettings {
        let handle = try FileHandle(forReadingFrom: app.appendingPathComponent("Contents/Resources/app.asar"))
        defer { try? handle.close() }
        func read(_ count: Int) throws -> Data {
            guard let bytes = try handle.read(upToCount: count), bytes.count == count else { throw VendorDistributionError.invalidArchive }
            return bytes
        }
        let header = try read(16)
        func u32(_ offset: Int) -> UInt32 {
            (0..<4).reduce(UInt32(0)) { $0 | UInt32(header[offset + $1]) << (8 * $1) }
        }
        let headerSize = Int(u32(12))
        guard headerSize > 0, headerSize < 16 * 1024 * 1024 else { throw VendorDistributionError.invalidArchive }
        var entry = try JSONSerialization.jsonObject(with: read(headerSize)) as? [String: Any]
        for name in ["bytenode", "dist", "royalGuard.js"] {
            entry = (entry?["files"] as? [String: [String: Any]])?[name]
        }
        guard let entry, entry["unpacked"] == nil, entry["link"] == nil,
              let size = entry["size"] as? Int, size == 11537,
              let offsetString = entry["offset"] as? String, let offset = UInt64(offsetString),
              offset < 256 * 1024 * 1024 else { throw VendorDistributionError.invalidArchive }
        try handle.seek(toOffset: 8 + UInt64(u32(4)) + offset)
        var source = try read(size)
        defer { source.resetBytes(in: 0..<source.count) }
        guard SHA256.hash(data: source).map({ String(format: "%02x", $0) }).joined() == "9892975a054502b2d7c6a4029e20ddc81c547b5a78855ac509d30b7dce06e1a8" else {
            throw VendorDistributionError.unexpectedSource
        }
        return try settingsFromPinnedSource(String(decoding: source, as: UTF8.self), pid: pid, logPath: logPath)
    }

    static func settingsFromPinnedSource(_ source: String, pid: Int32, logPath: String) throws -> NativeSettings {
        guard let start = source.range(of: "getClientConf:()=>({") else { throw VendorDistributionError.malformedMaterial }
        let fragment = String(source[start.upperBound...])
        func field(_ name: String) throws -> String {
            let regex = try NSRegularExpression(pattern: #"(?:^|,)"# + name + #":Buffer\.from\((\[[^\]]+\])\.join\(""\)\|\|"","hex"\)\.toString\(\)"#)
            let matches = regex.matches(in: fragment, range: NSRange(fragment.startIndex..., in: fragment))
            guard matches.count == 1, let range = Range(matches[0].range(at: 1), in: fragment),
                  let parts = try JSONSerialization.jsonObject(with: Data(fragment[range].utf8)) as? [String] else { throw VendorDistributionError.malformedMaterial }
            guard parts.count <= 16384, parts.count % 2 == 0,
                  parts.allSatisfy({ $0.count == 1 && $0.first!.isHexDigit }) else { throw VendorDistributionError.malformedMaterial }
            var bytes = Data()
            for index in stride(from: 0, to: parts.count, by: 2) {
                guard let byte = UInt8(parts[index] + parts[index + 1], radix: 16) else { throw VendorDistributionError.malformedMaterial }
                bytes.append(byte)
            }
            guard let value = String(data: bytes, encoding: .utf8) else { throw VendorDistributionError.malformedMaterial }
            return value
        }
        return try NativeSettings(certificateID: field("sheetaApiCertId"), certificateKey: field("sheetaApiCertKey"), publicKey: field("sheetaApiPublicKey"), pid: pid, logPath: logPath)
    }
}
