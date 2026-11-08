import Foundation
import CryptoKit
import Darwin

public enum NativeDeviceIdentityError: Error { case invalidIdentity, storage }

struct NativeDeviceIdentity: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let value: String
    var description: String { "NativeDeviceIdentity(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: ["values": "redacted"], displayStyle: .struct) }

    static func generate() -> Self {
        let uuid = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let start = uuid.index(uuid.startIndex, offsetBy: Int.random(in: 0..<16))
        let segment = String(uuid[start..<uuid.index(start, offsetBy: 16)])
        let hash = Insecure.MD5.hash(data: Data(segment.utf8)).map { String(format: "%02x", $0) }.joined()
        let checksum = String(hash.dropFirst(12).prefix(8))
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        let suffix = String((0..<6).map { _ in alphabet.randomElement()! })
        return Self(value: "03" + segment + checksum + suffix)
    }

    static func validate(_ value: String) throws -> Self {
        let bytes = Array(value.utf8)
        guard bytes.count == 32, value.hasPrefix("03"),
              bytes[2..<26].allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              bytes[26...].allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) }) else {
            throw NativeDeviceIdentityError.invalidIdentity
        }
        let segment = Data(bytes[2..<18])
        let hash = Insecure.MD5.hash(data: segment).map { String(format: "%02x", $0) }.joined()
        guard String(decoding: bytes[18..<26], as: UTF8.self) == String(hash.dropFirst(12).prefix(8)) else {
            throw NativeDeviceIdentityError.invalidIdentity
        }
        return Self(value: value)
    }

    static func loadOrCreate(directory: URL) throws -> Self {
        let file = directory.appendingPathComponent("device-id")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        func readExisting() throws -> Self {
            let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
            guard fd >= 0 else { throw NativeDeviceIdentityError.storage }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
                close(fd); throw NativeDeviceIdentityError.storage
            }
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            defer { try? handle.close() }
            guard let data = try handle.read(upToCount: 33), data.count == 32,
                  let value = String(data: data, encoding: .utf8) else { throw NativeDeviceIdentityError.invalidIdentity }
            return try validate(value)
        }
        if FileManager.default.fileExists(atPath: file.path) { return try readExisting() }
        let identity = generate()
        let temporary = directory.appendingPathComponent(".device-id-" + UUID().uuidString)
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw NativeDeviceIdentityError.storage }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: temporary) }
        try handle.write(contentsOf: Data(identity.value.utf8))
        try handle.synchronize()
        if link(temporary.path, file.path) == 0 { return identity }
        guard errno == EEXIST else { throw NativeDeviceIdentityError.storage }
        return try readExisting()
    }
}
