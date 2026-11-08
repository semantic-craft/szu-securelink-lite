import Foundation
import Security

enum BackendPublicEnvelope {
    static func serverScope(material: BackendPublicMaterial, timestamp: String) throws -> String {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        guard let rsa = SecKeyCreateWithData(material.publicDER as CFData, attributes as CFDictionary, nil) else {
            throw BackendDiscoveryError.invalidMaterial
        }
        let data = try JSONSerialization.data(withJSONObject: ["serverType": "SDP", "timestamp": timestamp], options: [.sortedKeys])
        return try encrypt(data, using: rsa)
    }
    static func validServerScope(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 4096, let decoded = Data(base64Encoded: value), !decoded.isEmpty else { return false }
        return decoded.base64EncodedString() == value
    }
    static func encrypt(_ plaintext: Data, using key: SecKey) throws -> String {
        let blockSize = SecKeyGetBlockSize(key) - 11
        guard blockSize > 0, !plaintext.isEmpty, plaintext.count <= 65536 else {
            throw BackendDiscoveryError.invalidRequest
        }
        var encrypted = Data()
        for offset in stride(from: 0, to: plaintext.count, by: blockSize) {
            let block = plaintext.subdata(in: offset..<min(plaintext.count, offset + blockSize))
            guard let result = SecKeyCreateEncryptedData(key, .rsaEncryptionPKCS1, block as CFData, nil) else {
                throw BackendDiscoveryError.invalidMaterial
            }
            encrypted.append(result as Data)
        }
        return encrypted.base64EncodedString()
    }
}
