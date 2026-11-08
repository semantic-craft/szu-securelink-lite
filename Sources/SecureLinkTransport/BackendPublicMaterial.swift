import Foundation
import CryptoKit
import Security

/// Versioned public protocol material, recovered offline from the pinned
/// distribution. No vendor artifact or user configuration is read at runtime.
/// Source VA: RSA blob 0x100e2d790; IV blob 0x100e2d750; certID
/// 0x100e2cb90; locale 0x100e2cbb0. The final empty envelope was computed
/// offline; neither its symmetric key nor the blob-unwrapping key is included.
/// Fingerprint is SHA256 of the five ordered fields, each prefixed by BE32 length.
/// Password support is deliberately limited to the fixed empty CAS envelope.
public struct BackendPublicMaterial: Sendable {
    public let publicDER: Data
    public let iv: Data
    public let certID: String
    public let locale: String
    public let emptyPasswordEnvelope: String

    static let protocolVersion = "securelink-cas-fb0019debdaa-v1"
    static let sourceSHA256 = "fb0019debdaa4f677fe8a77b39c8caf014d18a946de6c0ceb47a04dd4bc80efe"
    static let materialSHA256 = "87b4a09961d8488e04f4bcdcb899d3eef55a7dc1d99d2d683b39f3da7049a8f4"

    static func production() throws -> Self {
        guard let publicDER = Data(base64Encoded: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSBCDJeCGCGqfhvcnTjbFmxj1Mc7fBWlI5ndx0MkehUwRbOsDoqQT4QF8Aj5ZoxYzS4RuwFdAtARWcVV8R6euF+Ot8xRwVvitunhr3wV24RshiyubfR+I08drjvaXpa46ObdqlI00ipXTDMpFEE/8GHDwznz0H0HybHeL7DlsUIQIDAQAB"),
              let iv = Data(base64Encoded: "c2VjdXJlbGluazY2NjY2Ng==") else {
            throw BackendDiscoveryError.invalidMaterial
        }
        let material = Self(publicDER: publicDER, iv: iv,
                            certID: "secureLink", locale: "en_GB",
                            emptyPasswordEnvelope: "CzXLIV3mmxl8VNYQrseDcg==")
        try material.validate()
        guard material.fingerprint == materialSHA256 else { throw BackendDiscoveryError.invalidMaterial }
        return material
    }

    public var fingerprint: String {
        var bytes = Data()
        for field in [publicDER, iv, Data(certID.utf8), Data(locale.utf8), Data(emptyPasswordEnvelope.utf8)] {
            var count = UInt32(field.count).bigEndian
            withUnsafeBytes(of: &count) { bytes.append(contentsOf: $0) }
            bytes.append(field)
        }
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    func validate() throws {
        guard publicDER.count > 0, publicDER.count < 8192, iv.count == 16,
              !certID.isEmpty, certID.utf8.count < 256,
              !locale.isEmpty, locale.utf8.count < 32,
              [certID, locale].allSatisfy({ $0.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e } }),
              let empty = Data(base64Encoded: emptyPasswordEnvelope), empty.count == 16,
              empty.base64EncodedString() == emptyPasswordEnvelope,
              let key = SecKeyCreateWithData(publicDER as CFData,
                  [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, nil),
              SecKeyIsAlgorithmSupported(key, .encrypt, .rsaEncryptionPKCS1) else {
            throw BackendDiscoveryError.invalidMaterial
        }
    }
}
