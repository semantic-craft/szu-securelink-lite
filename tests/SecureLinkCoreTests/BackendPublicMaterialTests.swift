import Foundation
import CryptoKit
import Security
import XCTest
import SecureLinkCore
@testable import SecureLinkTransport

final class BackendPublicMaterialTests: XCTestCase {
    private func sha(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    func testProductionProviderIsSelfContainedAndPinned() throws {
        // The production API takes no path and has no disk fallback.
        let material = try BackendPublicMaterial.production()
        XCTAssertEqual(material.fingerprint, BackendPublicMaterial.materialSHA256)
        XCTAssertEqual(BackendPublicMaterial.protocolVersion, "securelink-cas-fb0019debdaa-v1")
        try material.validate()
        XCTAssertEqual(material.iv.count, 16)
        XCTAssertEqual(Data(base64Encoded: material.emptyPasswordEnvelope)?.count, 16)
        XCTAssertFalse(BackendDiscovery.Receipt(fieldTypes: [:]).vendorArtifactRequired)
        XCTAssertFalse(BackendDiscovery.CASReceipt().vendorArtifactRequired)
    }
    func testPinnedMaterialMatchesOfflineRecoveredSyntheticEncryption() throws {
        let material = try BackendPublicMaterial.production()
        let key = Data(repeating: 3, count: 16)
        let body = try BackendDiscovery.body(payload: ["fixture": 1], key: key, iv: material.iv)
        // Golden hashes were computed using the old pinned binary recovery and
        // independent CommonCrypto call, exclusively on synthetic plaintext.
        XCTAssertEqual(sha(Data(body.utf8)), "07acd401eec61ef0e1dbf939dff155b5979ff05ed22b3fe0c10d9b0828cfa461")
        let sign = BackendDiscovery.signature(certID: material.certID, timestamp: "1700000000000", nonce: "fixture-nonce", body: body)
        XCTAssertEqual(sha(Data(sign.utf8)), "5acc6eeb2bb672c9a950dd4acff6c6e590a5d45bd19b24a2a33035e6b630729e")
        let plain = try SessionCipher(key: key, iv: material.iv).decrypt(XCTUnwrap(Data(base64Encoded: body)))
        XCTAssertEqual(plain, Data(#"{"fixture":1}"#.utf8))
        for operation in [BackendDiscovery.Operation.preconfig, .authConfig, .authURL] {
            let request = try BackendDiscovery.preparedRequest(material: material, operation: operation,
                payload: ["fixture": 1], key: key, timestamp: "1700000000000", nonce: "fixture-nonce", credential: nil)
            XCTAssertEqual(request.httpBody, Data(body.utf8))
            XCTAssertEqual(request.value(forHTTPHeaderField: "certId"), material.certID)
            XCTAssertEqual(URLComponents(url: try XCTUnwrap(request.url), resolvingAgainstBaseURL: false)?.queryItems?.first?.value, material.locale)
            let encryptedKey = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(request.value(forHTTPHeaderField: "secret"))))
            XCTAssertGreaterThanOrEqual(encryptedKey.count, 128)
        }
    }
    func testMalformedMaterialIsRejectedWithoutArtifactFallback() throws {
        let m = try BackendPublicMaterial.production()
        for bad in [
            BackendPublicMaterial(publicDER: Data([1,2,3]), iv: m.iv, certID: m.certID, locale: m.locale, emptyPasswordEnvelope: m.emptyPasswordEnvelope),
            BackendPublicMaterial(publicDER: m.publicDER, iv: Data(), certID: m.certID, locale: m.locale, emptyPasswordEnvelope: m.emptyPasswordEnvelope),
            BackendPublicMaterial(publicDER: m.publicDER, iv: m.iv, certID: "bad\nheader", locale: m.locale, emptyPasswordEnvelope: m.emptyPasswordEnvelope),
            BackendPublicMaterial(publicDER: m.publicDER, iv: m.iv, certID: m.certID, locale: m.locale, emptyPasswordEnvelope: "invalid")
        ] { XCTAssertThrowsError(try bad.validate()) }
    }
}
