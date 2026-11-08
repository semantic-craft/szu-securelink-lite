import Foundation
import CommonCrypto

public enum CipherError: Error, Equatable { case invalidParameters, operationFailed }

public struct SessionCipher {
    private let key: Data
    private let iv: Data
    public init(key: Data, iv: Data) throws {
        guard key.count == kCCKeySizeAES128, iv.count == kCCBlockSizeAES128 else {
            throw CipherError.invalidParameters
        }
        self.key = key; self.iv = iv
    }
    public func encrypt(_ plain: Data) throws -> Data { try transform(plain, operation: CCOperation(kCCEncrypt)) }
    public func decrypt(_ encrypted: Data) throws -> Data {
        guard !encrypted.isEmpty, encrypted.count % kCCBlockSizeAES128 == 0 else {
            throw CipherError.invalidParameters
        }
        let padded = try transform(encrypted, operation: CCOperation(kCCDecrypt))
        guard let last = padded.last else { throw CipherError.operationFailed }
        let count = Int(last)
        guard count > 0, count <= kCCBlockSizeAES128, padded.count >= count,
              padded.suffix(count).allSatisfy({ $0 == last }) else { throw CipherError.operationFailed }
        return padded.dropLast(count)
    }
    private func transform(_ input: Data, operation: CCOperation) throws -> Data {
        guard input.count <= PlainFrame.maximumSize + kCCBlockSizeAES128 else { throw CipherError.invalidParameters }
        var output = Data(count: input.count + kCCBlockSizeAES128)
        let capacity = output.count
        var written = 0
        let status = output.withUnsafeMutableBytes { out in
            input.withUnsafeBytes { source in
                key.withUnsafeBytes { key in
                    iv.withUnsafeBytes { iv in
                        CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), operation == CCOperation(kCCEncrypt) ? CCOptions(kCCOptionPKCS7Padding) : 0,
                                key.baseAddress, key.count, iv.baseAddress, source.baseAddress, source.count,
                                out.baseAddress, capacity, &written)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw CipherError.operationFailed }
        output.count = written
        return output
    }
}
