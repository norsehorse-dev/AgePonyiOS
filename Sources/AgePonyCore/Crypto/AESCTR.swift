import Foundation
import CommonCrypto

public enum AESCTRError: Error {
    case unsupportedKeySize(Int)
    case cryptorCreateFailed(CCCryptorStatus)
    case cryptorUpdateFailed(CCCryptorStatus)
    case cryptorFinalFailed(CCCryptorStatus)
}

/// Thin wrapper around CommonCrypto's `CCCryptor` for AES-CTR mode with a
/// big-endian 128-bit counter (the mode OpenSSH uses for `aes256-ctr` and
/// `aes128-ctr` PEM encryption).
///
/// CryptoKit doesn't expose CTR (only GCM), so we go through CommonCrypto.
/// The system implementation is well-tested and we already trust it via SecKey.
public enum AESCTR {

    /// CTR is symmetric — encryption and decryption are the same operation.
    /// `iv` is the initial counter value (16 bytes, BE).
    public static func process(key: Data, iv: Data, input: Data) throws -> Data {
        guard key.count == 16 || key.count == 32 else {
            throw AESCTRError.unsupportedKeySize(key.count)
        }
        precondition(iv.count == 16, "AES-CTR IV must be 16 bytes")

        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { keyPtr -> CCCryptorStatus in
            iv.withUnsafeBytes { ivPtr -> CCCryptorStatus in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),                // CTR is symmetric; encrypt == decrypt
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivPtr.baseAddress, keyPtr.baseAddress, key.count,
                    nil, 0, 0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        guard status == kCCSuccess, let cryptor = cryptor else {
            throw AESCTRError.cryptorCreateFailed(status)
        }
        defer { CCCryptorRelease(cryptor) }

        let outLen = CCCryptorGetOutputLength(cryptor, input.count, true)
        var output = Data(count: outLen)
        var bytesProduced = 0

        let updateStatus: CCCryptorStatus = input.withUnsafeBytes { inPtr in
            output.withUnsafeMutableBytes { outPtr in
                CCCryptorUpdate(
                    cryptor,
                    inPtr.baseAddress, input.count,
                    outPtr.baseAddress, outLen,
                    &bytesProduced
                )
            }
        }
        guard updateStatus == kCCSuccess else {
            throw AESCTRError.cryptorUpdateFailed(updateStatus)
        }

        var finalBytes = 0
        let finalStatus: CCCryptorStatus = output.withUnsafeMutableBytes { outPtr in
            let advanced = outPtr.baseAddress!.advanced(by: bytesProduced)
            return CCCryptorFinal(cryptor, advanced, outLen - bytesProduced, &finalBytes)
        }
        guard finalStatus == kCCSuccess else {
            throw AESCTRError.cryptorFinalFailed(finalStatus)
        }

        output.count = bytesProduced + finalBytes
        return output
    }
}
