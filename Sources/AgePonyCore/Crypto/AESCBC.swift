import Foundation
import CommonCrypto

public enum AESCBCError: Error {
    case unsupportedKeySize(Int)
    case badIVSize(Int)
    case notBlockAligned(Int)
    case cryptorCreateFailed(CCCryptorStatus)
    case cryptorUpdateFailed(CCCryptorStatus)
    case cryptorFinalFailed(CCCryptorStatus)
}

/// Thin wrapper around CommonCrypto's `CCCryptor` for AES-CBC with **no
/// padding**. This is the mode CTAP2's PIN/UV auth protocol one uses: the
/// platform encrypts the (already block-sized) PIN hash and decrypts the
/// returned PIN token with the shared secret as the key and an all-zero IV.
///
/// CryptoKit exposes only AEAD modes (GCM / ChaChaPoly), so — exactly as with
/// `AESCTR` — we go through the system CommonCrypto implementation.
///
/// Because there is no padding, `input` must be a whole number of 16-byte
/// blocks. CTAP always satisfies this (the PIN hash is 16 bytes, the PIN token
/// is 16 or 32), so a non-aligned input is a programming error and throws.
public enum AESCBC {

    /// Encrypt `input` under AES-CBC with the given `key` and `iv`, no padding.
    public static func encrypt(key: Data, iv: Data, input: Data) throws -> Data {
        try process(operation: CCOperation(kCCEncrypt), key: key, iv: iv, input: input)
    }

    /// Decrypt `input` under AES-CBC with the given `key` and `iv`, no padding.
    public static func decrypt(key: Data, iv: Data, input: Data) throws -> Data {
        try process(operation: CCOperation(kCCDecrypt), key: key, iv: iv, input: input)
    }

    private static func process(
        operation: CCOperation, key: Data, iv: Data, input: Data
    ) throws -> Data {
        guard key.count == 16 || key.count == 32 else {
            throw AESCBCError.unsupportedKeySize(key.count)
        }
        guard iv.count == kCCBlockSizeAES128 else {
            throw AESCBCError.badIVSize(iv.count)
        }
        guard input.count % kCCBlockSizeAES128 == 0 else {
            throw AESCBCError.notBlockAligned(input.count)
        }

        var cryptor: CCCryptorRef?
        let createStatus = key.withUnsafeBytes { keyPtr -> CCCryptorStatus in
            iv.withUnsafeBytes { ivPtr -> CCCryptorStatus in
                CCCryptorCreateWithMode(
                    operation,
                    CCMode(kCCModeCBC),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivPtr.baseAddress, keyPtr.baseAddress, key.count,
                    nil, 0, 0,
                    CCModeOptions(0),
                    &cryptor
                )
            }
        }
        guard createStatus == kCCSuccess, let cryptor = cryptor else {
            throw AESCBCError.cryptorCreateFailed(createStatus)
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
            throw AESCBCError.cryptorUpdateFailed(updateStatus)
        }

        var finalBytes = 0
        let finalStatus: CCCryptorStatus = output.withUnsafeMutableBytes { outPtr in
            let advanced = outPtr.baseAddress!.advanced(by: bytesProduced)
            return CCCryptorFinal(cryptor, advanced, outLen - bytesProduced, &finalBytes)
        }
        guard finalStatus == kCCSuccess else {
            throw AESCBCError.cryptorFinalFailed(finalStatus)
        }

        output.count = bytesProduced + finalBytes
        return output
    }
}
