//
//  ScryptStanza.swift
//  AgePonyCore
//
//  scrypt recipient stanza per age v1 (passphrase-based encryption).
//
//  Encrypt with passphrase:
//    1. salt = 16 random bytes
//    2. wrap_key = scrypt(
//         password = utf8(passphrase),
//         salt = "age-encryption.org/v1/scrypt" || salt,
//         N = 2^workFactor, r = 8, p = 1, dkLen = 32)
//    3. wrapped = ChaCha20-Poly1305.seal(file_key, key=wrap_key,
//                                       nonce=12 zero bytes, aad=empty)
//    4. Stanza:
//         -> scrypt base64(salt) workFactor
//         base64(wrapped)
//
//  Per the age v1 spec, scrypt stanzas are mutually exclusive with other
//  recipient types: a file encrypted with scrypt MUST have exactly one
//  recipient stanza. Enforced at the `Age` top-level API.
//

import Foundation
import CryptoKit

public enum ScryptStanzaError: Error, Equatable {
    case invalidStanzaType
    case invalidArgs
    case invalidSaltLength
    case invalidWorkFactor
    case invalidWrappedKey
    case decryptFailed
}

public struct ScryptRecipient: AgeRecipient {
    public let passphrase: String
    public let workFactor: Int  // log2(N); AgePony default is 18

    public init(passphrase: String, workFactor: Int = 18) {
        self.passphrase = passphrase
        self.workFactor = workFactor
    }

    public func wrap(fileKey: Data) throws -> Stanza {
        // 16 random bytes for the stanza salt.
        var saltBytes = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 {
            saltBytes[i] = UInt8.random(in: 0...UInt8.max)
        }

        let wrapKeyBytes = try Scrypt.ageWrapKey(
            passphrase: passphrase,
            stanzaSalt: saltBytes,
            workFactor: workFactor
        )
        let wrapKey = SymmetricKey(data: Data(wrapKeyBytes))
        let zeroNonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
        let sealed = try ChaChaPoly.seal(fileKey, using: wrapKey, nonce: zeroNonce, authenticating: Data())
        let wrapped = sealed.ciphertext + sealed.tag

        let saltArg = Stanza.base64NoPad(Data(saltBytes))
        let wfArg = String(workFactor)
        return Stanza(type: "scrypt", args: [saltArg, wfArg], body: Data(wrapped))
    }
}

public struct ScryptIdentity: AgeIdentity {
    public let passphrase: String
    /// Refuse to attempt decryption of stanzas with work factor above this
    /// threshold. Without a cap, a malicious file could force the user's
    /// device to compute scrypt with arbitrarily large N. age reference impls
    /// commonly cap this around 20.
    public let maxWorkFactor: Int

    public init(passphrase: String, maxWorkFactor: Int = 22) {
        self.passphrase = passphrase
        self.maxWorkFactor = maxWorkFactor
    }

    public func unwrap(stanza: Stanza) throws -> Data? {
        guard stanza.type == "scrypt" else { return nil }
        guard stanza.args.count == 2 else { return nil }

        let saltData: Data
        do {
            saltData = try Stanza.base64Decode(stanza.args[0])
        } catch {
            return nil
        }
        guard saltData.count == 16 else { return nil }

        guard let workFactor = Int(stanza.args[1]),
              workFactor > 0,
              workFactor <= maxWorkFactor else {
            throw ScryptStanzaError.invalidWorkFactor
        }

        let wrapKeyBytes = try Scrypt.ageWrapKey(
            passphrase: passphrase,
            stanzaSalt: Array(saltData),
            workFactor: workFactor
        )
        let wrapKey = SymmetricKey(data: Data(wrapKeyBytes))

        guard stanza.body.count == 32 else { return nil }
        let ciphertext = stanza.body.prefix(16)
        let tag = stanza.body.suffix(16)
        let zeroNonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))

        let sealed: ChaChaPoly.SealedBox
        do {
            sealed = try ChaChaPoly.SealedBox(nonce: zeroNonce, ciphertext: ciphertext, tag: tag)
        } catch {
            return nil
        }

        do {
            let plaintext = try ChaChaPoly.open(sealed, using: wrapKey, authenticating: Data())
            return plaintext
        } catch {
            // Wrong passphrase looks the same as "not for me" from a tag perspective.
            // The top-level Age API decides whether to surface this as a user error.
            return nil
        }
    }
}
