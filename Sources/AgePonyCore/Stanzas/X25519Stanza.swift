//
//  X25519Stanza.swift
//  AgePonyCore
//
//  X25519 recipient stanza per age v1.
//
//  Encrypt to recipient (X25519 public key, 32 bytes):
//    1. Generate ephemeral X25519 keypair.
//    2. shared_secret = X25519(ephemeral_priv, recipient_pub)
//    3. wrap_key = HKDF-SHA-256(
//         ikm = shared_secret,
//         salt = ephemeral_pub || recipient_pub,
//         info = "age-encryption.org/v1/X25519",
//         L = 32)
//    4. wrapped = ChaCha20-Poly1305.seal(file_key, key=wrap_key,
//                                       nonce=12 zero bytes, aad=empty)
//    5. Stanza:
//         -> X25519 base64(ephemeral_pub)
//         base64(wrapped)        // 32 bytes = 16 ciphertext + 16 tag
//

import Foundation
import CryptoKit

public enum X25519Error: Error, Equatable {
    case invalidPublicKeyLength
    case invalidPrivateKeyLength
    case invalidStanzaType
    case missingEphemeral
    case invalidEphemeral
    case invalidWrappedKey
    case decryptFailed
}

public struct X25519Recipient: AgeRecipient {
    public let publicKey: Data  // 32 bytes, raw

    public init(publicKey: Data) throws {
        guard publicKey.count == 32 else { throw X25519Error.invalidPublicKeyLength }
        self.publicKey = publicKey
    }

    /// Parse an `age1...` recipient string.
    public init(ageRecipient: String) throws {
        let bytes = try Bech32.decodeAgeRecipient(ageRecipient)
        try self.init(publicKey: Data(bytes))
    }

    public func wrap(fileKey: Data) throws -> Stanza {
        let ephemeralPriv = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPub = ephemeralPriv.publicKey
        let theirPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        let shared = try ephemeralPriv.sharedSecretFromKeyAgreement(with: theirPub)

        let salt = ephemeralPub.rawRepresentation + publicKey
        let wrapKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("age-encryption.org/v1/X25519".utf8),
            outputByteCount: 32
        )
        let zeroNonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
        let sealed = try ChaChaPoly.seal(fileKey, using: wrapKey, nonce: zeroNonce, authenticating: Data())
        let wrapped = sealed.ciphertext + sealed.tag  // 16 + 16 = 32 bytes

        let ephArg = Stanza.base64NoPad(ephemeralPub.rawRepresentation)
        return Stanza(type: "X25519", args: [ephArg], body: Data(wrapped))
    }
}

public struct X25519Identity: AgeIdentity {
    public let privateKey: Data  // 32 bytes, raw X25519 scalar
    public let publicKey: Data   // 32 bytes, derived

    public init(privateKey: Data) throws {
        guard privateKey.count == 32 else { throw X25519Error.invalidPrivateKeyLength }
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        self.privateKey = privateKey
        self.publicKey = key.publicKey.rawRepresentation
    }

    /// Parse an `AGE-SECRET-KEY-1...` identity string.
    public init(ageIdentity: String) throws {
        let bytes = try Bech32.decodeAgeIdentity(ageIdentity)
        try self.init(privateKey: Data(bytes))
    }

    /// Generate a fresh X25519 identity.
    public static func generate() -> X25519Identity {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        // Safe: rawRepresentation is always 32 bytes for Curve25519.
        return try! X25519Identity(privateKey: priv.rawRepresentation)
    }

    /// The Bech32-encoded recipient string ("age1...") corresponding to this identity.
    public var ageRecipient: String {
        Bech32.encodeAgeRecipient(Array(publicKey))
    }

    /// The Bech32-encoded identity string ("AGE-SECRET-KEY-1...").
    public var ageIdentityString: String {
        Bech32.encodeAgeIdentity(Array(privateKey))
    }

    public func unwrap(stanza: Stanza) throws -> Data? {
        guard stanza.type == "X25519" else { return nil }
        guard stanza.args.count == 1 else { return nil }

        let ephemeralPubData: Data
        do {
            ephemeralPubData = try Stanza.base64Decode(stanza.args[0])
        } catch {
            return nil
        }
        guard ephemeralPubData.count == 32 else { return nil }

        let myPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let theirPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubData)
        let shared = try myPriv.sharedSecretFromKeyAgreement(with: theirPub)

        let salt = ephemeralPubData + publicKey
        let wrapKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("age-encryption.org/v1/X25519".utf8),
            outputByteCount: 32
        )

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
            // X25519 stanzas are addressed but not labeled by recipient — any
            // identity may attempt every stanza. A failing tag just means
            // "not for me", not a corrupt file.
            return nil
        }
    }
}
