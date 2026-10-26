//
//  P256Stanza.swift
//  AgePonyCore
//
//  piv-p256 recipient stanza — the `age1yubikey1...` recipient produced by
//  age-plugin-yubikey. AgePony can *encrypt to* one of these in software; only
//  the YubiKey itself can decrypt, so there is no matching identity here. This
//  mirrors Android agepony-core `recipients/P256.kt` byte-for-byte.
//
//  Encrypt to recipient (compressed SEC1 P-256 public key, 33 bytes):
//    1. Generate an ephemeral P-256 keypair (e, E). E is the 33-byte
//       compressed point.
//    2. shared = ECDH(e, recipient_pub) x-coordinate (32 bytes, big-endian).
//    3. wrap_key = HKDF-SHA-256(
//         ikm  = shared,
//         salt = E || recipient_pub,           (33 + 33 = 66 bytes)
//         info = "piv-p256",
//         L    = 32)
//    4. body = ChaCha20-Poly1305.seal(file_key, key=wrap_key,
//                                     nonce=12 zero bytes, aad=empty)
//    5. tag  = SHA-256(recipient_pub)[0..<4].
//    6. Stanza:
//         -> piv-p256 base64(tag) base64(E)
//         base64(body)            // 32 bytes = 16 ciphertext + 16 auth tag
//
//  Verified against str4d/age-plugin-yubikey `src/piv_p256.rs` (wrap_file_key,
//  salt, STANZA_KEY_LABEL) and `src/recipient.rs` (static_tag, TAG_BYTES = 4),
//  cross-checked against Android P256.kt and its on-device YubiKey decrypt.
//

import Foundation
import CryptoKit

public enum P256RecipientError: Error, Equatable {
    case invalidPublicKeyLength
    case invalidCompressionByte
    case invalidPoint
    case unexpectedHRP
}

/// An age piv-p256 recipient (`age1yubikey1...`). Encrypt-only.
public struct P256Recipient: AgeRecipient {
    /// Compressed SEC1 P-256 public key, 33 bytes (leading 0x02 or 0x03).
    public let compressedPublicKey: Data

    private static let stanzaType = "piv-p256"
    private static let tagByteCount = 4
    private static let info = Data("piv-p256".utf8)

    public init(compressedPublicKey: Data) throws {
        guard compressedPublicKey.count == 33 else {
            throw P256RecipientError.invalidPublicKeyLength
        }
        let lead = compressedPublicKey[compressedPublicKey.startIndex]
        guard lead == 0x02 || lead == 0x03 else {
            throw P256RecipientError.invalidCompressionByte
        }
        // Reject a point that is not on the curve; the initializer throws otherwise.
        do {
            _ = try P256.KeyAgreement.PublicKey(compressedRepresentation: compressedPublicKey)
        } catch {
            throw P256RecipientError.invalidPoint
        }
        self.compressedPublicKey = compressedPublicKey
    }

    /// Parse a Bech32 `age1yubikey1...` recipient string.
    public init(ageRecipient: String) throws {
        let bytes = try Bech32.decodeYubiKeyRecipient(ageRecipient)
        try self.init(compressedPublicKey: Data(bytes))
    }

    public func wrap(fileKey: Data) throws -> Stanza {
        try wrap(fileKey: fileKey, ephemeral: P256.KeyAgreement.PrivateKey())
    }

    /// Testable seam: wrap with a caller-supplied ephemeral so a known-answer
    /// vector can pin exact bytes. Production `wrap(fileKey:)` passes a fresh key.
    internal func wrap(fileKey: Data, ephemeral: P256.KeyAgreement.PrivateKey) throws -> Stanza {
        let theirPub = try P256.KeyAgreement.PublicKey(compressedRepresentation: compressedPublicKey)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: theirPub)
        let epk = ephemeral.publicKey.compressedRepresentation // 33 bytes

        let salt = epk + compressedPublicKey
        let wrapKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Self.info,
            outputByteCount: 32
        )

        let zeroNonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
        let sealed = try ChaChaPoly.seal(fileKey, using: wrapKey, nonce: zeroNonce, authenticating: Data())
        let body = sealed.ciphertext + sealed.tag // 16 + 16 = 32 bytes

        let digest = SHA256.hash(data: compressedPublicKey)
        let tag = Data(Array(digest).prefix(Self.tagByteCount))

        return Stanza(
            type: Self.stanzaType,
            args: [Stanza.base64NoPad(tag), Stanza.base64NoPad(epk)],
            body: Data(body)
        )
    }

    /// Encode back to the `age1yubikey1...` Bech32 string.
    public func toBech32() -> String {
        Bech32.encodeYubiKeyRecipient(Array(compressedPublicKey))
    }
}
