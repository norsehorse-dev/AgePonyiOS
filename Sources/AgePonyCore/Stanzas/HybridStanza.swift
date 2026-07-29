//
//  HybridStanza.swift
//  AgePonyCore
//
//  The post-quantum age recipient: the standardized MLKEM768-X25519 hybrid
//  (`mlkem768x25519` stanza, `age1pq1…` public key). Files encrypted to this
//  recipient interoperate with the `age` CLI v1.3.0+.
//
//  Wrap:
//    HPKE.Seal(publicKey, info = "age-encryption.org/mlkem768x25519", fileKey)
//    stanza = -> mlkem768x25519 base64(enc)
//             base64(body)
//
//  Key strings:
//    age1pq1…              1216-byte hybrid public key
//    AGE-SECRET-KEY-PQ-1…  32-byte identity seed
//
//  Note that an `age1pq1…` recipient is ~1959 characters, far past BIP-0173's
//  90-character limit. age applies no such limit; see Bech32.swift.
//

import Foundation

public enum HybridStanzaError: Error, Equatable {
    case invalidPublicKeyLength
    case invalidSeedLength
}

/// age's label marking a recipient as post-quantum.
public let postQuantumLabel = "postquantum"

// The `age1pq` / `AGE-SECRET-KEY-PQ-` human-readable parts are owned by Bech32.swift,
// alongside the classical ones, rather than being restated here — one definition per
// constant, so an HRP cannot drift between the encoder and this file.
private let hybridStanzaType = "mlkem768x25519"
private let hybridInfo = "age-encryption.org/mlkem768x25519"
private let hybridBodySize = 16 + 16   // file key + ChaCha20Poly1305 tag

// MARK: - Recipient

/// A post-quantum age recipient.
///
/// Carries the `postquantum` label, so age refuses to put it in a file alongside a
/// classical recipient. That rule is not pedantry: a file readable by an X25519 key
/// is only as quantum-safe as X25519, so mixing would silently undo the point of
/// choosing a post-quantum recipient at all.
public struct HybridRecipient: LabeledAgeRecipient {
    public let publicKey: Data   // 1216 bytes

    public var labels: Set<String> { [postQuantumLabel] }

    public init(publicKey: Data) throws {
        guard publicKey.count == HpkeMlkem768X25519.publicKeySize else {
            throw HybridStanzaError.invalidPublicKeyLength
        }
        self.publicKey = publicKey
    }

    /// Parse an `age1pq1…` recipient string.
    public init(ageRecipient: String) throws {
        try self.init(publicKey: Data(try Bech32.decodePostQuantumRecipient(ageRecipient)))
    }

    public func wrap(fileKey: Data) throws -> Stanza {
        try wrap(fileKey: fileKey, testRandom: nil)
    }

    /// Deterministic wrap, for known-answer tests. `testRandom` is 64 bytes:
    /// ML-KEM `m` followed by the X25519 ephemeral scalar.
    internal func wrap(fileKey: Data, testRandom: Data?) throws -> Stanza {
        let (enc, ciphertext) = try HpkeMlkem768X25519.seal(
            publicKey: publicKey,
            info: Data(hybridInfo.utf8),
            plaintext: fileKey,
            testRandom: testRandom
        )
        return Stanza(
            type: hybridStanzaType,
            args: [Stanza.base64NoPad(enc)],
            body: ciphertext
        )
    }

    /// This public key as an `age1pq1…` string.
    public var ageRecipient: String {
        Bech32.encodePostQuantumRecipient(Array(publicKey))
    }
}

// MARK: - Identity

/// A post-quantum age identity: a 32-byte seed encoded as `AGE-SECRET-KEY-PQ-1…`.
///
/// The ML-KEM and X25519 keys are both derived deterministically from the seed, so
/// the seed alone is the whole backup.
public struct HybridIdentity: AgeIdentity {
    /// The 32-byte identity seed.
    public let seed: Data

    private let key: HpkeMlkem768X25519.PrivateKey

    /// The 1216-byte hybrid public key.
    public var publicKey: Data { key.publicKey }

    public init(seed: Data) throws {
        guard seed.count == HpkeMlkem768X25519.seedSize else {
            throw HybridStanzaError.invalidSeedLength
        }
        self.seed = seed
        self.key = try HpkeMlkem768X25519.PrivateKey(seed: seed)
    }

    /// Parse an `AGE-SECRET-KEY-PQ-1…` identity string (case-insensitive per BIP-0173).
    public init(ageIdentity: String) throws {
        try self.init(seed: Data(try Bech32.decodePostQuantumIdentity(ageIdentity)))
    }

    /// Generate a fresh post-quantum identity.
    public static func generate() throws -> HybridIdentity {
        try HybridIdentity(seed: MLKEM768.randomBytes(HpkeMlkem768X25519.seedSize))
    }

    /// The recipient corresponding to this identity.
    public func recipient() throws -> HybridRecipient {
        try HybridRecipient(publicKey: publicKey)
    }

    /// This identity as an `AGE-SECRET-KEY-PQ-1…` string.
    public var ageIdentityString: String {
        Bech32.encodePostQuantumIdentity(Array(seed))
    }

    public func unwrap(stanza: Stanza) throws -> Data? {
        guard stanza.type == hybridStanzaType else { return nil }
        guard stanza.args.count == 1 else { return nil }

        let enc: Data
        do {
            enc = try Stanza.base64Decode(stanza.args[0])
        } catch {
            return nil
        }
        guard enc.count == HpkeMlkem768X25519.encSize else { return nil }
        guard stanza.body.count == hybridBodySize else { return nil }

        do {
            return try HpkeMlkem768X25519.open(
                priv: key,
                enc: enc,
                info: Data(hybridInfo.utf8),
                ciphertext: stanza.body
            )
        } catch {
            // Not our stanza, or authentication failed. Same as X25519: a failing
            // tag means "not for me", not a corrupt file.
            return nil
        }
    }
}
