//
//  TagStanza.swift
//  AgePonyCore
//
//  age 1.3's tagged recipients (C2SP age.md), built for identities that live in
//  hardware:
//
//    - classic `age1tag1...`: 33-byte compressed P-256 point, stanza `p256tag`,
//      HPKE DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305;
//    - hybrid `age1tagpq1...`: ML-KEM-768 encapsulation key || 65-byte uncompressed
//      P-256 point, stanza `mlkem768p256tag`, HPKE MLKEM768-P256. Post-quantum, so
//      labelled "postquantum" and refused alongside non-PQ recipients.
//
//  Stanza: `-> <type> base64(tag) base64(enc)` with a 32-byte body. The 4-byte tag is
//  HKDF-Extract(salt = label, ikm = enc || SHA-256(recipient P-256 part)[:4])[:4]; the
//  hybrid form hashes only its uncompressed P-256 part. It lets an identity recognise
//  its stanza without an ECDH, which matters when every ECDH is a Secure Enclave call
//  or a YubiKey tap.
//
//  Interoperates with stock age 1.3, age-plugin-yubikey, age-plugin-se and
//  age-plugin-tpm. Mirrors Android agepony-core `recipients/Tag.kt`.
//

import Foundation
import CryptoKit

/// An identity whose private operation is slow or interactive (Secure Enclave behind a
/// prompt, a YubiKey that needs a tap). `matches` answers from public data alone, so a
/// caller can try every software key first and find out which key a file needs without
/// making the hardware do anything.
public protocol HardwareIdentity: AgeIdentity {
    func matches(stanza: Stanza) -> Bool
}

public enum TagRecipientError: Error, Equatable {
    case invalidLength(Int)
    case unexpectedHRP(String)
    case malformedMLKEMKey
}

public struct TagRecipient: LabeledAgeRecipient, Equatable {
    public static let classicHRP = "age1tag"
    public static let hybridHRP = "age1tagpq"
    public static let classicStanzaType = "p256tag"
    public static let hybridStanzaType = "mlkem768p256tag"
    static let classicLabel = Data("age-encryption.org/p256tag".utf8)
    static let hybridLabel = Data("age-encryption.org/mlkem768p256tag".utf8)
    static let tagSize = 4
    static let bodySize = 32

    /// Raw recipient encoding: 33-byte compressed point, or 1249-byte hybrid key.
    public let publicKey: Data
    public let isHybrid: Bool

    public init(publicKey: Data) throws {
        switch publicKey.count {
        case P256Curve.compressedSize: isHybrid = false
        case HpkeP256.hybridPublicKeySize: isHybrid = true
        default: throw TagRecipientError.invalidLength(publicKey.count)
        }
        self.publicKey = Data(publicKey)
        // Validate the P-256 part now so a bad key fails at parse time. The ML-KEM
        // modulus check runs for keys being entered (Bech32) and again at encrypt time,
        // not here, so a stored key keeps loading and displaying.
        _ = try P256Curve.decode(p256Part)
    }

    /// Parse an `age1tag1...` or `age1tagpq1...` string.
    public init(ageRecipient: String) throws {
        let (hrp, bytes) = try Bech32.decodeBytes(ageRecipient.trimmingCharacters(in: .whitespacesAndNewlines))
        switch hrp {
        case Self.classicHRP:
            guard bytes.count == P256Curve.compressedSize else { throw TagRecipientError.invalidLength(bytes.count) }
        case Self.hybridHRP:
            guard bytes.count == HpkeP256.hybridPublicKeySize else { throw TagRecipientError.invalidLength(bytes.count) }
            guard MLKEM768.isValidEncapsulationKey(Data(bytes.prefix(MLKEM768.encapsulationKeySize))) else {
                throw TagRecipientError.malformedMLKEMKey
            }
        default:
            throw TagRecipientError.unexpectedHRP(hrp)
        }
        try self.init(publicKey: Data(bytes))
    }

    /// True if `string` looks like a tag recipient (classic or hybrid).
    public static func isTagRecipient(_ string: String) -> Bool {
        let t = string.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return t.hasPrefix(classicHRP + "1") || t.hasPrefix(hybridHRP + "1")
    }

    public var stanzaType: String { isHybrid ? Self.hybridStanzaType : Self.classicStanzaType }
    var label: Data { isHybrid ? Self.hybridLabel : Self.classicLabel }
    var kemID: UInt16 { isHybrid ? HpkeP256.kemMLKEM768P256 : HpkeP256.kemDHKEMP256 }

    /// The P-256 part: compressed point (classic) or uncompressed point (hybrid).
    public var p256Part: Data {
        isHybrid ? Data(publicKey.suffix(P256Curve.uncompressedSize)) : publicKey
    }

    public var labels: Set<String> { isHybrid ? [postQuantumLabel] : [] }

    public func wrap(fileKey: Data) throws -> Stanza {
        try wrap(fileKey: fileKey, testRandom: nil)
    }

    /// Test hook. Classic: 32-byte ephemeral scalar. Hybrid: ML-KEM m (32) || P-256 scalar (32).
    internal func wrap(fileKey: Data, testRandom: Data?) throws -> Stanza {
        let (ss, enc) = isHybrid
            ? try HpkeP256.hybridEncap(publicKey: publicKey, testRandom: testRandom)
            : try HpkeP256.dhkemEncap(recipientPublicKey: publicKey, ephemeral: testRandom)
        let body = try HpkeP256.seal(kemID: kemID, sharedSecret: ss, info: label, plaintext: fileKey)
        return Stanza(type: stanzaType, args: [Stanza.base64NoPad(tag(enc: enc)), Stanza.base64NoPad(enc)], body: body)
    }

    /// The 4-byte tag for `enc` under this recipient.
    public func tag(enc: Data) -> Data {
        let rh = Data(SHA256.hash(data: p256Part).prefix(Self.tagSize))
        return Data(HpkeP256.hkdfExtract(salt: label, ikm: enc + rh).prefix(Self.tagSize))
    }

    public func toBech32() -> String {
        Bech32.encodeBytes(hrp: isHybrid ? Self.hybridHRP : Self.classicHRP, bytes: Array(publicKey))
    }
}

/// An identity for a `TagRecipient`. The P-256 half is a `P256KeyAgreement` (a Secure
/// Enclave key, or software); the ML-KEM half of a hybrid identity is an
/// `MLKEMDecapsulation`: a vault seed in the own code or CryptoKit, or, for keys made on
/// iOS 26 and later, a Secure Enclave key (5.1.0 RC3, E8).
///
/// `unwrap` checks the tag before any ECDH or decapsulation, so a hardware key only acts
/// for stanzas addressed to it. Errors from the hardware itself (a cancelled prompt, say)
/// propagate; a failed AEAD open or a stanza for someone else returns nil.
public struct TagIdentity: HardwareIdentity {
    public let recipient: TagRecipient
    let p256: P256KeyAgreement
    let mlkem: (any MLKEMDecapsulation)?

    init(recipient: TagRecipient, p256: P256KeyAgreement, mlkem: (any MLKEMDecapsulation)?) {
        self.recipient = recipient
        self.p256 = p256
        self.mlkem = mlkem
    }

    /// A classic identity whose P-256 key sits behind `p256`; `publicKey` is its point
    /// in any SEC1 encoding.
    public static func classic(publicKey: Data, p256: P256KeyAgreement) throws -> TagIdentity {
        TagIdentity(recipient: try TagRecipient(publicKey: try P256Curve.compressed(publicKey)), p256: p256, mlkem: nil)
    }

    /// A hybrid identity: ML-KEM-768 from `mlkemSeed` (64 bytes, d || z) in software
    /// (CryptoKit on iOS 26 / macOS 26, own code before), P-256 behind `p256` with public
    /// point `p256PublicKey` (any SEC1 encoding).
    public static func hybrid(mlkemSeed: Data, p256PublicKey: Data, p256: P256KeyAgreement) throws -> TagIdentity {
        try hybrid(mlkem: try HybridKEMBackend.mlkemKey(seed: mlkemSeed), p256PublicKey: p256PublicKey, p256: p256)
    }

    /// A hybrid identity whose ML-KEM half is `mlkem`, wherever it lives (a Secure
    /// Enclave key, say), and whose P-256 half is behind `p256` with public point
    /// `p256PublicKey` (any SEC1 encoding).
    public static func hybrid(mlkem: any MLKEMDecapsulation, p256PublicKey: Data, p256: P256KeyAgreement) throws -> TagIdentity {
        let recipient = try TagRecipient(publicKey: mlkem.encapsulationKey + (try P256Curve.uncompressed(p256PublicKey)))
        return TagIdentity(recipient: recipient, p256: p256, mlkem: mlkem)
    }

    /// A stand-in that can only tell which stanzas are addressed to `recipient`, from
    /// public data. It has no private half: `unwrap` never opens anything (a hybrid one
    /// returns nil; a classic one throws, as `RecordedKeyAgreement` with no results does).
    public static func probe(recipient: TagRecipient) -> TagIdentity {
        TagIdentity(recipient: recipient, p256: RecordedKeyAgreement(results: [:]), mlkem: nil)
    }

    /// Fully software classic identity (tests, and devices without a Secure Enclave).
    public static func softwareClassic(scalar: Data) throws -> TagIdentity {
        let sw = try P256SoftwareKey(scalar: scalar)
        return try classic(publicKey: sw.publicUncompressed, p256: sw)
    }

    /// Fully software hybrid identity from a 32-byte seed, matching filippo.io/hpke.
    public static func softwareHybrid(seed: Data) throws -> TagIdentity {
        let (mlkemSeed, d) = try HpkeP256.hybridExpandSeed(seed)
        let sw = try P256SoftwareKey(scalar: d)
        return try hybrid(mlkemSeed: mlkemSeed, p256PublicKey: sw.publicUncompressed, p256: sw)
    }

    public func matches(stanza: Stanza) -> Bool {
        #if os(iOS) || os(macOS)
        // An ML-KEM half that can't be used on this system (RC3 review fix 1) doesn't
        // claim a stanza, so another hardware key (a YubiKey) is still asked for.
        if mlkem is UnavailableMLKEM { return false }
        #endif
        return parse(stanza) != nil
    }

    public func unwrap(stanza: Stanza) throws -> Data? {
        guard let (enc, body) = parse(stanza) else { return nil }
        let ss: Data
        if recipient.isHybrid {
            // A hybrid identity without its ML-KEM half (a probe) can't open anything.
            // Before 5.1.0 this fell through to the classic DHKEM and threw on the enc length.
            guard let mlkem else { return nil }
            do {
                ss = try HpkeP256.hybridDecap(
                    privateKey: HpkeP256.HybridPrivateKey(mlkem: mlkem, p256: p256, p256PublicUncompressed: recipient.p256Part),
                    enc: enc
                )
            } catch is MLKEMDecapsulationRefused {
                // CryptoKit refused a software ML-KEM decapsulation (iOS 26). The own code
                // would have reached "not for me" here, so: nil. Hardware errors propagate.
                return nil
            }
        } else {
            ss = try HpkeP256.dhkemDecap(enc: enc, keyAgreement: p256, recipientPublicKey: recipient.publicKey)
        }
        return try? HpkeP256.open(kemID: recipient.kemID, sharedSecret: ss, info: recipient.label, ciphertext: body)
    }

    private func parse(_ stanza: Stanza) -> (enc: Data, body: Data)? {
        guard stanza.type == recipient.stanzaType, stanza.args.count == 2,
              stanza.body.count == TagRecipient.bodySize,
              let tag = try? Stanza.base64Decode(stanza.args[0]),
              let enc = try? Stanza.base64Decode(stanza.args[1]),
              tag.count == TagRecipient.tagSize,
              enc.count == (recipient.isHybrid ? HpkeP256.hybridEncSize : HpkeP256.dhkemEncSize)
        else { return nil }
        let expected = recipient.tag(enc: enc)
        var diff: UInt8 = 0
        for (a, b) in zip(tag, expected) { diff |= a ^ b }
        return diff == 0 ? (enc, stanza.body) : nil
    }
}
