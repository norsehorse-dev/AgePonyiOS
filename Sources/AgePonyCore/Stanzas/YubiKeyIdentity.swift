//
//  YubiKeyIdentity.swift
//  AgePonyCore
//
//  The decrypting side of age-plugin-yubikey keys.
//
//  An `AGE-PLUGIN-YUBIKEY-1...` identity line is only a pointer: Bech32 (HRP
//  `age-plugin-yubikey-`) of serial (u32 little-endian) || retired slot (0x82...0x95) ||
//  4-byte tag, the tag being SHA-256 of the compressed public key, truncated. The
//  private key never leaves the YubiKey.
//
//  One YubiKey key answers both the older `piv-p256` stanzas and the age 1.3 `p256tag`
//  ones (newer age-plugin-yubikey writes the latter), through one key agreement, so
//  either costs one tap.
//
//  Mirrors Android agepony-core `recipients/YubiKey.kt`.
//

import Foundation
import CryptoKit

public enum YubiKeyError: Error, Equatable {
    case notAStub
    case malformedStub
    case notARetiredSlot(UInt8)
    case keyDoesNotMatchStub
    /// The tapped YubiKey has a different serial from the one the stub names.
    case wrongYubiKey(expected: UInt32, found: UInt32)
}

public struct YubiKeyStub: Equatable, Hashable {
    public static let hrp = "age-plugin-yubikey-"

    public let serial: UInt32
    public let slot: UInt8
    public let tag: Data

    public init(serial: UInt32, slot: UInt8, tag: Data) throws {
        guard (0x82...0x95).contains(slot) else { throw YubiKeyError.notARetiredSlot(slot) }
        guard tag.count == 4 else { throw YubiKeyError.malformedStub }
        self.serial = serial
        self.slot = slot
        self.tag = Data(tag)
    }

    public static func isStub(_ s: String) -> Bool {
        s.trimmingCharacters(in: .whitespacesAndNewlines).uppercased().hasPrefix("AGE-PLUGIN-YUBIKEY-1")
    }

    /// Parse an `AGE-PLUGIN-YUBIKEY-1...` line.
    public init(parsing s: String) throws {
        let (hrp, bytes) = try Bech32.decodeBytes(s.trimmingCharacters(in: .whitespacesAndNewlines))
        guard hrp == Self.hrp else { throw YubiKeyError.notAStub }
        try self.init(bytes: Data(bytes))
    }

    public init(bytes: Data) throws {
        let b = Array(bytes)
        guard b.count >= 9 else { throw YubiKeyError.malformedStub }
        let serial = UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24
        try self.init(serial: serial, slot: b[4], tag: Data(b[5..<9]))
    }

    public var bytes: Data {
        Data([UInt8(serial & 0xFF), UInt8(serial >> 8 & 0xFF), UInt8(serial >> 16 & 0xFF), UInt8(serial >> 24), slot]) + tag
    }

    public func encode() -> String { Bech32.encodeBytes(hrp: Self.hrp, bytes: Array(bytes)).uppercased() }

    public func matchesKey(compressedPublicKey: Data) -> Bool {
        Self.staticTag(compressedPublicKey: compressedPublicKey) == tag
    }

    /// The 4-byte static tag age-plugin-yubikey uses for a key.
    public static func staticTag(compressedPublicKey: Data) -> Data {
        Data(SHA256.hash(data: compressedPublicKey).prefix(4))
    }
}

/// The decrypting side of a `piv-p256` (`age1yubikey1...`) recipient. ECDH goes through
/// `keyAgreement`, which for a real YubiKey is PIV GENERAL AUTHENTICATE over NFC.
///
/// Stanza `piv-p256 <tag> <epk>`: tag = SHA-256(recipient)[:4], epk a compressed point.
/// wrapKey = HKDF-SHA256(ikm = ECDH x, salt = epk || recipient, info = "piv-p256").
public struct PivP256Identity: HardwareIdentity {
    public let compressedPublicKey: Data
    let keyAgreement: P256KeyAgreement
    let tag: Data

    public init(publicKey: Data, keyAgreement: P256KeyAgreement) throws {
        compressedPublicKey = try P256Curve.compressed(publicKey)
        self.keyAgreement = keyAgreement
        tag = YubiKeyStub.staticTag(compressedPublicKey: compressedPublicKey)
    }

    public func matches(stanza: Stanza) -> Bool { epk(of: stanza) != nil }

    public func unwrap(stanza: Stanza) throws -> Data? {
        guard let epk = epk(of: stanza) else { return nil }
        let shared = try keyAgreement.sharedX(peerUncompressed: try P256Curve.uncompressed(epk))
        let wrapKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared),
            salt: epk + compressedPublicKey,
            info: Data("piv-p256".utf8),
            outputByteCount: 32
        )
        guard let box = try? ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: Data(count: 12)),
            ciphertext: stanza.body.prefix(16),
            tag: stanza.body.suffix(16)
        ) else { return nil }
        return try? ChaChaPoly.open(box, using: wrapKey)
    }

    /// The stanza's ephemeral key when the stanza is addressed to this key, else nil.
    func epk(of stanza: Stanza) -> Data? {
        guard stanza.type == "piv-p256", stanza.args.count == 2, stanza.body.count == 32,
              let t = try? Stanza.base64Decode(stanza.args[0]),
              let epk = try? Stanza.base64Decode(stanza.args[1]),
              t.count == 4, epk.count == 33, t == tag,
              (try? P256Curve.decode(epk)) != nil else { return nil }
        return epk
    }
}

/// A YubiKey age identity: one PIV key answering both `piv-p256` and `p256tag` stanzas.
public struct YubiKeyIdentity: HardwareIdentity {
    public let stub: YubiKeyStub
    let piv: PivP256Identity
    let tagged: TagIdentity

    public init(stub: YubiKeyStub, publicKey: Data, keyAgreement: P256KeyAgreement) throws {
        let piv = try PivP256Identity(publicKey: publicKey, keyAgreement: keyAgreement)
        guard stub.matchesKey(compressedPublicKey: piv.compressedPublicKey) else { throw YubiKeyError.keyDoesNotMatchStub }
        self.stub = stub
        self.piv = piv
        self.tagged = try TagIdentity.classic(publicKey: piv.compressedPublicKey, p256: keyAgreement)
    }

    public var compressedPublicKey: Data { piv.compressedPublicKey }

    public func matches(stanza: Stanza) -> Bool { piv.matches(stanza: stanza) || tagged.matches(stanza: stanza) }

    public func unwrap(stanza: Stanza) throws -> Data? {
        switch stanza.type {
        case "piv-p256": return try piv.unwrap(stanza: stanza)
        case TagRecipient.classicStanzaType: return try tagged.unwrap(stanza: stanza)
        default: return nil
        }
    }

    /// The uncompressed peer points the card would have to ECDH with to open a file
    /// with this header, in header order. Lets the app do the NFC exchange up front
    /// (asynchronously) and decrypt with a `RecordedKeyAgreement`.
    public func peerPoints(in stanzas: [Stanza]) -> [Data] {
        stanzas.compactMap { s -> Data? in
            if let epk = piv.epk(of: s) { return try? P256Curve.uncompressed(epk) }
            if tagged.matches(stanza: s), let enc = try? Stanza.base64Decode(s.args[1]) { return enc }
            return nil
        }
    }
}

/// A key agreement whose results were computed elsewhere, keyed by the peer point.
/// For hardware the app talks to asynchronously (a YubiKey over NFC): run the ECDH for
/// each point `YubiKeyIdentity.peerPoints(in:)` names, then decrypt synchronously.
public struct RecordedKeyAgreement: P256KeyAgreement {
    public struct Missing: Error, Equatable {}
    let results: [Data: Data]

    public init(results: [Data: Data]) { self.results = results }

    public func sharedX(peerUncompressed: Data) throws -> Data {
        guard let x = results[Data(peerUncompressed)] else { throw Missing() }
        return x
    }
}
