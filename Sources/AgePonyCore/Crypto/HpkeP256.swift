//
//  HpkeP256.swift
//  AgePonyCore
//
//  HPKE (RFC 9180) base mode, single shot, with HKDF-SHA256 (0x0001) and
//  ChaCha20Poly1305 (0x0003), for the two KEMs age 1.3's tag recipients use:
//
//    - DHKEM(P-256, HKDF-SHA256), KEM id 0x0010, for `p256tag`;
//    - MLKEM768-P256 (draft-ietf-hpke-pq), KEM id 0x0050, for `mlkem768p256tag`.
//
//  Mirrors filippo.io/hpke v0.4.0 (what age 1.3 uses) and Android agepony-core
//  `crypto/HpkeP256.kt`. The key schedule is hand-rolled rather than CryptoKit's `HPKE`
//  so one code path covers both KEMs, and so decapsulation can take a
//  `P256KeyAgreement`: the P-256 half may be a Secure Enclave key, which only offers
//  ECDH.
//

import Foundation
import CryptoKit

// MARK: - P-256 key agreement

/// P-256 ECDH as a pluggable operation, so the private half can live in software or
/// in the Secure Enclave.
public protocol P256KeyAgreement {
    /// ECDH with `peerUncompressed` (65-byte SEC1 point), returning the 32-byte
    /// big-endian x-coordinate of the shared point.
    func sharedX(peerUncompressed: Data) throws -> Data
}

public enum P256CurveError: Error, Equatable {
    case invalidEncoding
    case invalidPoint
    case invalidScalar
}

/// P-256 helpers: strict SEC1 decoding and scalar checks.
public enum P256Curve {
    public static let uncompressedSize = 65
    public static let compressedSize = 33
    public static let scalarSize = 32

    /// The group order n, big-endian.
    static let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ]

    /// Decode a compressed (02/03, 33 bytes) or uncompressed (04, 65 bytes) point,
    /// rejecting every other encoding (including SEC1 "hybrid" 06/07, which age refuses)
    /// and points not on the curve.
    public static func decode(_ encoded: Data) throws -> P256.KeyAgreement.PublicKey {
        let b = Array(encoded)
        do {
            if b.count == compressedSize, b[0] == 0x02 || b[0] == 0x03 {
                return try P256.KeyAgreement.PublicKey(compressedRepresentation: encoded)
            }
            if b.count == uncompressedSize, b[0] == 0x04 {
                return try P256.KeyAgreement.PublicKey(x963Representation: encoded)
            }
        } catch {
            throw P256CurveError.invalidPoint
        }
        throw P256CurveError.invalidEncoding
    }

    public static func uncompressed(_ encoded: Data) throws -> Data {
        try decode(encoded).x963Representation
    }

    public static func compressed(_ encoded: Data) throws -> Data {
        try decode(encoded).compressedRepresentation
    }

    /// True if `d` (32 bytes, big-endian) is a valid private scalar: 0 < d < n.
    public static func isValidScalar(_ d: Data) -> Bool {
        let b = Array(d)
        guard b.count == scalarSize, b.contains(where: { $0 != 0 }) else { return false }
        for i in 0..<scalarSize where b[i] != order[i] {
            return b[i] < order[i]
        }
        return false // d == n
    }

    static func randomScalar() -> Data {
        while true {
            let d = MLKEM768.randomBytes(scalarSize)
            if isValidScalar(d) { return d }
        }
    }
}

/// A P-256 private key held in software. Used for tests and non-hardware paths.
public struct P256SoftwareKey: P256KeyAgreement {
    let key: P256.KeyAgreement.PrivateKey

    public init(scalar: Data) throws {
        guard P256Curve.isValidScalar(scalar) else { throw P256CurveError.invalidScalar }
        key = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
    }

    public init(_ key: P256.KeyAgreement.PrivateKey) { self.key = key }

    public static func generate() -> P256SoftwareKey { P256SoftwareKey(P256.KeyAgreement.PrivateKey()) }

    public var publicUncompressed: Data { key.publicKey.x963Representation }

    public func sharedX(peerUncompressed: Data) throws -> Data {
        let peer = try P256Curve.decode(peerUncompressed)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }
}

// MARK: - HPKE

public enum HpkeP256Error: Error, Equatable {
    case invalidEncLength
    case invalidPublicKeyLength
    case invalidSeedLength
    case invalidTestRandomLength
    case deriveKeyPairFailed
}

public enum HpkeP256 {
    public static let kemDHKEMP256: UInt16 = 0x0010
    public static let kemMLKEM768P256: UInt16 = 0x0050
    static let kdfHKDFSHA256: UInt16 = 0x0001
    static let aeadChaCha20Poly1305: UInt16 = 0x0003

    public static let dhkemEncSize = P256Curve.uncompressedSize                                       // 65
    public static let hybridPublicKeySize = MLKEM768.encapsulationKeySize + P256Curve.uncompressedSize // 1249
    public static let hybridEncSize = MLKEM768.ciphertextSize + P256Curve.uncompressedSize            // 1153
    public static let hybridSeedSize = 32

    static let hpkeV1 = Data("HPKE-v1".utf8)
    static let hybridLabel = Data("MLKEM768-P256".utf8)

    // MARK: DHKEM(P-256, HKDF-SHA256)

    /// Encapsulate to a P-256 public key (any SEC1 encoding). `ephemeral` is a test
    /// hook (32-byte scalar). Returns (sharedSecret, enc).
    static func dhkemEncap(recipientPublicKey: Data, ephemeral: Data? = nil) throws -> (sharedSecret: Data, enc: Data) {
        let pkR = try P256Curve.decode(recipientPublicKey)
        let e = try ephemeral.map { try P256SoftwareKey(scalar: $0) } ?? P256SoftwareKey.generate()
        let enc = e.publicUncompressed
        let dh = try e.sharedX(peerUncompressed: pkR.x963Representation)
        return (dhkemExtractAndExpand(dh: dh, kemContext: enc + pkR.x963Representation), enc)
    }

    /// Public form of `dhkemEncap` without the test hook.
    public static func dhkemEncap(recipientPublicKey: Data) throws -> (sharedSecret: Data, enc: Data) {
        try dhkemEncap(recipientPublicKey: recipientPublicKey, ephemeral: nil)
    }

    /// Decapsulate `enc` for the key behind `keyAgreement`, whose public key is
    /// `recipientPublicKey` (any SEC1 encoding).
    public static func dhkemDecap(enc: Data, keyAgreement: P256KeyAgreement, recipientPublicKey: Data) throws -> Data {
        guard enc.count == dhkemEncSize else { throw HpkeP256Error.invalidEncLength }
        _ = try P256Curve.decode(enc) // reject off-curve input before it reaches hardware
        let dh = try keyAgreement.sharedX(peerUncompressed: enc)
        return dhkemExtractAndExpand(dh: dh, kemContext: enc + (try P256Curve.uncompressed(recipientPublicKey)))
    }

    static func dhkemExtractAndExpand(dh: Data, kemContext: Data) -> Data {
        let suite = kemSuite(kemDHKEMP256)
        let prk = labeledExtract(suite: suite, salt: Data(), label: "eae_prk", ikm: dh)
        return labeledExpand(suite: suite, prk: prk, label: "shared_secret", info: kemContext, length: 32)
    }

    /// RFC 9180 7.1.3 DeriveKeyPair for DHKEM(P-256): deterministic, for test vectors.
    /// Returns the 32-byte scalar.
    public static func dhkemDeriveKeyPair(ikm: Data) throws -> Data {
        let suite = kemSuite(kemDHKEMP256)
        let prk = labeledExtract(suite: suite, salt: Data(), label: "dkp_prk", ikm: ikm)
        for counter in 0..<256 {
            let candidate = labeledExpand(suite: suite, prk: prk, label: "candidate", info: Data([UInt8(counter)]), length: 32)
            if P256Curve.isValidScalar(candidate) { return candidate }
        }
        throw HpkeP256Error.deriveKeyPairFailed
    }

    // MARK: MLKEM768-P256

    /// Hybrid private key material: ML-KEM half in software, P-256 half behind `p256`.
    public struct HybridPrivateKey {
        public let mlkem: MLKEM768.KeyPair
        public let p256: P256KeyAgreement
        public let p256PublicUncompressed: Data

        public init(mlkem: MLKEM768.KeyPair, p256: P256KeyAgreement, p256PublicUncompressed: Data) {
            precondition(p256PublicUncompressed.count == P256Curve.uncompressedSize)
            self.mlkem = mlkem
            self.p256 = p256
            self.p256PublicUncompressed = p256PublicUncompressed
        }

        public var publicKey: Data { mlkem.encapsulationKey + p256PublicUncompressed }
    }

    /// Expand a 32-byte hybrid seed as filippo.io/hpke `NewPrivateKey` does: one
    /// SHAKE256 stream gives the 64-byte ML-KEM seed, then 32-byte P-256 candidates
    /// until one is a valid scalar.
    public static func hybridExpandSeed(_ seed: Data) throws -> (mlkemSeed: Data, p256Scalar: Data) {
        guard seed.count == hybridSeedSize else { throw HpkeP256Error.invalidSeedLength }
        for tries in 1...64 {
            let stream = SHA3.shake256(seed, outputByteCount: MLKEM768.seedSize + 32 * tries)
            let candidate = Data(stream.suffix(32))
            if P256Curve.isValidScalar(candidate) {
                return (Data(stream.prefix(MLKEM768.seedSize)), candidate)
            }
        }
        throw HpkeP256Error.deriveKeyPairFailed
    }

    /// A fully software hybrid key from a 32-byte seed.
    public static func hybridFromSeed(_ seed: Data) throws -> HybridPrivateKey {
        let (mlkemSeed, d) = try hybridExpandSeed(seed)
        let sw = try P256SoftwareKey(scalar: d)
        return HybridPrivateKey(mlkem: try MLKEM768.keyPairFromSeed(mlkemSeed), p256: sw, p256PublicUncompressed: sw.publicUncompressed)
    }

    /// draft-ietf-hpke-pq DeriveKeyPair for MLKEM768-P256: SHAKE256 labeled derive to a
    /// 32-byte seed.
    public static func hybridDeriveSeed(ikm: Data) -> Data {
        let label = Data("DeriveKeyPair".utf8)
        let input = ikm + hpkeV1 + kemSuite(kemMLKEM768P256) + be16(UInt16(label.count)) + label + be16(32)
        return SHA3.shake256(input, outputByteCount: 32)
    }

    /// Encapsulate to a 1249-byte hybrid public key (ek_PQ || uncompressed P-256).
    /// `testRandom` (64 bytes: ML-KEM m || P-256 ephemeral scalar) makes it deterministic.
    static func hybridEncap(publicKey: Data, testRandom: Data? = nil) throws -> (sharedSecret: Data, enc: Data) {
        guard publicKey.count == hybridPublicKeySize else { throw HpkeP256Error.invalidPublicKeyLength }
        if let testRandom, testRandom.count != 64 { throw HpkeP256Error.invalidTestRandomLength }
        let ekPQ = Data(publicKey.prefix(MLKEM768.encapsulationKeySize))
        let ekT = Data(publicKey.suffix(P256Curve.uncompressedSize))
        let pkT = try P256Curve.decode(ekT)

        let e = try testRandom.map { try P256SoftwareKey(scalar: Data($0.suffix(32))) } ?? P256SoftwareKey.generate()
        let ssT = try e.sharedX(peerUncompressed: pkT.x963Representation)
        let ctT = e.publicUncompressed
        let (ssPQ, ctPQ) = try MLKEM768.encapsulate(encapsulationKey: ekPQ, message: testRandom.map { Data($0.prefix(32)) })
        return (hybridCombine(ssPQ: ssPQ, ssT: ssT, ctT: ctT, ekT: ekT), ctPQ + ctT)
    }

    /// Public form of `hybridEncap` without the test hook.
    public static func hybridEncap(publicKey: Data) throws -> (sharedSecret: Data, enc: Data) {
        try hybridEncap(publicKey: publicKey, testRandom: nil)
    }

    public static func hybridDecap(privateKey: HybridPrivateKey, enc: Data) throws -> Data {
        guard enc.count == hybridEncSize else { throw HpkeP256Error.invalidEncLength }
        let ctPQ = Data(enc.prefix(MLKEM768.ciphertextSize))
        let ctT = Data(enc.suffix(P256Curve.uncompressedSize))
        _ = try P256Curve.decode(ctT)
        let ssPQ = try MLKEM768.decapsulate(decapsulationKey: privateKey.mlkem.decapsulationKey, ciphertext: ctPQ)
        let ssT = try privateKey.p256.sharedX(peerUncompressed: ctT)
        return hybridCombine(ssPQ: ssPQ, ssT: ssT, ctT: ctT, ekT: privateKey.p256PublicUncompressed)
    }

    static func hybridCombine(ssPQ: Data, ssT: Data, ctT: Data, ekT: Data) -> Data {
        SHA3.sha3_256(ssPQ + ssT + ctT + ekT + hybridLabel)
    }

    // MARK: Single-shot seal / open

    /// Seal `plaintext` under the HPKE context for `sharedSecret`. Returns ciphertext || tag.
    public static func seal(kemID: UInt16, sharedSecret: Data, info: Data, plaintext: Data) throws -> Data {
        let (key, nonce) = keySchedule(kemID: kemID, sharedSecret: sharedSecret, info: info)
        let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: try ChaChaPoly.Nonce(data: nonce))
        return box.ciphertext + box.tag
    }

    /// Open ciphertext || tag produced by `seal`. Throws on authentication failure.
    public static func open(kemID: UInt16, sharedSecret: Data, info: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw CryptoKitError.authenticationFailure }
        let (key, nonce) = keySchedule(kemID: kemID, sharedSecret: sharedSecret, info: info)
        let box = try ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: nonce),
            ciphertext: ciphertext.prefix(ciphertext.count - 16),
            tag: ciphertext.suffix(16)
        )
        return try ChaChaPoly.open(box, using: SymmetricKey(data: key))
    }

    static func keySchedule(kemID: UInt16, sharedSecret: Data, info: Data) -> (key: Data, nonce: Data) {
        let suite = Data("HPKE".utf8) + be16(kemID) + be16(kdfHKDFSHA256) + be16(aeadChaCha20Poly1305)
        let pskIDHash = labeledExtract(suite: suite, salt: Data(), label: "psk_id_hash", ikm: Data())
        let infoHash = labeledExtract(suite: suite, salt: Data(), label: "info_hash", ikm: info)
        let context = Data([0]) + pskIDHash + infoHash
        let secret = labeledExtract(suite: suite, salt: sharedSecret, label: "secret", ikm: Data())
        return (
            labeledExpand(suite: suite, prk: secret, label: "key", info: context, length: 32),
            labeledExpand(suite: suite, prk: secret, label: "base_nonce", info: context, length: 12)
        )
    }

    // MARK: HKDF-SHA256 with HPKE labels

    static func kemSuite(_ kemID: UInt16) -> Data { Data("KEM".utf8) + be16(kemID) }

    static func labeledExtract(suite: Data, salt: Data, label: String, ikm: Data) -> Data {
        hkdfExtract(salt: salt, ikm: hpkeV1 + suite + Data(label.utf8) + ikm)
    }

    static func labeledExpand(suite: Data, prk: Data, label: String, info: Data, length: Int) -> Data {
        hkdfExpand(prk: prk, info: be16(UInt16(length)) + hpkeV1 + suite + Data(label.utf8) + info, length: length)
    }

    static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        let key = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
        return Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: key)))
    }

    static func hkdfExpand(prk: Data, info: Data, length: Int) -> Data {
        let key = SymmetricKey(data: prk)
        var out = Data()
        var t = Data()
        var counter: UInt8 = 1
        while out.count < length {
            t = Data(HMAC<SHA256>.authenticationCode(for: t + info + Data([counter]), using: key))
            out.append(t)
            counter &+= 1
        }
        return Data(out.prefix(length))
    }

    static func be16(_ v: UInt16) -> Data { Data([UInt8(v >> 8), UInt8(v & 0xff)]) }
}
