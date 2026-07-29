//
//  HpkeMlkem768X25519.swift
//  AgePonyCore
//
//  The MLKEM768-X25519 hybrid KEM (a.k.a. X-Wing, KEM id 0x647a) wrapped in
//  single-shot HPKE (RFC 9180) base mode, exactly as age's `mlkem768x25519`
//  recipient uses it.
//
//  KEM (draft-ietf-hpke-pq / filippo.io/hpke):
//    - an identity is a 32-byte seed; SHAKE256(seed) yields the 64-byte ML-KEM key
//      seed followed by the 32-byte X25519 scalar,
//    - public key = ek_PQ(1184) || ek_T(32) = 1216 bytes,
//    - encap: ss = SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label),
//      enc = ct_PQ(1088) || ct_T(32) = 1120 bytes, where label = 5c2e2f2f5e5c.
//
//  HPKE suite: KEM 0x647a, KDF HKDF-SHA256 (0x0001), AEAD ChaCha20Poly1305 (0x0003).
//  The 16-byte age file key seals to a 32-byte body (16 ciphertext + 16 tag).
//
//  The hybrid is "if either half holds, the file holds": breaking it needs both a
//  quantum computer for ML-KEM and a break of X25519. That is why the combiner
//  mixes both shared secrets, and why a post-quantum recipient refuses to share a
//  file with a classical one — see HybridStanza.swift.
//
//  Pinned byte-for-byte to filippo.io/hpke reference vectors in HybridTests.
//

import Foundation
import CryptoKit

public enum HybridKEMError: Error, Equatable {
    case invalidSeedLength
    case invalidPublicKeyLength
    case invalidEncapsulationLength
    case invalidTestRandomLength
}

public enum HpkeMlkem768X25519 {

    // MARK: - Suite constants

    public static let kemID: UInt16 = 0x647A
    public static let kdfID: UInt16 = 0x0001
    public static let aeadID: UInt16 = 0x0003

    /// Identity seed size.
    public static let seedSize = 32
    /// ek_PQ(1184) || ek_T(32).
    public static let publicKeySize = MLKEM768.encapsulationKeySize + 32   // 1216
    /// ct_PQ(1088) || ct_T(32).
    public static let encSize = MLKEM768.ciphertextSize + 32               // 1120

    /// The hybrid KEM combiner label: the literal bytes `\.//^\`.
    private static let label = Data([0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C])

    /// suite_id = "HPKE" || I2OSP(kem,2) || I2OSP(kdf,2) || I2OSP(aead,2).
    private static let suiteID: Data =
        Data("HPKE".utf8) + be16(kemID) + be16(kdfID) + be16(aeadID)

    private static let hpkeV1 = Data("HPKE-v1".utf8)

    private static func be16(_ v: UInt16) -> Data {
        Data([UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)])
    }

    // MARK: - Key derivation

    /// A hybrid private key derived from a 32-byte identity seed.
    ///
    /// Holds the ML-KEM keypair for decapsulation, the X25519 scalar, and the
    /// concatenated 1216-byte public key. Derivation is deterministic, so the same
    /// seed reproduces the same identity on every device and on the `age` CLI.
    public struct PrivateKey {
        public let seed: Data
        let mlkem: MLKEM768.KeyPair
        let x25519Private: Data
        public let publicKey: Data

        public init(seed: Data) throws {
            guard seed.count == HpkeMlkem768X25519.seedSize else {
                throw HybridKEMError.invalidSeedLength
            }
            // One SHAKE256 stream: 64-byte ML-KEM seed, then the 32-byte X25519 scalar.
            let expanded = SHA3.shake256(seed, outputByteCount: MLKEM768.seedSize + 32)
            let mlkemSeed = Data(expanded.prefix(MLKEM768.seedSize))
            let x25519Priv = Data(expanded.suffix(32))

            self.seed = seed
            self.mlkem = try MLKEM768.keyPairFromSeed(mlkemSeed)
            self.x25519Private = x25519Priv
            self.publicKey = self.mlkem.encapsulationKey
                + (try HpkeMlkem768X25519.x25519PublicKey(x25519Priv))
        }
    }

    // MARK: - X25519 (CryptoKit)

    static func x25519PublicKey(_ privateKey: Data) throws -> Data {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            .publicKey.rawRepresentation
    }

    /// X25519 Diffie-Hellman.
    ///
    /// One deliberate divergence from the reference implementation: CryptoKit
    /// rejects a low-order peer public key by throwing, where filippo.io/hpke and
    /// the `age` CLI would return the all-zero shared secret and carry on. This can
    /// only be reached by encrypting to a hostile `age1pq1…` recipient whose
    /// trailing 32 bytes are a small-order point — in which case refusing is the
    /// better answer. On the decrypt side it is invisible: `HybridIdentity.unwrap`
    /// catches and returns nil, which is already how "not for me" is signalled.
    static func x25519Exchange(privateKey: Data, peerPublicKey: Data) throws -> Data {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
        return shared.withUnsafeBytes { Data($0) }
    }

    // MARK: - KEM

    private static func publicKeyParts(_ pk: Data) throws -> (ekPQ: Data, ekT: Data) {
        guard pk.count == publicKeySize else { throw HybridKEMError.invalidPublicKeyLength }
        return (Data(pk.prefix(MLKEM768.encapsulationKeySize)), Data(pk.suffix(32)))
    }

    private static func combine(ssPQ: Data, ssT: Data, ctT: Data, ekT: Data) -> Data {
        SHA3.sha3_256(ssPQ + ssT + ctT + ekT + label)
    }

    /// Encapsulate to `publicKey`, returning the 32-byte shared secret and 1120-byte enc.
    public static func encap(publicKey: Data) throws -> (sharedSecret: Data, enc: Data) {
        try encap(publicKey: publicKey, testRandom: nil)
    }

    /// Encapsulate with caller-supplied randomness.
    ///
    /// `testRandom` is 64 bytes — ML-KEM `m` (32) followed by the X25519 ephemeral
    /// scalar (32) — making the operation deterministic for known-answer tests.
    ///
    /// Deliberately `internal`. Supplying this from outside the module would let a
    /// caller fix the encapsulation randomness and destroy the confidentiality of
    /// the file, with nothing at the call site to suggest anything unusual had
    /// happened. The public entry point above cannot express it.
    internal static func encap(
        publicKey: Data,
        testRandom: Data?
    ) throws -> (sharedSecret: Data, enc: Data) {
        let (ekPQ, ekT) = try publicKeyParts(publicKey)

        let message: Data?
        let ephemeralPrivate: Data
        if let testRandom {
            guard testRandom.count == 64 else { throw HybridKEMError.invalidTestRandomLength }
            message = Data(testRandom.prefix(32))
            ephemeralPrivate = Data(testRandom.suffix(32))
        } else {
            message = nil
            ephemeralPrivate = MLKEM768.randomBytes(32)
        }

        let (ssPQ, ctPQ) = try MLKEM768.encapsulate(encapsulationKey: ekPQ, message: message)
        let ctT = try x25519PublicKey(ephemeralPrivate)
        let ssT = try x25519Exchange(privateKey: ephemeralPrivate, peerPublicKey: ekT)

        return (combine(ssPQ: ssPQ, ssT: ssT, ctT: ctT, ekT: ekT), ctPQ + ctT)
    }

    /// Decapsulate `enc` with `priv`, returning the 32-byte shared secret.
    public static func decap(priv: PrivateKey, enc: Data) throws -> Data {
        guard enc.count == encSize else { throw HybridKEMError.invalidEncapsulationLength }
        let ctPQ = Data(enc.prefix(MLKEM768.ciphertextSize))
        let ctT = Data(enc.suffix(32))

        let ssPQ = try MLKEM768.decapsulate(
            decapsulationKey: priv.mlkem.decapsulationKey,
            ciphertext: ctPQ
        )
        let ekT = try x25519PublicKey(priv.x25519Private)
        let ssT = try x25519Exchange(privateKey: priv.x25519Private, peerPublicKey: ctT)
        return combine(ssPQ: ssPQ, ssT: ssT, ctT: ctT, ekT: ekT)
    }

    // MARK: - HPKE base mode (single-shot)

    /// Seal `plaintext` to `publicKey` under `info`, returning `(enc, ciphertext)`.
    ///
    /// A single Seal uses sequence number 0, so the AEAD nonce is exactly base_nonce.
    public static func seal(
        publicKey: Data,
        info: Data,
        plaintext: Data
    ) throws -> (enc: Data, ciphertext: Data) {
        try seal(publicKey: publicKey, info: info, plaintext: plaintext, testRandom: nil)
    }

    /// Seal with caller-supplied randomness. `internal` for the same reason as `encap`.
    internal static func seal(
        publicKey: Data,
        info: Data,
        plaintext: Data,
        testRandom: Data?
    ) throws -> (enc: Data, ciphertext: Data) {
        let (sharedSecret, enc) = try encap(publicKey: publicKey, testRandom: testRandom)
        let ctx = keySchedule(sharedSecret: sharedSecret, info: info)
        let nonce = try ChaChaPoly.Nonce(data: ctx.baseNonce)
        let sealed = try ChaChaPoly.seal(
            plaintext,
            using: SymmetricKey(data: ctx.key),
            nonce: nonce,
            authenticating: Data()
        )
        return (enc, sealed.ciphertext + sealed.tag)
    }

    /// Open a ciphertext produced by `seal` for `enc` under `info`.
    public static func open(
        priv: PrivateKey,
        enc: Data,
        info: Data,
        ciphertext: Data
    ) throws -> Data {
        let sharedSecret = try decap(priv: priv, enc: enc)
        let ctx = keySchedule(sharedSecret: sharedSecret, info: info)
        let nonce = try ChaChaPoly.Nonce(data: ctx.baseNonce)
        // ChaCha20Poly1305 tags are always the trailing 16 bytes.
        guard ciphertext.count >= 16 else { throw CryptoKitError.authenticationFailure }
        let box = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: ciphertext.prefix(ciphertext.count - 16),
            tag: ciphertext.suffix(16)
        )
        return try ChaChaPoly.open(box, using: SymmetricKey(data: ctx.key), authenticating: Data())
    }

    private struct Context {
        let key: Data
        let baseNonce: Data
    }

    private static func keySchedule(sharedSecret: Data, info: Data) -> Context {
        let pskIDHash = labeledExtract(salt: Data(), label: "psk_id_hash", ikm: Data())
        let infoHash = labeledExtract(salt: Data(), label: "info_hash", ikm: info)
        let ksContext = Data([0]) + pskIDHash + infoHash          // mode_base = 0x00
        let secret = labeledExtract(salt: sharedSecret, label: "secret", ikm: Data())
        return Context(
            key: labeledExpand(prk: secret, label: "key", info: ksContext, length: 32),      // Nk
            baseNonce: labeledExpand(prk: secret, label: "base_nonce", info: ksContext, length: 12)  // Nn
        )
    }

    private static func labeledExtract(salt: Data, label: String, ikm: Data) -> Data {
        hkdfExtract(salt: salt, ikm: hpkeV1 + suiteID + Data(label.utf8) + ikm)
    }

    private static func labeledExpand(prk: Data, label: String, info: Data, length: Int) -> Data {
        hkdfExpand(
            prk: prk,
            info: be16(UInt16(length)) + hpkeV1 + suiteID + Data(label.utf8) + info,
            length: length
        )
    }

    // MARK: - HKDF-SHA256 (RFC 5869)
    //
    // Extract and expand are kept separate because HPKE calls them independently;
    // CryptoKit's one-shot HKDF cannot express that.

    private static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        // RFC 5869: an absent salt is HashLen zero bytes.
        let keyData = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
        return Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: keyData)))
    }

    private static func hkdfExpand(prk: Data, info: Data, length: Int) -> Data {
        let key = SymmetricKey(data: prk)
        var out = Data()
        var t = Data()
        var counter: UInt8 = 1
        while out.count < length {
            var input = Data()
            input.append(t)
            input.append(info)
            input.append(counter)
            t = Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
            out.append(t)
            counter += 1
        }
        return Data(out.prefix(length))
    }
}
