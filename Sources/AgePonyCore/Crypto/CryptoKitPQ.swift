//
//  CryptoKitPQ.swift
//  AgePonyCore
//
//  5.1.0 RC3 (E8): the CryptoKit side of the post-quantum KEMs, iOS 26 / macOS 26 and
//  later. HybridKEMBackend decides when these run; the API calls are the ones the RC3
//  spike (CryptoKitSpikeTests) compiled and passed against the CCTV vectors and
//  AgePony's own code.
//
//    - age's `mlkem768x25519` suite: HPKE base mode, KEM X-Wing (MLKEM768-X25519,
//      0x647A), HKDF-SHA256, ChaCha20Poly1305, built by hand because CryptoKit's own
//      post-quantum suite is AES-GCM.
//    - ML-KEM-768 from the 64-byte seed (d || z) an `age1tagpq1` key keeps in the
//      vault, and encapsulation to an `age1tagpq1` recipient's ML-KEM half. The
//      MLKEM768-P256 combiner and key schedule stay AgePony's (HpkeP256.swift):
//      CryptoKit has no MLKEM768-P256 KEM.
//
//  Name clash: AgePonyCore and CryptoKit both have a `MLKEM768`. This file writes
//  `AgePonyCore.MLKEM768` and `CryptoKit.MLKEM768` every time.
//
//  Compile gate: the post-quantum types exist only in the iOS 26 / macOS 26 SDK
//  (Xcode 26, Swift 6.2). With an older Xcode this file is empty and the own code runs.
//

#if (os(iOS) || os(macOS)) && compiler(>=6.2)
import Foundation
import CryptoKit

// MARK: - X-Wing HPKE (mlkem768x25519)

@available(iOS 26, macOS 26, *)
enum CryptoKitXWing {
    static var suite: HPKE.Ciphersuite {
        HPKE.Ciphersuite(kem: .XWingMLKEM768X25519, kdf: .HKDF_SHA256, aead: .chaChaPoly)
    }

    /// Single-shot seal: the first message of a context uses base_nonce, as age does.
    /// Empty AAD. The caller has already run AgePony's recipient checks.
    static func seal(publicKey: Data, info: Data, plaintext: Data) throws -> (enc: Data, ciphertext: Data) {
        let pk = try XWingMLKEM768X25519.PublicKey(rawRepresentation: publicKey)
        var sender = try HPKE.Sender(recipientKey: pk, ciphersuite: suite, info: info)
        let ciphertext = try sender.seal(plaintext, authenticating: Data())
        return (sender.encapsulatedKey, ciphertext)
    }
}

/// An `age1pq1` identity's private half in CryptoKit, from the 32-byte seed inside an
/// `AGE-SECRET-KEY-PQ-1` string. The spike (S2) showed CryptoKit derives the same
/// 1216-byte public key from the same seed.
@available(iOS 26, macOS 26, *)
struct CryptoKitXWingKey: XWingDecryptionKey {
    let key: XWingMLKEM768X25519.PrivateKey
    /// The X25519 scalar, derived as the own code does (SHAKE256(seed), bytes 64..<96),
    /// only for AgePony's low-order check on `ct_T` before CryptoKit opens.
    let x25519Private: Data
    let publicKey: Data

    init(seed: Data) throws {
        guard seed.count == HpkeMlkem768X25519.seedSize else { throw HybridKEMError.invalidSeedLength }
        let key = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)
        self.key = key
        self.x25519Private = Data(SHA3.shake256(seed, outputByteCount: AgePonyCore.MLKEM768.seedSize + 32).suffix(32))
        self.publicKey = key.publicKey.rawRepresentation
        guard publicKey.count == HpkeMlkem768X25519.publicKeySize else { throw HybridKEMError.invalidPublicKeyLength }
    }

    func open(enc: Data, info: Data, ciphertext: Data) throws -> Data {
        guard enc.count == HpkeMlkem768X25519.encSize else { throw HybridKEMError.invalidEncapsulationLength }
        // AgePony's own refusal of a low-order or identity X25519 share, the same
        // exchange the own code makes. CryptoKit refuses the CCTV ones too, but age's rule
        // stays ours, and it runs first: any failure here is `lowOrderPoint`, an error
        // CryptoKit never throws, which is how the tests see the order.
        do {
            _ = try HpkeMlkem768X25519.x25519Exchange(privateKey: x25519Private, peerPublicKey: Data(enc.suffix(32)))
        } catch {
            throw HybridKEMError.lowOrderPoint
        }
        var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: CryptoKitXWing.suite,
                                           info: info, encapsulatedKey: enc)
        return try recipient.open(ciphertext, authenticating: Data())
    }
}

// MARK: - ML-KEM-768

@available(iOS 26, macOS 26, *)
enum CryptoKitMLKEM {
    /// Encapsulate to a 1184-byte key the caller has already checked (length and FIPS 203).
    static func encapsulate(encapsulationKey: Data) throws -> (sharedSecret: Data, ciphertext: Data) {
        let pk = try CryptoKit.MLKEM768.PublicKey(rawRepresentation: encapsulationKey)
        let result = try pk.encapsulate()
        guard result.encapsulated.count == AgePonyCore.MLKEM768.ciphertextSize else {
            throw MLKEMError.invalidCiphertextLength
        }
        return (bytes(result.sharedSecret), result.encapsulated)
    }

    static func bytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }
}

/// The ML-KEM half of an existing `age1tagpq1` key (64-byte vault seed) in CryptoKit.
/// The spike (S3) showed the same encapsulation key, the same shared secrets both ways,
/// and the same implicit-rejection secret as the own code.
@available(iOS 26, macOS 26, *)
struct CryptoKitMLKEMKey: MLKEMDecapsulation {
    let key: CryptoKit.MLKEM768.PrivateKey
    let encapsulationKey: Data

    init(seed: Data) throws {
        guard seed.count == AgePonyCore.MLKEM768.seedSize else { throw MLKEMError.invalidSeedLength }
        let key = try CryptoKit.MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil)
        self.key = key
        self.encapsulationKey = key.publicKey.rawRepresentation
        guard encapsulationKey.count == AgePonyCore.MLKEM768.encapsulationKeySize else {
            throw MLKEMError.invalidEncapsulationKeyLength
        }
    }

    func decapsulate(ciphertext: Data) throws -> Data {
        guard ciphertext.count == AgePonyCore.MLKEM768.ciphertextSize else { throw MLKEMError.invalidCiphertextLength }
        do {
            return CryptoKitMLKEM.bytes(try key.decapsulate(ciphertext))
        } catch {
            // No own-code retry. The own code never fails here (implicit rejection), so
            // the outcome it would reach is "not for me": TagIdentity.unwrap returns nil
            // for this error.
            throw MLKEMDecapsulationRefused()
        }
    }
}
#endif
