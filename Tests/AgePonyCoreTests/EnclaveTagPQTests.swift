//
//  EnclaveTagPQTests.swift
//  AgePonyCoreTests
//
//  5.1.0 RC3 (E8): quantum-safe hardware keys (`age1tagpq1`) with both halves in the
//  Secure Enclave on iOS 26 / macOS 26.
//
//    - the vault layout (SecureEnclaveTagPQMaterial): round trips, magic detection, and
//      the 5.0.1 layout never read as the new one;
//    - TagIdentity with a pluggable ML-KEM half, and the public-only probe returning nil
//      instead of throwing;
//    - the Enclave path end to end through the real Sources types (spike S4d without the
//      test-local sketch), skipped when this process can't make Enclave keys;
//    - what a 5.0.1 build does with the new layout: that key fails to decrypt, nothing else.
//

import XCTest
import Foundation
#if os(iOS) || os(macOS)
import LocalAuthentication
#endif
@testable import AgePonyCore

final class EnclaveTagPQTests: XCTestCase {

    static func random(_ n: Int) -> Data { AgePonyCore.MLKEM768.randomBytes(n) }

    // MARK: - Layout

    func test_layout_enclave_roundTrips() throws {
        let mlkemBlob = Self.random(1489)
        let p256Blob = Self.random(324)
        let material = try SecureEnclaveTagPQMaterial.enclave(mlkemBlob: mlkemBlob, p256Blob: p256Blob).encoded()
        XCTAssertEqual(material.prefix(8), Data("AGPNSE2\0".utf8))
        XCTAssertEqual(SecureEnclaveTagPQMaterial.magic.count, 8)
        XCTAssertEqual(Array(material[8..<12]), [0x00, 0x00, 0x05, 0xD1])        // 1489, big-endian
        XCTAssertEqual(material.count, 8 + 4 + 1489 + 324)
        let decoded = try SecureEnclaveTagPQMaterial.decode(material)
        XCTAssertEqual(decoded, .enclave(mlkemBlob: mlkemBlob, p256Blob: p256Blob))
        XCTAssertTrue(decoded.mlkemInEnclave)
        XCTAssertEqual(decoded.p256Blob, p256Blob)
        // A slice with a non-zero startIndex decodes the same.
        let sliced = (Data([1, 2, 3]) + material).dropFirst(3)
        XCTAssertEqual(try SecureEnclaveTagPQMaterial.decode(sliced), decoded)
    }

    func test_layout_vaultSeed_roundTrips_andMatches501Bytes() throws {
        let seed = Self.random(64)
        let p256Blob = Self.random(324)
        let material = try SecureEnclaveTagPQMaterial.vaultSeed(mlkemSeed: seed, p256Blob: p256Blob).encoded()
        XCTAssertEqual(material, seed + p256Blob, "the 5.0.1 layout is seed || blob, unchanged")
        let decoded = try SecureEnclaveTagPQMaterial.decode(material)
        XCTAssertEqual(decoded, .vaultSeed(mlkemSeed: seed, p256Blob: p256Blob))
        XCTAssertFalse(decoded.mlkemInEnclave)
    }

    /// Random 5.0.1 records are never read as the new layout, including ones built to
    /// start with the magic but whose length field doesn't fit.
    func test_layout_oldLayout_neverMisdetected() throws {
        for _ in 0..<200 {
            let material = Self.random(64) + Self.random(Int.random(in: 1...600))
            XCTAssertFalse(try SecureEnclaveTagPQMaterial.decode(material).mlkemInEnclave)
        }
        let magic = SecureEnclaveTagPQMaterial.magic
        // Magic, then a length longer than what follows.
        let tooLong = magic + Data([0x00, 0x00, 0xFF, 0xFF]) + Self.random(52) + Self.random(324)
        XCTAssertEqual(try SecureEnclaveTagPQMaterial.decode(tooLong),
                       .vaultSeed(mlkemSeed: Data(tooLong.prefix(64)), p256Blob: Data(tooLong.dropFirst(64))))
        // Magic, then a zero length.
        let zero = magic + Data([0, 0, 0, 0]) + Self.random(52) + Self.random(324)
        XCTAssertFalse(try SecureEnclaveTagPQMaterial.decode(zero).mlkemInEnclave)
        // Magic, then a length above the cap.
        let huge = magic + Data([0x7F, 0xFF, 0xFF, 0xFF]) + Self.random(52) + Self.random(324)
        XCTAssertFalse(try SecureEnclaveTagPQMaterial.decode(huge).mlkemInEnclave)
        // Magic and a length that uses up every byte: no P-256 blob left, so not the new layout.
        let rest = Self.random(376)
        let noP256 = magic + Data([0x00, 0x00, 0x01, 0x78]) + rest
        XCTAssertFalse(try SecureEnclaveTagPQMaterial.decode(noP256).mlkemInEnclave)
    }

    func test_layout_malformed() throws {
        XCTAssertThrowsError(try SecureEnclaveTagPQMaterial.decode(Data()))
        XCTAssertThrowsError(try SecureEnclaveTagPQMaterial.decode(Self.random(64))) {
            XCTAssertEqual($0 as? SecureEnclaveTagPQMaterialError, .malformed)
        }
        XCTAssertThrowsError(try SecureEnclaveTagPQMaterial.enclave(mlkemBlob: Data(), p256Blob: Self.random(10)).encoded())
        XCTAssertThrowsError(try SecureEnclaveTagPQMaterial.enclave(mlkemBlob: Self.random(10), p256Blob: Data()).encoded())
        XCTAssertThrowsError(try SecureEnclaveTagPQMaterial.vaultSeed(mlkemSeed: Self.random(63), p256Blob: Self.random(10)).encoded())
    }

    // MARK: - TagIdentity with a pluggable ML-KEM half

    /// Counts decapsulations, standing in for an Enclave ML-KEM key.
    final class CountingMLKEM: MLKEMDecapsulation {
        let inner = try! AgePonyCore.MLKEM768.keyPairFromSeed(AgePonyCore.MLKEM768.randomBytes(64))
        var calls = 0
        var encapsulationKey: Data { inner.encapsulationKey }
        func decapsulate(ciphertext: Data) throws -> Data {
            calls += 1
            return try inner.decapsulate(ciphertext: ciphertext)
        }
    }

    func test_pluggableMLKEM_roundTrips_andOnlyActsForItsStanzas() throws {
        let mlkem = CountingMLKEM()
        let p256 = P256SoftwareKey.generate()
        let id = try TagIdentity.hybrid(mlkem: mlkem, p256PublicKey: p256.publicUncompressed, p256: p256)
        XCTAssertEqual(id.recipient.publicKey, mlkem.encapsulationKey + p256.publicUncompressed)
        let pt = Data("pluggable".utf8)
        let ct = try Age.encrypt(plaintext: pt, to: [try TagRecipient(ageRecipient: id.recipient.toBech32())])
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [id]), pt)
        XCTAssertEqual(mlkem.calls, 1)

        let other = try TagIdentity.softwareHybrid(seed: Self.random(32))
        let foreign = try Age.encrypt(plaintext: pt, to: [other.recipient])
        XCTAssertThrowsError(try Age.decrypt(ciphertext: foreign, identities: [id]))
        XCTAssertEqual(mlkem.calls, 1, "a stanza for another key is refused on the tag, before ML-KEM")
    }

    func test_probe_matchesFromPublicData_andUnwrapReturnsNil() throws {
        let real = try TagIdentity.softwareHybrid(seed: Self.random(32))
        let probe = TagIdentity.probe(recipient: real.recipient)
        let stanza = try real.recipient.wrap(fileKey: Self.random(16))
        XCTAssertTrue(probe.matches(stanza: stanza))
        // Before 5.1.0 a hybrid identity with no ML-KEM half threw here (classic DHKEM on a
        // 1153-byte enc). Now: nil, "can't open".
        XCTAssertNil(try probe.unwrap(stanza: stanza))
        let other = try TagIdentity.softwareHybrid(seed: Self.random(32)).recipient.wrap(fileKey: Self.random(16))
        XCTAssertFalse(probe.matches(stanza: other))
    }

    // MARK: - Secure Enclave (macOS / iOS)

    #if os(iOS) || os(macOS)

    /// A real Enclave-layout key, or XCTSkip with the reason.
    func makeEnclaveKey() throws -> (privateKeyMaterial: Data, publicKey: Data) {
        guard SecureEnclaveTagPQ.mlkemInEnclaveAvailable else {
            print("RC3-SE: SKIPPED, Secure Enclave ML-KEM not available here (needs macOS 26 / iOS 26, Xcode 26 and an Enclave)")
            throw XCTSkip("Secure Enclave ML-KEM-768 needs macOS 26 / iOS 26 and a Secure Enclave")
        }
        do {
            return try SecureEnclaveTagPQ.generate(protection: .noPrompt, mlkemInEnclave: true)
        } catch {
            print("RC3-SE: SKIPPED, Enclave key creation threw \(error) in this process")
            throw XCTSkip("Secure Enclave key creation failed in this test process: \(error)")
        }
    }

    /// Spike S4d through the real types: generate, Bech32 round trip (FIPS 203 check),
    /// Age.encrypt, then decrypt with the identity the vault would hydrate.
    func test_enclaveKey_endToEnd() throws {
        let key = try makeEnclaveKey()
        let layout = try SecureEnclaveTagPQMaterial.decode(key.privateKeyMaterial)
        XCTAssertTrue(layout.mlkemInEnclave, "a key made with the Enclave available stores no seed")
        XCTAssertEqual(key.publicKey.count, HpkeP256.hybridPublicKeySize)
        if case .enclave(let mlkemBlob, let p256Blob) = layout {
            print("RC3-SE: blobs ML-KEM \(mlkemBlob.count) bytes, P-256 \(p256Blob.count) bytes")
        }
        let recipient = try TagRecipient(ageRecipient: try TagRecipient(publicKey: key.publicKey).toBech32())
        XCTAssertEqual(recipient.publicKey, key.publicKey)

        let contexts: [(String, LAContext?)] = [("no context", nil), ("shared LAContext", LAContext())]
        for (label, context) in contexts {
            let pt = Data("RC3 \(label) \(UUID().uuidString)".utf8)
            let file = try Age.encrypt(plaintext: pt, to: [recipient])
            let identity = try SecureEnclaveTagPQ.identity(privateKeyMaterial: key.privateKeyMaterial,
                                                           publicKey: key.publicKey,
                                                           authenticationContext: context)
            XCTAssertEqual(identity.recipient, recipient)
            // Both halves share one non-nil LAContext, the one passed in if any (one prompt).
            let p256 = try XCTUnwrap(identity.p256 as? SecureEnclaveKeyAgreement, label)
            let shared = try XCTUnwrap(p256.context, "\(label): P-256 half has no LAContext")
            #if compiler(>=6.2)
            if #available(iOS 26, macOS 26, *) {
                let mlkem = try XCTUnwrap(identity.mlkem as? SecureEnclaveMLKEM, label)
                XCTAssertTrue(mlkem.context === shared, "\(label): the two halves have different LAContexts")
            } else {
                XCTFail("an Enclave-layout key was made below macOS 26")
            }
            #endif
            if let context { XCTAssertTrue(shared === context, "\(label): not the context passed in") }
            XCTAssertEqual(try Age.decrypt(ciphertext: file, identities: [identity]), pt, label)
            // Both backends encrypt to it.
            let ownFile = try HybridKEMBackend.withOwnCode { try Age.encrypt(plaintext: pt, to: [recipient]) }
            XCTAssertEqual(try Age.decrypt(ciphertext: ownFile, identities: [identity]), pt, "\(label), own-code encrypt")
        }
        print("RC3-SE: age1tagpq1 key with both halves in the Enclave: encrypt and decrypt ok")
    }

    /// iOS 26, but the Enclave won't make the ML-KEM key: the key is still made, in the
    /// vault-seed layout with the P-256 Enclave key, and decrypts (RC3 review fix 3).
    func test_generate_enclaveMLKEMRefused_fallsBackToVaultSeedLayout() throws {
        guard SecureEnclaveKeyAgreement.isAvailable else { throw XCTSkip("no Secure Enclave") }
        struct Refused: Error {}
        let key: (privateKeyMaterial: Data, publicKey: Data)
        do {
            key = try SecureEnclaveTagPQ.generate(protection: .noPrompt, mlkemInEnclave: true,
                                                  makeEnclaveMLKEM: { _ in throw Refused() })
        } catch {
            throw XCTSkip("Secure Enclave key creation failed in this test process: \(error)")
        }
        XCTAssertFalse(try SecureEnclaveTagPQMaterial.decode(key.privateKeyMaterial).mlkemInEnclave)
        let pt = Data("fallback layout".utf8)
        let file = try Age.encrypt(plaintext: pt, to: [try TagRecipient(publicKey: key.publicKey)])
        let identity = try SecureEnclaveTagPQ.identity(privateKeyMaterial: key.privateKeyMaterial,
                                                       publicKey: key.publicKey, authenticationContext: nil)
        XCTAssertEqual(try Age.decrypt(ciphertext: file, identities: [identity]), pt)
    }

    /// An Enclave-layout key where Enclave ML-KEM can't be used (below iOS 26, restored
    /// vault): an identity whose ML-KEM half throws `requiresIOS26`, so the user is told why
    /// instead of the key vanishing, and which doesn't claim stanzas, so a YubiKey in the
    /// same file is still asked for (RC3 review fix 1). Testable on any OS.
    func test_unavailableEnclaveMLKEM_throwsRequiresIOS26_andDoesNotClaimStanzas() throws {
        let p256 = P256SoftwareKey.generate()
        let ek = try TagIdentity.softwareHybrid(seed: Self.random(32)).recipient.publicKey.prefix(AgePonyCore.MLKEM768.encapsulationKeySize)
        let id = try TagIdentity.hybrid(mlkem: UnavailableMLKEM(encapsulationKey: Data(ek)),
                                        p256PublicKey: p256.publicUncompressed, p256: p256)
        let pt = Data("needs 26".utf8)
        let file = try Age.encrypt(plaintext: pt, to: [id.recipient])
        let stanza = try XCTUnwrap(try Age.parseHeader(ciphertext: file).stanzas.first)
        XCTAssertFalse(id.matches(stanza: stanza))
        XCTAssertTrue(TagIdentity.probe(recipient: id.recipient).matches(stanza: stanza), "the inspector's probe still names it")
        XCTAssertThrowsError(try id.unwrap(stanza: stanza)) {
            XCTAssertEqual($0 as? SecureEnclaveKeyError, .requiresIOS26)
        }
        XCTAssertThrowsError(try Age.decrypt(ciphertext: file, identities: [id])) {
            XCTAssertEqual($0 as? SecureEnclaveKeyError, .requiresIOS26)
        }
        // The helper the below-26 hydration branch uses builds the same kind of identity.
        let blob = Self.random(324)
        let viaHelper = try SecureEnclaveTagPQ.unavailableIdentity(mlkemEncapsulationKey: Data(ek), p256Blob: blob,
                                                                   p256Point: p256.publicUncompressed,
                                                                   authenticationContext: nil)
        XCTAssertTrue(viaHelper.mlkem is UnavailableMLKEM)
        XCTAssertEqual(viaHelper.recipient, id.recipient)
        XCTAssertThrowsError(try viaHelper.unwrap(stanza: stanza)) {
            XCTAssertEqual($0 as? SecureEnclaveKeyError, .requiresIOS26)
        }
    }

    /// Keys made before 5.1.0 (seed in the vault) still decrypt, on both backends.
    func test_vaultSeedKey_stillDecrypts() throws {
        guard SecureEnclaveKeyAgreement.isAvailable else { throw XCTSkip("no Secure Enclave") }
        let key: (privateKeyMaterial: Data, publicKey: Data)
        do {
            key = try SecureEnclaveTagPQ.generate(protection: .noPrompt, mlkemInEnclave: false)
        } catch {
            throw XCTSkip("Secure Enclave key creation failed in this test process: \(error)")
        }
        XCTAssertFalse(try SecureEnclaveTagPQMaterial.decode(key.privateKeyMaterial).mlkemInEnclave)
        let pt = Data("5.0.1 layout".utf8)
        let file = try Age.encrypt(plaintext: pt, to: [try TagRecipient(publicKey: key.publicKey)])
        let identity = try SecureEnclaveTagPQ.identity(privateKeyMaterial: key.privateKeyMaterial,
                                                       publicKey: key.publicKey, authenticationContext: nil)
        XCTAssertEqual(try Age.decrypt(ciphertext: file, identities: [identity]), pt)
        let own = try HybridKEMBackend.withOwnCode {
            try SecureEnclaveTagPQ.identity(privateKeyMaterial: key.privateKeyMaterial,
                                            publicKey: key.publicKey, authenticationContext: nil)
        }
        XCTAssertEqual(try HybridKEMBackend.withOwnCode { try Age.decrypt(ciphertext: file, identities: [own]) }, pt)
    }

    /// What 5.0.1's hydration (VaultModels.toAgeIdentity at the 5.0.1 commit) does with the
    /// new layout: first 64 bytes as the ML-KEM seed, the rest as the P-256 blob. The key
    /// still matches its stanzas from public data, and decrypting fails for that key with an
    /// error. Nothing crashes, and a software key in the same file still opens it.
    func test_newLayout_readBy501Hydration_failsForThatKeyOnly() throws {
        let key = try makeEnclaveKey()
        let pt = Data("downgrade".utf8)
        let recipient = try TagRecipient(publicKey: key.publicKey)
        let soft = try HybridIdentity.generate()
        let file = try Age.encrypt(plaintext: pt, to: [recipient])
        let both = try Age.encrypt(plaintext: pt, to: [recipient, try soft.recipient()])
        try HybridKEMBackend.withOwnCode {
            let m = key.privateKeyMaterial
            let se = SecureEnclaveKeyAgreement(dataRepresentation: Data(m.dropFirst(64)))
            let fiveOhOne = try TagIdentity.hybrid(mlkemSeed: Data(m.prefix(64)),
                                                   p256PublicKey: Data(key.publicKey.suffix(P256Curve.uncompressedSize)),
                                                   p256: se)
            let stanza = try XCTUnwrap(try Age.parseHeader(ciphertext: file).stanzas.first)
            XCTAssertTrue(fiveOhOne.matches(stanza: stanza), "5.0.1 still recognises the stanza (tag uses the P-256 point)")
            XCTAssertThrowsError(try Age.decrypt(ciphertext: file, identities: [fiveOhOne])) {
                print("RC3-SE: 5.0.1 hydration of the new layout: decrypt throws \(type(of: $0)).\($0)")
                XCTAssertEqual($0 as? SecureEnclaveKeyError, .invalidKeyData)
            }
            // Software keys first, as the app orders them: the rest of the vault is unaffected.
            XCTAssertEqual(try Age.decrypt(ciphertext: both, identities: [soft, fiveOhOne]), pt)
        }
    }
    #endif
}
