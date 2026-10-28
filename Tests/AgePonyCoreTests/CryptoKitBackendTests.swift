//
//  CryptoKitBackendTests.swift
//  AgePonyCoreTests
//
//  5.1.0 RC3 (E8): AgePony runs the post-quantum KEMs in CryptoKit on iOS 26 /
//  macOS 26 and in its own code before that (HybridKEMBackend.swift). On a macOS 26
//  Mac, `swift test` reaches the CryptoKit path by default; the three subclasses below
//  run every CCTV vector and every HybridTests and TagRecipientTests case again with
//  the own code forced, so both backends are tested on one machine. On an older Mac
//  both runs use the own code.
//
//  The tests in CryptoKitBackendTests check that the switch really switches, that keys
//  and stanzas cross between the backends, and that AgePony's own checks still run in
//  front of CryptoKit (the RC3 spike showed CryptoKit alone opens five CCTV vectors age
//  must reject, and accepts bad-modulus and low-order keys until it encapsulates).
//

import XCTest
import Foundation
@testable import AgePonyCore

// MARK: - The existing suites, own code forced

final class CCTVTestkitOwnCodeTests: CCTVTestkitTests {
    override class var expectsCryptoKit: Bool { false }

    override func invokeTest() {
        HybridKEMBackend.withOwnCode {
            XCTAssertFalse(HybridKEMBackend.usesCryptoKit, "own code must be forced for \(type(of: self))")
            super.invokeTest()
        }
    }
}

final class HybridOwnCodeTests: HybridTests {
    override class var expectsCryptoKit: Bool { false }

    override func invokeTest() {
        HybridKEMBackend.withOwnCode {
            XCTAssertFalse(HybridKEMBackend.usesCryptoKit, "own code must be forced for \(type(of: self))")
            super.invokeTest()
        }
    }
}

final class TagRecipientOwnCodeTests: TagRecipientTests {
    override class var expectsCryptoKit: Bool { false }

    override func invokeTest() {
        HybridKEMBackend.withOwnCode {
            XCTAssertFalse(HybridKEMBackend.usesCryptoKit, "own code must be forced for \(type(of: self))")
            super.invokeTest()
        }
    }
}

// MARK: - Backend switch, interop, checks in front of CryptoKit

final class CryptoKitBackendTests: XCTestCase {

    let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })

    /// Whether this machine runs the CryptoKit path by default.
    static var cryptoKitExpected: Bool {
        #if (os(iOS) || os(macOS)) && compiler(>=6.2)
        if #available(iOS 26, macOS 26, *) { return true }
        #endif
        return false
    }

    /// Run `body` once per backend, labelled.
    func bothBackends(_ body: (String) throws -> Void) throws {
        try body(Self.cryptoKitExpected ? "CryptoKit" : "own code (no CryptoKit here)")
        try HybridKEMBackend.withOwnCode { try body("own code") }
    }

    func test_backendSwitch_andTestHook() throws {
        XCTAssertFalse(HybridKEMBackend.forceOwnCode, "the hook must start off")
        XCTAssertEqual(HybridKEMBackend.usesCryptoKit, Self.cryptoKitExpected)
        XCTAssertEqual(try HybridIdentity.generate().usesCryptoKit, Self.cryptoKitExpected)
        try HybridKEMBackend.withOwnCode {
            XCTAssertTrue(HybridKEMBackend.forceOwnCode)
            XCTAssertFalse(HybridKEMBackend.usesCryptoKit)
            XCTAssertFalse(try HybridIdentity.generate().usesCryptoKit)
            XCTAssertTrue(try HybridKEMBackend.mlkemKey(seed: AgePonyCore.MLKEM768.randomBytes(64)) is AgePonyCore.MLKEM768.KeyPair)
        }
        XCTAssertFalse(HybridKEMBackend.forceOwnCode, "withOwnCode must put the setting back")
        #if (os(iOS) || os(macOS)) && compiler(>=6.2)
        if #available(iOS 26, macOS 26, *) {
            XCTAssertTrue(try HybridKEMBackend.mlkemKey(seed: AgePonyCore.MLKEM768.randomBytes(64)) is CryptoKitMLKEMKey)
            XCTAssertTrue(try HybridKEMBackend.xwingKey(seed: AgePonyCore.MLKEM768.randomBytes(32)) is CryptoKitXWingKey)
        }
        #endif
        print("RC3 backend: \(Self.cryptoKitExpected ? "CryptoKit on this machine, own code when forced" : "own code only on this machine")")
    }

    // MARK: mlkem768x25519

    /// Same seed, same public key; every wrap/unwrap pairing across the backends works.
    func test_hybrid_crossBackendInterop() throws {
        for _ in 0..<4 {
            let seed = AgePonyCore.MLKEM768.randomBytes(HpkeMlkem768X25519.seedSize)
            let ck = try HybridIdentity(seed: seed)
            let own = try HybridKEMBackend.withOwnCode { try HybridIdentity(seed: seed) }
            XCTAssertEqual(ck.publicKey, own.publicKey)
            let recipient = try ck.recipient()

            let sealedDefault = try recipient.wrap(fileKey: fileKey)
            let sealedOwn = try HybridKEMBackend.withOwnCode { try recipient.wrap(fileKey: fileKey) }
            for (label, stanza) in [("default seal", sealedDefault), ("own seal", sealedOwn)] {
                XCTAssertEqual(try ck.unwrap(stanza: stanza), fileKey, "\(label), default open")
                XCTAssertEqual(try own.unwrap(stanza: stanza), fileKey, "\(label), own open")
                XCTAssertEqual(try Stanza.base64Decode(stanza.args[0]).count, HpkeMlkem768X25519.encSize)
                XCTAssertEqual(stanza.body.count, 32)
            }
        }
    }

    /// The stanza checks age requires stay AgePony's in front of CryptoKit. The CCTV
    /// vectors cover these too; these name them.
    func test_hybrid_stanzaChecksRunBeforeEitherBackend() throws {
        try bothBackends { label in
            let id = try HybridIdentity.generate()
            let good = try id.recipient().wrap(fileKey: fileKey)
            XCTAssertEqual(try id.unwrap(stanza: good), fileKey, label)

            // hybrid_extra_argument: CryptoKit alone opens it.
            let extraArg = Stanza(type: good.type, args: good.args + ["AAAA"], body: good.body)
            XCTAssertNil(try id.unwrap(stanza: extraArg), "\(label): extra argument")
            // hybrid_uppercase: CryptoKit doesn't see the type.
            let upper = Stanza(type: good.type.uppercased(), args: good.args, body: good.body)
            XCTAssertNil(try id.unwrap(stanza: upper), "\(label): stanza type case")
            // hybrid_long_file_key: a 25-byte file key sealed to the same key gives a 41-byte
            // body, refused on the body size (32) before any open.
            let (enc, body) = try HpkeMlkem768X25519.seal(publicKey: id.publicKey,
                                                          info: Data("age-encryption.org/mlkem768x25519".utf8),
                                                          plaintext: Data(repeating: 7, count: 25))
            let longBody = Stanza(type: good.type, args: [Stanza.base64NoPad(enc)], body: body)
            XCTAssertEqual(longBody.body.count, 41)
            XCTAssertNil(try id.unwrap(stanza: longBody), "\(label): 41-byte body (25-byte file key), refused on body size")
            // hybrid_low_order: ct_T replaced by the all-zero point.
            var lowOrder = try Stanza.base64Decode(good.args[0])
            lowOrder.replaceSubrange((lowOrder.count - 32)..<lowOrder.count, with: Data(repeating: 0, count: 32))
            let lowOrderStanza = Stanza(type: good.type, args: [Stanza.base64NoPad(lowOrder)], body: good.body)
            XCTAssertNil(try id.unwrap(stanza: lowOrderStanza), "\(label): low-order X25519 share")
            // Short enc.
            let short = Stanza(type: good.type, args: [Stanza.base64NoPad(Data(lowOrder.prefix(1119)))], body: good.body)
            XCTAssertNil(try id.unwrap(stanza: short), "\(label): short enc")
        }
    }

    /// AgePony's low-order check runs before CryptoKit opens: on an all-zero or
    /// order-4 `ct_T` the CryptoKit key throws `HybridKEMError.lowOrderPoint`, which
    /// CryptoKit itself never throws (its own refusal is a CryptoKit error). RC3 review fix 6.
    func test_hybrid_lowOrderShare_refusedByAgePonyBeforeCryptoKit() throws {
        #if (os(iOS) || os(macOS)) && compiler(>=6.2)
        guard #available(iOS 26, macOS 26, *) else { throw XCTSkip("needs macOS 26 / iOS 26") }
        let seed = AgePonyCore.MLKEM768.randomBytes(HpkeMlkem768X25519.seedSize)
        let key = try CryptoKitXWingKey(seed: seed)
        let good = try HybridIdentity(seed: seed).recipient().wrap(fileKey: fileKey)
        let enc = try Stanza.base64Decode(good.args[0])
        let info = Data("age-encryption.org/mlkem768x25519".utf8)
        XCTAssertEqual(try key.open(enc: enc, info: info, ciphertext: good.body), fileKey)
        for (what, point) in [("all-zero", Data(repeating: 0, count: 32)),
                              ("u = 1", Data([1] + [UInt8](repeating: 0, count: 31)))] {
            let bad = Data(enc.prefix(enc.count - 32)) + point
            XCTAssertThrowsError(try key.open(enc: bad, info: info, ciphertext: good.body), what) {
                XCTAssertEqual($0 as? HybridKEMError, .lowOrderPoint, "\(what): \($0)")
            }
        }
        #else
        throw XCTSkip("needs Xcode 26")
        #endif
    }

    /// Encrypting refuses the same keys with the same errors on both backends.
    func test_hybrid_encryptSideChecks_sameErrorsOnBothBackends() throws {
        let good = try HybridIdentity.generate().publicKey
        var badEK = Data(good.prefix(AgePonyCore.MLKEM768.encapsulationKeySize))
        badEK[badEK.startIndex] = 0xFF
        badEK[badEK.startIndex + 1] |= 0x0F                 // first coefficient 4095 >= q
        let badModulus = badEK + Data([9] + [UInt8](repeating: 0, count: 31))
        let lowOrder = Data(good.prefix(AgePonyCore.MLKEM768.encapsulationKeySize)) + Data(repeating: 0, count: 32)

        for (what, key) in [("bad modulus", badModulus), ("low-order X25519 half", lowOrder)] {
            var errors: [String] = []
            try bothBackends { label in
                let r = try HybridRecipient(publicKey: key)
                XCTAssertThrowsError(try r.wrap(fileKey: fileKey), "\(label): \(what)") { errors.append(String(describing: $0)) }
            }
            XCTAssertEqual(errors.count, 2)
            XCTAssertEqual(Set(errors).count, 1, "\(what): both backends must throw the same error, got \(errors)")
        }
        XCTAssertThrowsError(try HybridRecipient(publicKey: badModulus).wrap(fileKey: fileKey)) {
            XCTAssertEqual($0 as? MLKEMError, .malformedEncapsulationKey)
        }
    }

    // MARK: mlkem768p256tag

    func test_tag_crossBackendInterop() throws {
        for _ in 0..<4 {
            let seed = AgePonyCore.MLKEM768.randomBytes(32)
            let ck = try TagIdentity.softwareHybrid(seed: seed)
            let own = try HybridKEMBackend.withOwnCode { try TagIdentity.softwareHybrid(seed: seed) }
            XCTAssertEqual(ck.recipient, own.recipient)
            let sealedDefault = try ck.recipient.wrap(fileKey: fileKey)
            let sealedOwn = try HybridKEMBackend.withOwnCode { try own.recipient.wrap(fileKey: fileKey) }
            for (label, stanza) in [("default seal", sealedDefault), ("own seal", sealedOwn)] {
                XCTAssertEqual(try ck.unwrap(stanza: stanza), fileKey, "\(label), default open")
                XCTAssertEqual(try own.unwrap(stanza: stanza), fileKey, "\(label), own open")
            }
        }
    }

    func test_tag_badModulusRecipient_refusedOnBothBackends() throws {
        var raw = Data(try TagRecipient(ageRecipient: TagRecipientTests.tagtestHybrid).publicKey)
        raw[0] = 0xFF; raw[1] = 0x0F
        let stored = try TagRecipient(publicKey: raw)
        try bothBackends { label in
            XCTAssertThrowsError(try stored.wrap(fileKey: fileKey), label) {
                XCTAssertEqual($0 as? MLKEMError, .malformedEncapsulationKey, label)
            }
        }
    }

    // MARK: No own-code fallback: CryptoKit failures map to the own code's outcomes

    /// An ML-KEM half that refuses, as CryptoKit would if it ever threw on decapsulation.
    struct RefusingMLKEM: MLKEMDecapsulation {
        let encapsulationKey: Data
        let error: Error
        func decapsulate(ciphertext: Data) throws -> Data { throw error }
    }
    struct PromptCancelled: Error, Equatable {}

    /// A software decapsulation refusal is "not for me" (nil), the result the own code
    /// reaches through implicit rejection; any other error (a hardware prompt) still
    /// propagates. Nothing retries through the own code.
    func test_tag_cryptoKitDecapsulationRefusal_isNotForMe() throws {
        let real = try TagIdentity.softwareHybrid(seed: AgePonyCore.MLKEM768.randomBytes(32))
        let p256 = P256SoftwareKey.generate()
        let ek = Data(real.recipient.publicKey.prefix(AgePonyCore.MLKEM768.encapsulationKeySize))
        let refused = try TagIdentity.hybrid(mlkem: RefusingMLKEM(encapsulationKey: ek, error: MLKEMDecapsulationRefused()),
                                             p256PublicKey: p256.publicUncompressed, p256: p256)
        let stanza = try refused.recipient.wrap(fileKey: fileKey)
        XCTAssertNil(try refused.unwrap(stanza: stanza))
        let cancelled = try TagIdentity.hybrid(mlkem: RefusingMLKEM(encapsulationKey: ek, error: PromptCancelled()),
                                               p256PublicKey: p256.publicUncompressed, p256: p256)
        XCTAssertThrowsError(try cancelled.unwrap(stanza: stanza)) {
            XCTAssertEqual($0 as? PromptCancelled, PromptCancelled())
        }
    }

    /// CryptoKit errors after AgePony's checks become the own code's errors.
    func test_cryptoKitErrorMapping() {
        struct SomeHPKEError: Error {}
        XCTAssertEqual(HybridKEMBackend.mapEncapsulationError(SomeHPKEError()) as? MLKEMError, .malformedEncapsulationKey)
        XCTAssertEqual(HybridKEMBackend.mapEncapsulationError(MLKEMError.invalidEncapsulationKeyLength) as? MLKEMError,
                       .invalidEncapsulationKeyLength)
        XCTAssertEqual(HpkeMlkem768X25519.mapSealError(SomeHPKEError()) as? HybridKEMError, .invalidPublicKeyLength)
        XCTAssertEqual(HpkeMlkem768X25519.mapSealError(HybridKEMError.lowOrderPoint) as? HybridKEMError, .lowOrderPoint)
    }

    /// A CryptoKit ML-KEM key from a vault seed answers exactly as the own key does,
    /// implicit rejection included (spike S3, through the Sources type).
    func test_mlkemKeyFromSeed_matchesOwnCode() throws {
        for _ in 0..<4 {
            let seed = AgePonyCore.MLKEM768.randomBytes(64)
            let key = try HybridKEMBackend.mlkemKey(seed: seed)
            let own = try AgePonyCore.MLKEM768.keyPairFromSeed(seed)
            XCTAssertEqual(key.encapsulationKey, own.encapsulationKey)
            let (ss, ct) = try HybridKEMBackend.mlkemEncapsulate(encapsulationKey: own.encapsulationKey, message: nil)
            XCTAssertEqual(try key.decapsulate(ciphertext: ct), ss)
            XCTAssertEqual(try own.decapsulate(ciphertext: ct), ss)
            var bad = ct
            bad[bad.startIndex] ^= 1
            XCTAssertEqual(try key.decapsulate(ciphertext: bad), try own.decapsulate(ciphertext: bad))
        }
        XCTAssertThrowsError(try HybridKEMBackend.mlkemKey(seed: Data(count: 63))) {
            XCTAssertEqual($0 as? MLKEMError, .invalidSeedLength)
        }
    }
}
