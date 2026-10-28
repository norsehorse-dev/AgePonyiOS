//
//  TagRecipientTests.swift
//  AgePonyCoreTests
//
//  age 1.3 tag recipients (p256tag, mlkem768p256tag). The two tagtest recipients are
//  those of age's own test plugin (filippo.io/age age-plugin-tagtest), derived with HPKE
//  DeriveKeyPair from the ikm "age-plugin-tagtest", and the same strings Android's
//  TagRecipientTest pins. Matching them proves KEM key derivation, point encoding and
//  Bech32 layout agree with age 1.3 and with Android.
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

// Not final: TagRecipientOwnCodeTests (CryptoKitBackendTests.swift) runs every test here
// again with the own code forced, so on macOS 26 both backends are covered (5.1.0 RC3).
class TagRecipientTests: XCTestCase {

    /// The post-quantum backend this class's tests must run on: CryptoKit on macOS 26 /
    /// iOS 26, own code before; the OwnCode subclasses override it (RC3 review fix 5).
    class var expectsCryptoKit: Bool { CryptoKitBackendTests.cryptoKitExpected }

    override func invokeTest() {
        XCTAssertEqual(HybridKEMBackend.usesCryptoKit, type(of: self).expectsCryptoKit,
                       "post-quantum backend for \(type(of: self))")
        super.invokeTest()
    }

    static let tagtestClassic = "age1tag1qwe0kafsjrar4txm6heqnhpfuggzr0gvznz7fvygxrlq90u5mq2pysxtw6h"
    static let tagtestHybrid = "age1tagpq14h4z7cks9sxftfc8tq4xektt4854ur9rv76tvujdvtzk2fmyywkvh9z2emz3x4epvhz7qdt2v7uksyyq2cdzf3k04ny0g5sc3u4heqh3r9v4cnwhfjw0a2azpgmnk9xk02wvywt5szcq6q3jvwsjxvkn3tsk52vqjczdcvc398ym4j6cvqas4w99gkgt7ur3fmt4g873phr23tgxw3f7wgsz9zxz7m8cp27vpq3h5vc8nssjemtr2etmtmqkg4fzn2u9x9zvtysuya5yrytgx482ftx9864h8a6pprarxd3d0qe8nw2at5ekg3tsahtef7kawasxjamyckw2ans6v933vuypcfrra32f89r2v72mka9hhc55s49xe2khfsq7w9r2zynuzfx4fg6v7jjncsc87rw2yy8qp8hr27edus6zw5xd6m3hax2nxhl2dys9792z3wp5c034sfkrxe86guj7pfdh7sytzrufl9euhuhyf9w6c7z2nwf7v5v8f2s4gplgvfx4jj4le22k2qn242qkqkcwx7llfyrct7jm2wcv0ytypeh6h93ezgtd7q6zr428qze3dec5jxlc5xxjetyephp42fljft3s02p0570kjwyfeyjcnks2vglkvyus5g9l4z6m0gf8wu22ygfm40028txwjlxvvgnn7c36z783c6tmc9k5nef8nucj6u3ustff5vhtnzhnscsvsz79wzrkv3sujtntx4wezucy6lp49flmnyydn3khk2xsesw0ekn4u44nzqw2g2rjyrrl7crshlzttgpe0jvqycjzp9kmtz23t3yu0w9j4n344nnrf88k2jqqfpjxte38pcn0epr879pqsuvajxrkmsas89pvfrzwcewneujn08guj5pvvrtn5hzzg2y6u4wwjqqxx4x8w65yc4dchf750dft8kgcttt2f6j0j5v8s7tkaua78tte7artdfar544vl0rau79h95mc4ghp887z82s6rq93txpkvan86n963kagqkldngnkjcn28zdrh38vdxj002zqs9mx7zjvg3ynzdfhfakkynt9fyqpaxpsdrsqrycuhw5ykwgjz6wldef7xtu6p689234hstxe7v8e5422f2dy8ystn57z3fvy9yfrm4t3lye6ejk5n6x8zqexmql7lx965xcxuuy38xzyt8j9qprnwgfqgx54l4tnjdpzdde6xgmwtnpkfwvyr7rkgnavvjn6a3e56wtvjx3evmhjjxvukpq5zqrj0s4sntkz3yeszs5dty8q0q6m7dgp6mjpvaer0c4343g72eycfqzkjupeaemh0n8e935hqs8fh3jgk7fzyxctzuqlx6d2q9jaf8r9wu4sjxj5w6ppw7m9c3hxrzpcv2uek3kxnndgf2hd99q9v2ux8pjkv29ntslvnvhy09dvcy9578rt89gf4cj4cu79zjxtlj3dpct6rjme02zj3qspsade96njkkufu9zuq2lk3qwvddpxjkqm2hnpqwck54zug7ctvkgvk325lwkg4q5rf73zkgys5e9y8jqc96ntdyl4r78lgtw4k5uljk5ttf46s3gc0rq0jwmddnxt875twwq92505zh3zkse5ag2dhjjxyfzkn7xv3j0kv9r3jzpvgep8fq6z8mar509u4fvnhvthp2ah0r45lsyq0mm6fwkcs30v8k9wzvgt6uvcty6qsjvarjs3htym69zu43m4jd3k4tllrr8c05v6p6spuhup4hkk2p9fp9lxafe3pntcn4nk83gzhjjpcjwyg7jcyz5uancu0fakgz27up7ymzp2xv3sqyqewkkqynskw9qkvysrncxj0cy7dt6q8dsseuwmc2urfmcvkykf82wfa54t85hqx8gywhmhzunm2x0d66a4pwl0xl78fhkces5dpq8pfnp35m5a3u8vdam64zx5s5x9cmnrx3zr066f4f8hlecqnq2fd5quw79ljg3q5nvs6ggmm4gkc"

    let ikm = Data("age-plugin-tagtest".utf8)
    let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })

    func tagtestClassicIdentity() throws -> TagIdentity {
        try TagIdentity.softwareClassic(scalar: try HpkeP256.dhkemDeriveKeyPair(ikm: ikm))
    }
    func tagtestHybridIdentity() throws -> TagIdentity {
        try TagIdentity.softwareHybrid(seed: HpkeP256.hybridDeriveSeed(ikm: ikm))
    }

    /// Counts ECDH calls and can be made to fail, standing in for a Secure Enclave key.
    final class CountingKey: P256KeyAgreement {
        let inner = P256SoftwareKey.generate()
        var calls = 0
        var failure: Error?
        func sharedX(peerUncompressed: Data) throws -> Data {
            calls += 1
            if let failure { throw failure }
            return try inner.sharedX(peerUncompressed: peerUncompressed)
        }
    }
    struct PromptCancelled: Error, Equatable {}

    func test_classicDerivation_matchesAgeTagtest() throws {
        XCTAssertEqual(try tagtestClassicIdentity().recipient.toBech32(), Self.tagtestClassic)
    }

    func test_hybridDerivation_matchesAgeTagtest() throws {
        XCTAssertEqual(try tagtestHybridIdentity().recipient.toBech32(), Self.tagtestHybrid)
    }

    func test_parsesBothEncodings_andRoundTripsBech32() throws {
        let c = try TagRecipient(ageRecipient: Self.tagtestClassic)
        XCTAssertFalse(c.isHybrid)
        XCTAssertEqual(c.toBech32(), Self.tagtestClassic)
        XCTAssertEqual(c.labels, [])
        let h = try TagRecipient(ageRecipient: Self.tagtestHybrid)
        XCTAssertTrue(h.isHybrid)
        XCTAssertEqual(h.toBech32(), Self.tagtestHybrid)
        XCTAssertEqual(h.labels, [postQuantumLabel])
        XCTAssertTrue(TagRecipient.isTagRecipient(Self.tagtestClassic))
        XCTAssertTrue(TagRecipient.isTagRecipient(Self.tagtestHybrid.uppercased()))
        XCTAssertFalse(TagRecipient.isTagRecipient("age1qqq"))
    }

    func test_rejectsWrongHRP_badPoints_andHybridSEC1() throws {
        XCTAssertThrowsError(try TagRecipient(ageRecipient: "age1yubikey1qtlu4dlqkg0tg6nswpgmhw34vpszdeaffzp4f6fgpemlvxqcvzv35hnavmu"))
        XCTAssertThrowsError(try TagRecipient(publicKey: Data(repeating: 5, count: 33)))
        XCTAssertThrowsError(try TagRecipient(publicKey: Data(repeating: 2, count: 40)))
        var hybridForm = P256SoftwareKey.generate().publicUncompressed
        hybridForm[hybridForm.startIndex] = 0x06
        XCTAssertThrowsError(try P256Curve.decode(hybridForm))
    }

    func test_malformedMLKEMKey_isRefused() throws {
        var raw = Data(try TagRecipient(ageRecipient: Self.tagtestHybrid).publicKey)
        raw[0] = 0xFF; raw[1] = 0x0F // first coefficient 0xFFF >= q
        let bech = Bech32.encodeBytes(hrp: "age1tagpq", bytes: Array(raw))
        XCTAssertThrowsError(try TagRecipient(ageRecipient: bech)) {
            XCTAssertEqual($0 as? TagRecipientError, .malformedMLKEMKey)
        }
        // Even when stored without the Bech32 check, encrypting to it fails.
        let stored = try TagRecipient(publicKey: raw)
        XCTAssertThrowsError(try stored.wrap(fileKey: fileKey))
    }

    func test_classicWrapUnwrap() throws {
        let id = try TagIdentity.softwareClassic(scalar: try HpkeP256.dhkemDeriveKeyPair(ikm: Data(repeating: 7, count: 8)))
        let s = try id.recipient.wrap(fileKey: fileKey)
        XCTAssertEqual(s.type, "p256tag")
        XCTAssertEqual(s.args.count, 2)
        XCTAssertEqual(s.body.count, 32)
        XCTAssertTrue(id.matches(stanza: s))
        XCTAssertEqual(try id.unwrap(stanza: s), fileKey)
    }

    func test_hybridWrapUnwrap() throws {
        let id = try TagIdentity.softwareHybrid(seed: Data((0..<32).map { UInt8($0) }))
        let s = try id.recipient.wrap(fileKey: fileKey)
        XCTAssertEqual(s.type, "mlkem768p256tag")
        XCTAssertEqual(try Stanza.base64Decode(s.args[1]).count, 1153)
        XCTAssertEqual(try id.unwrap(stanza: s), fileKey)
    }

    func test_wrongIdentity_neverTouchesItsKey() throws {
        let mine = try tagtestClassicIdentity()
        let key = CountingKey()
        let theirs = try TagIdentity.classic(publicKey: key.inner.publicUncompressed, p256: key)
        let s = try mine.recipient.wrap(fileKey: fileKey)
        XCTAssertFalse(theirs.matches(stanza: s))
        XCTAssertNil(try theirs.unwrap(stanza: s))
        XCTAssertEqual(key.calls, 0, "a stanza for another key must be rejected on the tag, before ECDH")
    }

    func test_fullFileRoundTrip() throws {
        let pt = Data("hardware bound".utf8)
        let h = try tagtestHybridIdentity()
        XCTAssertEqual(try Age.decrypt(ciphertext: try Age.encrypt(plaintext: pt, to: [h.recipient]), identities: [h]), pt)
        let c = try tagtestClassicIdentity()
        let x = X25519Identity.generate()
        let ct = try Age.encrypt(plaintext: pt, to: [c.recipient, try X25519Recipient(ageRecipient: x.ageRecipient)])
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [c]), pt)
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [x]), pt)
    }

    func test_hybrid_refusesMixingWithClassic() throws {
        let h = try tagtestHybridIdentity().recipient
        let x = try X25519Recipient(ageRecipient: X25519Identity.generate().ageRecipient)
        XCTAssertThrowsError(try Age.encrypt(plaintext: Data("x".utf8), to: [h, x]))
        XCTAssertThrowsError(try Age.encrypt(plaintext: Data("x".utf8), to: [h, try tagtestClassicIdentity().recipient]))
        XCTAssertNoThrow(try Age.encrypt(plaintext: Data("x".utf8), to: [h, try HybridIdentity.generate().recipient()]))
    }

    func test_failingHardwareKey_doesNotBlockSoftwareRecipient() throws {
        let key = CountingKey()
        key.failure = PromptCancelled()
        let broken = try TagIdentity.classic(publicKey: key.inner.publicUncompressed, p256: key)
        let backup = X25519Identity.generate()
        let pt = Data("two recipients".utf8)
        // Hardware stanza first in the header, as when the user lists it first.
        let ct = try Age.encrypt(plaintext: pt, to: [broken.recipient, try X25519Recipient(ageRecipient: backup.ageRecipient)])
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [broken, backup]), pt)
        XCTAssertEqual(key.calls, 0, "the software key opens it first")
        // With only the broken key, its own error surfaces rather than no-matching-identity.
        XCTAssertThrowsError(try Age.decrypt(ciphertext: ct, identities: [broken])) {
            XCTAssertEqual($0 as? PromptCancelled, PromptCancelled())
        }
        XCTAssertTrue(try Age.canDecrypt(ciphertext: ct, identities: [broken]))
    }

    func test_knownAnswer_fixedRandomness_isDeterministic() throws {
        let c = try tagtestClassicIdentity()
        let eph = try HpkeP256.dhkemDeriveKeyPair(ikm: Data("ephemeral".utf8))
        let a = try c.recipient.wrap(fileKey: Data(repeating: 1, count: 16), testRandom: eph)
        let b = try c.recipient.wrap(fileKey: Data(repeating: 1, count: 16), testRandom: eph)
        XCTAssertEqual(a, b)
        XCTAssertEqual(try c.unwrap(stanza: a), Data(repeating: 1, count: 16))
    }
}

// MARK: - The app's Secure Enclave storage layout (Phase 3)

extension TagRecipientTests {
    /// The app keeps a hybrid hardware key as a random 64-byte ML-KEM seed plus an
    /// Enclave P-256 key. Same path with a software P-256 key standing in.
    func test_hybridFromSeparateHalves_roundTrips_andStaysOnItsOwnStanzas() throws {
        let mlkemSeed = AgePonyCore.MLKEM768.randomBytes(64)
        let p256 = P256SoftwareKey.generate()
        let id = try TagIdentity.hybrid(mlkemSeed: mlkemSeed, p256PublicKey: p256.publicUncompressed, p256: p256)
        XCTAssertEqual(id.recipient.publicKey.count, HpkeP256.hybridPublicKeySize)
        // Rebuilt from storage: same recipient.
        let again = try TagIdentity.hybrid(mlkemSeed: mlkemSeed, p256PublicKey: id.recipient.p256Part, p256: p256)
        XCTAssertEqual(again.recipient, id.recipient)
        XCTAssertTrue(id.recipient.toBech32().hasPrefix("age1tagpq1"))

        let pt = Data("enclave".utf8)
        let ct = try Age.encrypt(plaintext: pt, to: [try TagRecipient(ageRecipient: id.recipient.toBech32())])
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [again]), pt)

        // A classic identity on the same P-256 key doesn't claim the hybrid stanza.
        let classic = try TagIdentity.classic(publicKey: p256.publicUncompressed, p256: p256)
        XCTAssertFalse(try Age.parseHeader(ciphertext: ct).stanzas.contains { classic.matches(stanza: $0) })
        XCTAssertTrue(classic.recipient.toBech32().hasPrefix("age1tag1"))
    }
}
