//
//  YubiKeyPivTests.swift
//  AgePonyCoreTests
//
//  YubiKey PIV decrypt against a simulated card. The key and certificate are the ones
//  Android's YubiKeyPivTest uses, so both platforms read the same slot the same way.
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

/// A PIV card simulator: one P-256 key in retired slot 82, PIN 123456, chained GET DATA.
final class FakePivCard: PivCard {
    let key: P256SoftwareKey
    let certDER: Data
    let serial: UInt32
    var pinVerified = false
    var ecdhCalls = 0
    var pinTries = 3
    private var pending = Data()

    init(key: P256SoftwareKey, certDER: Data, serial: UInt32 = 12_345_678) {
        self.key = key; self.certDER = certDER; self.serial = serial
    }

    func transmit(_ apdu: Data) throws -> Data {
        let a = Array(apdu)
        switch a[1] {
        case 0xA4: return sw(0x9000)
        case 0xF8: return Data([UInt8(serial >> 24), UInt8(serial >> 16 & 0xFF), UInt8(serial >> 8 & 0xFF), UInt8(serial & 0xFF)]) + sw(0x9000)
        case 0x20:
            let pin = String(decoding: a[5..<13].filter { $0 != 0xFF }, as: UTF8.self)
            if pin == "123456" { pinVerified = true; pinTries = 3; return sw(0x9000) }
            pinTries -= 1
            return sw(0x63C0 | UInt16(pinTries))
        case 0xCB:
            pending = Tlv.encode(tag: 0x53, value: Tlv.encode(tag: 0x70, value: certDER)
                + Tlv.encode(tag: 0x71, value: Data([0])) + Tlv.encode(tag: 0xFE, value: Data()))
            return chunk()
        case 0xC0: return chunk()
        case 0x87:
            guard pinVerified else { return sw(0x6982) }
            ecdhCalls += 1
            let body = Data(a[5..<(5 + Int(a[4]))])
            let template = try Tlv.find(body, tag: 0x7C)!
            let peer = try Tlv.find(template, tag: 0x85)!
            return Tlv.encode(tag: 0x7C, value: Tlv.encode(tag: 0x82, value: try key.sharedX(peerUncompressed: peer))) + sw(0x9000)
        default: return sw(0x6D00)
        }
    }

    private func chunk() -> Data {
        let n = min(200, pending.count)
        let out = pending.prefix(n)
        pending = Data(pending.dropFirst(n))
        return Data(out) + (pending.isEmpty ? sw(0x9000) : sw(0x6100 | UInt16(min(pending.count, 255))))
    }

    private func sw(_ v: UInt16) -> Data { Data([UInt8(v >> 8), UInt8(v & 0xFF)]) }
}

/// Talks to the card the way the app will: ECDH, and on "PIN required" verify then retry.
struct CardKeyAgreement: P256KeyAgreement {
    let card: FakePivCard
    let pin: String?
    func sharedX(peerUncompressed: Data) throws -> Data {
        try Piv.select(card)
        do {
            return try Piv.ecdh(card, slot: 0x82, peerUncompressed: peerUncompressed)
        } catch PivError.pinRequired {
            guard let pin else { throw PivError.pinRequired }
            try Piv.verifyPIN(card, pin: pin)
            return try Piv.ecdh(card, slot: 0x82, peerUncompressed: peerUncompressed)
        }
    }
}

final class YubiKeyPivTests: XCTestCase {

    static func hexData(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return d
    }

    let key = try! P256SoftwareKey(scalar: hexData("60cda4181bd5744a6c0b3ecadc89f7ca528c4dea68c8643549c163e93fd2f587"))
    let certDER = Data(base64Encoded: "MIIBxzCCAW2gAwIBAgIUDyEblkoM2MCTYtnPpEzaivk20yIwCgYIKoZIzj0EAwIwOTEaMBgGA1UEAwwRYWdlIGlkZW50aXR5IFRFU1QxGzAZBgNVBAoMEmFnZS1wbHVnaW4teXViaWtleTAeFw0yNjA5MjMwMzAzMDFaFw0zNjA5MjAwMzAzMDFaMDkxGjAYBgNVBAMMEWFnZSBpZGVudGl0eSBURVNUMRswGQYDVQQKDBJhZ2UtcGx1Z2luLXl1YmlrZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQJPmrO6hFIw1SMqKOwZlg5+E2FNTBK7AdpaiUCpv3Gv/NLuvgMa+jCYTESnvtcUb7UfX1TCr6+HJlZzEgqvP1bo1MwUTAdBgNVHQ4EFgQUMGDL+y60S+eoXlwcltyFx5GlD5gwHwYDVR0jBBgwFoAUMGDL+y60S+eoXlwcltyFx5GlD5gwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBDJsrW5Difydm8s6SQEvpqskTc/u4aIWV6wEL/uwwYAwIhAKOAQ13PEjt/kV5Mc2knLK6aTLyE1L4IsEH0kiZswp2E")!

    var compressedPub: Data { try! P256Curve.compressed(key.publicUncompressed) }
    var stub: YubiKeyStub { try! YubiKeyStub(serial: 12_345_678, slot: 0x82, tag: YubiKeyStub.staticTag(compressedPublicKey: compressedPub)) }

    func test_readsPublicKeyAndSerial_throughChaining() throws {
        let card = FakePivCard(key: key, certDER: certDER)
        try Piv.select(card)
        XCTAssertEqual(try Piv.serial(card), 12_345_678)
        XCTAssertEqual(try Piv.readPublicKey(card, slot: 0x82), compressedPub)
    }

    func test_stubRoundTrip() throws {
        let s = stub.encode()
        XCTAssertTrue(s.hasPrefix("AGE-PLUGIN-YUBIKEY-1"), s)
        XCTAssertTrue(YubiKeyStub.isStub(s))
        XCTAssertEqual(try YubiKeyStub(parsing: s), stub)
        XCTAssertEqual(try YubiKeyStub(parsing: s.lowercased()), stub)
        XCTAssertTrue(stub.matchesKey(compressedPublicKey: compressedPub))
        XCTAssertThrowsError(try YubiKeyStub(serial: 1, slot: 0x9A, tag: Data(count: 4)))
    }

    func test_decryptsPivP256AndP256Tag_withOneECDHEach() throws {
        let card = FakePivCard(key: key, certDER: certDER)
        let id = try YubiKeyIdentity(stub: stub, publicKey: compressedPub, keyAgreement: CardKeyAgreement(card: card, pin: "123456"))
        let pt = Data("for the yubikey".utf8)
        let legacy = try Age.encrypt(plaintext: pt, to: [try P256Recipient(compressedPublicKey: compressedPub)])
        XCTAssertEqual(try Age.decrypt(ciphertext: legacy, identities: [id]), pt)
        let tagged = try Age.encrypt(plaintext: pt, to: [try TagRecipient(publicKey: compressedPub)])
        XCTAssertEqual(try Age.decrypt(ciphertext: tagged, identities: [id]), pt)
        XCTAssertEqual(card.ecdhCalls, 2)
    }

    func test_softwareRecipientWins_withoutTouchingTheCard() throws {
        let card = FakePivCard(key: key, certDER: certDER)
        let id = try YubiKeyIdentity(stub: stub, publicKey: compressedPub, keyAgreement: CardKeyAgreement(card: card, pin: nil))
        let x = X25519Identity.generate()
        let ct = try Age.encrypt(plaintext: Data("x".utf8), to: [
            try P256Recipient(compressedPublicKey: compressedPub),
            try X25519Recipient(ageRecipient: x.ageRecipient),
        ])
        _ = try Age.decrypt(ciphertext: ct, identities: [id, x])
        XCTAssertEqual(card.ecdhCalls, 0)
        XCTAssertTrue(try Age.canDecryptStream(ciphertext: InputStream(data: ct), identities: [id]))
        XCTAssertEqual(card.ecdhCalls, 0)
    }

    func test_wrongPIN_reportsTriesLeft() throws {
        let card = FakePivCard(key: key, certDER: certDER)
        try Piv.select(card)
        XCTAssertThrowsError(try Piv.verifyPIN(card, pin: "000000")) {
            XCTAssertEqual($0 as? PivError, .wrongPIN(retriesLeft: 2))
        }
        XCTAssertThrowsError(try Piv.ecdh(card, slot: 0x82, peerUncompressed: P256SoftwareKey.generate().publicUncompressed)) {
            XCTAssertEqual($0 as? PivError, .pinRequired)
        }
        XCTAssertFalse(card.pinVerified)
    }

    func test_recordedKeyAgreement_decryptsAfterAsyncExchange() throws {
        // The app's flow: list the points the card must ECDH with, do the NFC exchange
        // (async, here direct), then decrypt with the recorded results.
        let pt = Data("two-phase".utf8)
        let ct = try Age.encrypt(plaintext: pt, to: [try TagRecipient(publicKey: compressedPub)])
        let probe = try YubiKeyIdentity(stub: stub, publicKey: compressedPub, keyAgreement: RecordedKeyAgreement(results: [:]))
        let points = probe.peerPoints(in: try Age.parseHeader(ciphertext: ct).stanzas)
        XCTAssertEqual(points.count, 1)
        var results: [Data: Data] = [:]
        for p in points { results[p] = try key.sharedX(peerUncompressed: p) }
        let id = try YubiKeyIdentity(stub: stub, publicKey: compressedPub, keyAgreement: RecordedKeyAgreement(results: results))
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [id]), pt)
    }

    func test_hostileCard_isBounded() throws {
        final class Chatty: PivCard {
            func transmit(_ apdu: Data) throws -> Data { Data(repeating: 0xAB, count: 250) + Data([0x61, 0xFF]) }
        }
        XCTAssertThrowsError(try Piv.select(Chatty()))
        XCTAssertThrowsError(try Tlv.find(Data([0x53, 0x82, 0x01]), tag: 0x53))
        XCTAssertThrowsError(try Tlv.find(Data([0x53, 0x05, 0x01]), tag: 0x53))
        XCTAssertNil(try X509P256.publicKey(fromCertificate: Data([0x30, 0x03, 0x02, 0x01, 0x01])))
    }

    func test_certificateParser_refusesOtherCurves() throws {
        // Swap the prime256v1 OID for secp256k1 (1.3.132.0.10): must not be read as P-256.
        var der = Array(certDER)
        let p256 = X509P256.oidPrime256v1
        let i = try XCTUnwrap((0...(der.count - p256.count)).first { Array(der[$0..<($0 + p256.count)]) == p256 })
        der.replaceSubrange((i - 2)..<(i + p256.count), with: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A, 0x05, 0x00, 0x05])
        XCTAssertNil(try? X509P256.publicKey(fromCertificate: Data(der)))
    }
}

// MARK: - One-tap session helpers (Phase 3)

extension YubiKeyPivTests {

    func test_session_readKey_checksSerialAndStub() throws {
        XCTAssertEqual(try PivSession.readKey(FakePivCard(key: key, certDER: certDER), stub: stub), compressedPub)
        XCTAssertThrowsError(try PivSession.readKey(FakePivCard(key: key, certDER: certDER, serial: 99), stub: stub)) {
            XCTAssertEqual($0 as? YubiKeyError, .wrongYubiKey(expected: 12_345_678, found: 99))
        }
        let otherStub = try YubiKeyStub(serial: 12_345_678, slot: 0x82, tag: Data([1, 2, 3, 4]))
        XCTAssertThrowsError(try PivSession.readKey(FakePivCard(key: key, certDER: certDER), stub: otherStub)) {
            XCTAssertEqual($0 as? YubiKeyError, .keyDoesNotMatchStub)
        }
    }

    func test_session_keyAgreements_pinFlow_andDecrypt() throws {
        let pt = Data("one tap".utf8)
        let ct = try Age.encrypt(plaintext: pt, to: [
            try P256Recipient(compressedPublicKey: compressedPub),
            try TagRecipient(publicKey: compressedPub),
        ])
        let points = try YubiKeyIdentity.probe(stub: stub, publicKey: compressedPub)
            .peerPoints(in: try Age.parseHeader(ciphertext: ct).stanzas)
        XCTAssertEqual(points.count, 2)

        // No PIN: the card asks for one, nothing is computed.
        let card = FakePivCard(key: key, certDER: certDER)
        XCTAssertThrowsError(try PivSession.keyAgreements(card, stub: stub, points: points, pin: nil)) {
            XCTAssertEqual($0 as? PivError, .pinRequired)
        }
        XCTAssertThrowsError(try PivSession.keyAgreements(card, stub: stub, points: points, pin: "000000")) {
            XCTAssertEqual($0 as? PivError, .wrongPIN(retriesLeft: 2))
        }
        // Through a closure transport, as the app drives it.
        let results = try PivSession.keyAgreements(BlockPivCard { try card.transmit($0) }, stub: stub, points: points, pin: "123456")
        XCTAssertEqual(results.count, 2)
        let id = try YubiKeyIdentity(stub: stub, publicKey: compressedPub, keyAgreement: RecordedKeyAgreement(results: results))
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [id]), pt)
    }

    func test_identityFile_parse() throws {
        let recipient = try Bech32.encodeYubiKeyRecipient(Array(compressedPub))
        let file = """
        #       Serial: 12345678, Slot: 1
        #         Name: age identity TEST
        #   PIN policy: Once   (A PIN is required once per session, if set)
        # Touch policy: Always (A physical touch is required for every decryption)
        #    Recipient: \(recipient)
        \(stub.encode())
        """
        let full = try YubiKeyStub.parseIdentityFile(file)
        XCTAssertEqual(full.stub, stub)
        XCTAssertEqual(full.publicKey, compressedPub)

        let bare = try YubiKeyStub.parseIdentityFile("  \(stub.encode().lowercased())\n")
        XCTAssertEqual(bare.stub, stub)
        XCTAssertNil(bare.publicKey)

        // A recipient comment for a different key is ignored rather than trusted.
        let other = Bech32.encodeYubiKeyRecipient(Array(try P256Curve.compressed(P256SoftwareKey.generate().publicUncompressed)))
        XCTAssertNil(try YubiKeyStub.parseIdentityFile("# Recipient: \(other)\n\(stub.encode())").publicKey)
        XCTAssertThrowsError(try YubiKeyStub.parseIdentityFile("AGE-SECRET-KEY-1XYZ"))
    }
}

// MARK: - PIN policy (5.1.0 item 1)

/// A YubiKey on firmware 5.3+: `FakePivCard` plus GET METADATA with a given PIN policy byte.
final class MetadataPivCard: PivCard {
    let inner: FakePivCard
    let policyByte: UInt8
    var metadataAPDUs: [Data] = []

    init(_ inner: FakePivCard, policyByte: UInt8) {
        self.inner = inner; self.policyByte = policyByte
    }

    func transmit(_ apdu: Data) throws -> Data {
        let a = Array(apdu)
        guard a[1] == 0xF7 else { return try inner.transmit(apdu) }
        metadataAPDUs.append(apdu)
        // Algorithm, policy (PIN, touch), origin, as a YubiKey answers for a P-256 slot.
        return Tlv.encode(tag: 0x01, value: Data([0x11]))
            + Tlv.encode(tag: 0x02, value: Data([policyByte, 0x01]))
            + Tlv.encode(tag: 0x03, value: Data([0x01]))
            + Data([0x90, 0x00])
    }
}

extension YubiKeyPivTests {

    func identityFile(pinPolicyLine: String?) -> String {
        var lines = [
            "#       Serial: 12345678, Slot: 1",
            "#         Name: age identity TEST",
        ]
        if let pinPolicyLine { lines.append(pinPolicyLine) }
        lines.append("# Touch policy: Always (A physical touch is required for every decryption)")
        lines.append(stub.encode())
        return lines.joined(separator: "\n")
    }

    func test_identityFile_pinPolicyComment() throws {
        let never = try YubiKeyStub.parseIdentityFile(identityFile(pinPolicyLine: "#   PIN policy: Never  (A PIN is NOT required to decrypt)"))
        XCTAssertEqual(never.pinPolicy, .notRequired)
        XCTAssertEqual(never.stub, stub)

        let once = try YubiKeyStub.parseIdentityFile(identityFile(pinPolicyLine: "#   PIN policy: Once   (A PIN is required once per session, if set)"))
        XCTAssertEqual(once.pinPolicy, .required)

        let always = try YubiKeyStub.parseIdentityFile(identityFile(pinPolicyLine: "#   PIN policy: Always (A PIN is required for every decryption, if set)"))
        XCTAssertEqual(always.pinPolicy, .required)

        // No PIN policy line (the touch policy line must not be read as one), and a bare stub.
        XCTAssertEqual(try YubiKeyStub.parseIdentityFile(identityFile(pinPolicyLine: nil)).pinPolicy, .unknown)
        XCTAssertEqual(try YubiKeyStub.parseIdentityFile(stub.encode()).pinPolicy, .unknown)

        // A value this version doesn't know stays unknown, so the app still asks first.
        XCTAssertEqual(try YubiKeyStub.parseIdentityFile(identityFile(pinPolicyLine: "#   PIN policy: Sometimes")).pinPolicy, .unknown)
    }

    func test_metadata_pinPolicyBytes() {
        func answer(_ policy: UInt8) -> Data {
            Tlv.encode(tag: 0x01, value: Data([0x11])) + Tlv.encode(tag: 0x02, value: Data([policy, 0x01]))
        }
        XCTAssertEqual(Piv.pinPolicy(metadata: answer(0), sw: 0x9000), .required)     // slot default
        XCTAssertEqual(Piv.pinPolicy(metadata: answer(1), sw: 0x9000), .notRequired)  // never
        XCTAssertEqual(Piv.pinPolicy(metadata: answer(2), sw: 0x9000), .required)     // once
        XCTAssertEqual(Piv.pinPolicy(metadata: answer(3), sw: 0x9000), .required)     // always
        XCTAssertEqual(Piv.pinPolicy(metadata: answer(0x7F), sw: 0x9000), .unknown)
        // Firmware before 5.3 has no GET METADATA.
        XCTAssertEqual(Piv.pinPolicy(metadata: Data(), sw: 0x6D00), .unknown)
        // No policy tag, or a truncated one.
        XCTAssertEqual(Piv.pinPolicy(metadata: Tlv.encode(tag: 0x01, value: Data([0x11])), sw: 0x9000), .unknown)
        XCTAssertEqual(Piv.pinPolicy(metadata: Data([0x02, 0x05, 0x01]), sw: 0x9000), .unknown)
    }

    func test_metadata_onTheImportTap() throws {
        // Old firmware (the fake card answers 6D00 to F7): key read, policy unknown.
        let old = FakePivCard(key: key, certDER: certDER)
        XCTAssertEqual(try Piv.pinPolicy(old, slot: 0x82), .unknown)
        let oldRead = try PivSession.readKeyAndPINPolicy(old, stub: stub)
        XCTAssertEqual(oldRead.key, compressedPub)
        XCTAssertEqual(oldRead.pinPolicy, .unknown)

        let expected: [(UInt8, YubiKeyPINPolicy)] = [(0, .required), (1, .notRequired), (2, .required), (3, .required)]
        for (byte, policy) in expected {
            let card = MetadataPivCard(FakePivCard(key: key, certDER: certDER), policyByte: byte)
            let read = try PivSession.readKeyAndPINPolicy(card, stub: stub)
            XCTAssertEqual(read.key, compressedPub)
            XCTAssertEqual(read.pinPolicy, policy, "policy byte \(byte)")
            // GET METADATA for the stub's slot: 00 F7 00 82 00. No PIN was sent.
            XCTAssertEqual(card.metadataAPDUs, [Data([0x00, 0xF7, 0x00, 0x82, 0x00])])
            XCTAssertFalse(card.inner.pinVerified)
        }
    }
}

extension YubiKeyPivTests {

    /// A file with two identities: the PIN policy is the first identity's, the one
    /// whose stub is read, not the last one in the file.
    func test_identityFile_pinPolicyFromFirstStubOnly() throws {
        let text = identityFile(pinPolicyLine: "#   PIN policy: Never  (A PIN is NOT required to decrypt)")
            + "\n\n" + identityFile(pinPolicyLine: "#   PIN policy: Always (A PIN is required for every decryption, if set)")
        let parsed = try YubiKeyStub.parseIdentityFile(text)
        XCTAssertEqual(parsed.stub, stub)
        XCTAssertEqual(parsed.pinPolicy, .notRequired)

        let reversed = identityFile(pinPolicyLine: "#   PIN policy: Once   (A PIN is required once per session, if set)")
            + "\n\n" + identityFile(pinPolicyLine: "#   PIN policy: Never  (A PIN is NOT required to decrypt)")
        XCTAssertEqual(try YubiKeyStub.parseIdentityFile(reversed).pinPolicy, .required)
    }
}
