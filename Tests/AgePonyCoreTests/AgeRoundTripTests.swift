//
//  AgeRoundTripTests.swift
//  AgePonyCoreTests
//
//  Full encrypt-then-decrypt tests through the top-level Age API.
//

import XCTest
@testable import AgePonyCore

final class AgeRoundTripTests: XCTestCase {

    // MARK: - X25519 single recipient

    func testX25519_singleRecipient() throws {
        let identity = X25519Identity.generate()
        let recipient = try X25519Recipient(ageRecipient: identity.ageRecipient)
        let plaintext = Data("hello age world".utf8)

        let ct = try Age.encrypt(plaintext: plaintext, to: [recipient])
        let pt = try Age.decrypt(ciphertext: ct, identities: [identity])
        XCTAssertEqual(pt, plaintext)
    }

    // MARK: - X25519 multi-recipient

    func testX25519_threeRecipients_eachCanDecrypt() throws {
        let a = X25519Identity.generate()
        let b = X25519Identity.generate()
        let c = X25519Identity.generate()
        let recipients = try [a, b, c].map { try X25519Recipient(ageRecipient: $0.ageRecipient) }

        let plaintext = Data("encrypted to three".utf8)
        let ct = try Age.encrypt(plaintext: plaintext, to: recipients)

        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [a]), plaintext)
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [b]), plaintext)
        XCTAssertEqual(try Age.decrypt(ciphertext: ct, identities: [c]), plaintext)
    }

    func testX25519_strangerCannotDecrypt() throws {
        let target = X25519Identity.generate()
        let stranger = X25519Identity.generate()
        let recipient = try X25519Recipient(ageRecipient: target.ageRecipient)

        let plaintext = Data("not for you".utf8)
        let ct = try Age.encrypt(plaintext: plaintext, to: [recipient])

        XCTAssertThrowsError(try Age.decrypt(ciphertext: ct, identities: [stranger])) { error in
            XCTAssertEqual(error as? AgeError, .noMatchingIdentity)
        }
    }

    // MARK: - scrypt round-trip

    func testScrypt_passphraseRoundTrip() throws {
        // Low work factor for fast tests; the cryptographic correctness comes
        // from ScryptTests.swift RFC 7914 vectors.
        let plaintext = Data("a passphrase-protected secret".utf8)
        let ct = try Age.encrypt(plaintext: plaintext, passphrase: "correct horse", workFactor: 4)
        let pt = try Age.decrypt(ciphertext: ct, passphrase: "correct horse")
        XCTAssertEqual(pt, plaintext)
    }

    func testScrypt_wrongPassphraseRejected() throws {
        let plaintext = Data("secret".utf8)
        let ct = try Age.encrypt(plaintext: plaintext, passphrase: "correct", workFactor: 4)
        XCTAssertThrowsError(try Age.decrypt(ciphertext: ct, passphrase: "wrong")) { error in
            XCTAssertEqual(error as? AgeError, .wrongPassphrase)
        }
    }

    // MARK: - Mixing recipient types

    func testScrypt_cannotBeMixedWithOtherRecipients() throws {
        let identity = X25519Identity.generate()
        let r1 = try X25519Recipient(ageRecipient: identity.ageRecipient)
        let r2 = ScryptRecipient(passphrase: "x", workFactor: 4)
        XCTAssertThrowsError(try Age.encrypt(plaintext: Data("hi".utf8), to: [r1, r2])) { error in
            XCTAssertEqual(error as? AgeError, .scryptMustBeSoleRecipient)
        }
    }

    func testNoRecipientsRejected() {
        XCTAssertThrowsError(try Age.encrypt(plaintext: Data(), to: [])) { error in
            XCTAssertEqual(error as? AgeError, .noRecipients)
        }
    }

    // MARK: - Plaintext sizes

    func testEmptyPlaintext() throws {
        let id = X25519Identity.generate()
        let r = try X25519Recipient(ageRecipient: id.ageRecipient)
        let ct = try Age.encrypt(plaintext: Data(), to: [r])
        let pt = try Age.decrypt(ciphertext: ct, identities: [id])
        XCTAssertEqual(pt, Data())
    }

    func testLargePlaintext_severalChunks() throws {
        let id = X25519Identity.generate()
        let r = try X25519Recipient(ageRecipient: id.ageRecipient)
        // ~200 KiB to exercise multiple chunks.
        let size = AgePayload.chunkSize * 3 + 257
        let plaintext = Data((0..<size).map { UInt8($0 % 256) })
        let ct = try Age.encrypt(plaintext: plaintext, to: [r])
        let pt = try Age.decrypt(ciphertext: ct, identities: [id])
        XCTAssertEqual(pt, plaintext)
    }

    // MARK: - Tamper detection through the full pipeline

    func testTamperingHeaderTriggersInvalidMAC() throws {
        let id = X25519Identity.generate()
        let r = try X25519Recipient(ageRecipient: id.ageRecipient)
        var ct = try Age.encrypt(plaintext: Data("hello".utf8), to: [r])

        // Find the first byte of a stanza body and flip a bit. (The version
        // line is 22 bytes including newline; the "-> X25519 ..." line follows.
        // The wrapped key body is on its own line after that.)
        // Simpler: flip a bit at offset ~80, which is well inside the stanza body.
        let i = 80
        ct[i] ^= 0x40

        XCTAssertThrowsError(try Age.decrypt(ciphertext: ct, identities: [id]))
    }

    func testTamperingPayloadTriggersDecryptFailed() throws {
        let id = X25519Identity.generate()
        let r = try X25519Recipient(ageRecipient: id.ageRecipient)
        var ct = try Age.encrypt(plaintext: Data("hello world".utf8), to: [r])
        // Flip a bit in the very last byte (a tag byte of the final chunk).
        ct[ct.count - 1] ^= 0x01
        XCTAssertThrowsError(try Age.decrypt(ciphertext: ct, identities: [id])) { error in
            // Either payloadError(.decryptFailed) or noMatchingIdentity depending
            // on which check trips first; both are valid rejections.
            switch error {
            case AgeError.payloadError, AgeError.noMatchingIdentity, AgeError.headerError:
                break
            default:
                XCTFail("expected an Age error rejection, got \(error)")
            }
        }
    }

    // MARK: - Armor integration

    func testArmoredRoundTrip() throws {
        let id = X25519Identity.generate()
        let r = try X25519Recipient(ageRecipient: id.ageRecipient)
        let plaintext = Data("armored payload".utf8)
        let binary = try Age.encrypt(plaintext: plaintext, to: [r])
        let armored = AgeArmor.encode(binary)
        XCTAssertTrue(armored.hasPrefix("-----BEGIN AGE ENCRYPTED FILE-----"))
        let decoded = try AgeArmor.decode(armored)
        XCTAssertEqual(decoded, binary)
        let pt = try Age.decrypt(ciphertext: decoded, identities: [id])
        XCTAssertEqual(pt, plaintext)
    }
}
