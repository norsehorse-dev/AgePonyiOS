//
//  X25519Tests.swift
//  AgePonyCoreTests
//

import XCTest
@testable import AgePonyCore

final class X25519Tests: XCTestCase {

    func testGenerateIdentityProducesValidStrings() {
        let id = X25519Identity.generate()
        XCTAssertTrue(id.ageRecipient.hasPrefix("age1"))
        XCTAssertTrue(id.ageIdentityString.hasPrefix("AGE-SECRET-KEY-1"))
        XCTAssertEqual(id.privateKey.count, 32)
        XCTAssertEqual(id.publicKey.count, 32)
    }

    func testIdentityStringRoundTripPreservesKeys() throws {
        let original = X25519Identity.generate()
        let secStr = original.ageIdentityString
        let pubStr = original.ageRecipient
        let parsedIdentity = try X25519Identity(ageIdentity: secStr)
        let parsedRecipient = try X25519Recipient(ageRecipient: pubStr)
        XCTAssertEqual(parsedIdentity.privateKey, original.privateKey)
        XCTAssertEqual(parsedIdentity.publicKey, original.publicKey)
        XCTAssertEqual(parsedRecipient.publicKey, original.publicKey)
    }

    func testWrapAndUnwrapRoundTrip() throws {
        let identity = X25519Identity.generate()
        let recipient = try X25519Recipient(ageRecipient: identity.ageRecipient)
        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })

        let stanza = try recipient.wrap(fileKey: fileKey)
        XCTAssertEqual(stanza.type, "X25519")
        XCTAssertEqual(stanza.args.count, 1)
        XCTAssertEqual(stanza.body.count, 32)

        let recovered = try identity.unwrap(stanza: stanza)
        XCTAssertNotNil(recovered)
        XCTAssertEqual(recovered, fileKey)
    }

    func testUnwrapReturnsNilForWrongIdentity() throws {
        let recipient = X25519Identity.generate()  // who we encrypt to
        let stranger = X25519Identity.generate()   // who tries to decrypt
        let recipientPub = try X25519Recipient(ageRecipient: recipient.ageRecipient)

        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let stanza = try recipientPub.wrap(fileKey: fileKey)
        let result = try stranger.unwrap(stanza: stanza)
        XCTAssertNil(result)
    }

    func testUnwrapReturnsNilForNonX25519Stanza() throws {
        let identity = X25519Identity.generate()
        let scryptStanza = Stanza(
            type: "scrypt",
            args: [Stanza.base64NoPad(Data(repeating: 0, count: 16)), "18"],
            body: Data(repeating: 0, count: 32)
        )
        let result = try identity.unwrap(stanza: scryptStanza)
        XCTAssertNil(result)
    }

    func testRecipientRejectsWrongPubKeyLength() {
        XCTAssertThrowsError(try X25519Recipient(publicKey: Data(repeating: 0, count: 31))) { error in
            XCTAssertEqual(error as? X25519Error, .invalidPublicKeyLength)
        }
    }

    func testIdentityRejectsWrongPrivKeyLength() {
        XCTAssertThrowsError(try X25519Identity(privateKey: Data(repeating: 0, count: 33))) { error in
            XCTAssertEqual(error as? X25519Error, .invalidPrivateKeyLength)
        }
    }

    func testEphemeralKeysAreRandom() throws {
        // Encrypting the same plaintext to the same recipient twice should
        // produce different ephemeral keys (and thus different stanzas).
        let recipient = X25519Identity.generate()
        let recipientPub = try X25519Recipient(ageRecipient: recipient.ageRecipient)
        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let stanza1 = try recipientPub.wrap(fileKey: fileKey)
        let stanza2 = try recipientPub.wrap(fileKey: fileKey)
        XCTAssertNotEqual(stanza1.args[0], stanza2.args[0], "ephemeral pubkey must be fresh")
        XCTAssertNotEqual(stanza1.body, stanza2.body, "wrapped key must differ when ephemeral differs")
    }
}
