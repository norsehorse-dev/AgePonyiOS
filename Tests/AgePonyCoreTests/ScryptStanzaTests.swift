//
//  ScryptStanzaTests.swift
//  AgePonyCoreTests
//
//  Uses a deliberately low workFactor (4-5) for round-trip tests so they
//  complete quickly. The cryptographic correctness comes from RFC 7914
//  vectors in ScryptTests.swift; here we're testing the stanza wrapping.
//

import XCTest
@testable import AgePonyCore

final class ScryptStanzaTests: XCTestCase {

    func testWrapAndUnwrapRoundTrip() throws {
        let recipient = ScryptRecipient(passphrase: "hunter2", workFactor: 4)
        let identity = ScryptIdentity(passphrase: "hunter2")
        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })

        let stanza = try recipient.wrap(fileKey: fileKey)
        XCTAssertEqual(stanza.type, "scrypt")
        XCTAssertEqual(stanza.args.count, 2)
        XCTAssertEqual(stanza.args[1], "4")
        XCTAssertEqual(stanza.body.count, 32)

        // First arg is the 16-byte salt, base64-encoded.
        let saltData = try Stanza.base64Decode(stanza.args[0])
        XCTAssertEqual(saltData.count, 16)

        let recovered = try identity.unwrap(stanza: stanza)
        XCTAssertNotNil(recovered)
        XCTAssertEqual(recovered, fileKey)
    }

    func testWrongPassphraseReturnsNil() throws {
        let recipient = ScryptRecipient(passphrase: "correct", workFactor: 4)
        let wrongIdentity = ScryptIdentity(passphrase: "wrong")
        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let stanza = try recipient.wrap(fileKey: fileKey)
        let result = try wrongIdentity.unwrap(stanza: stanza)
        XCTAssertNil(result)
    }

    func testReturnsNilForNonScryptStanza() throws {
        let identity = ScryptIdentity(passphrase: "anything")
        let nonScrypt = Stanza(type: "X25519", args: ["abc"], body: Data(repeating: 0, count: 32))
        let result = try identity.unwrap(stanza: nonScrypt)
        XCTAssertNil(result)
    }

    func testRejectsWorkFactorAboveCap() throws {
        let identity = ScryptIdentity(passphrase: "p", maxWorkFactor: 10)
        let stanza = Stanza(
            type: "scrypt",
            args: [Stanza.base64NoPad(Data(repeating: 0, count: 16)), "30"],  // way too high
            body: Data(repeating: 0, count: 32)
        )
        XCTAssertThrowsError(try identity.unwrap(stanza: stanza)) { error in
            XCTAssertEqual(error as? ScryptStanzaError, .invalidWorkFactor)
        }
    }

    func testRejectsMalformedWorkFactor() {
        let identity = ScryptIdentity(passphrase: "p")
        let stanza = Stanza(
            type: "scrypt",
            args: [Stanza.base64NoPad(Data(repeating: 0, count: 16)), "abc"],
            body: Data(repeating: 0, count: 32)
        )
        XCTAssertThrowsError(try identity.unwrap(stanza: stanza)) { error in
            XCTAssertEqual(error as? ScryptStanzaError, .invalidWorkFactor)
        }
    }

    func testSaltIsRandom() throws {
        // Wrapping twice with the same passphrase should produce different salts.
        let recipient = ScryptRecipient(passphrase: "x", workFactor: 4)
        let fileKey = Data(repeating: 0xAB, count: 16)
        let s1 = try recipient.wrap(fileKey: fileKey)
        let s2 = try recipient.wrap(fileKey: fileKey)
        XCTAssertNotEqual(s1.args[0], s2.args[0])
        XCTAssertNotEqual(s1.body, s2.body)
    }
}
