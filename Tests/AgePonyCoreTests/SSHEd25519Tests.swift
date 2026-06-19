//
//  SSHEd25519Tests.swift
//  AgePonyCoreTests
//
//  Round-trip tests for the ssh-ed25519 stanza. Cross-implementation tests
//  against the reference age CLI are in ReferenceCLITests.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class SSHEd25519Tests: XCTestCase {

    // MARK: - Helpers

    private func makeKeypair() -> (seed: Data, pub: Data) {
        let k = Curve25519.Signing.PrivateKey()
        return (k.rawRepresentation, k.publicKey.rawRepresentation)
    }

    private func randomFileKey() -> Data {
        var d = Data(count: 16)
        for i in 0..<16 { d[i] = UInt8.random(in: 0...255) }
        return d
    }

    // MARK: - Round-trip

    func testWrapUnwrapRoundTrip() throws {
        let (seed, pub) = makeKeypair()
        let recipient = try SSHEd25519Recipient(edPublicKey: pub)
        let identity = try SSHEd25519Identity(edSeed: seed, edPublicKey: pub)

        let fileKey = randomFileKey()
        let stanza = try recipient.wrap(fileKey: fileKey)

        XCTAssertEqual(stanza.type, "ssh-ed25519")
        XCTAssertEqual(stanza.args.count, 2)
        XCTAssertEqual(stanza.body.count, 32)  // 16-byte ciphertext + 16-byte Poly1305 tag

        let unwrapped = try identity.unwrap(stanza: stanza)
        XCTAssertEqual(unwrapped, fileKey)
    }

    func testStanzaTagIsDeterministicForKey() throws {
        let (_, pub) = makeKeypair()
        let recipient1 = try SSHEd25519Recipient(edPublicKey: pub)
        let recipient2 = try SSHEd25519Recipient(edPublicKey: pub)

        let stanza1 = try recipient1.wrap(fileKey: randomFileKey())
        let stanza2 = try recipient2.wrap(fileKey: randomFileKey())

        // The tag (args[0]) is a function of the key, not the file key.
        XCTAssertEqual(stanza1.args[0], stanza2.args[0])
        // The ephemeral (args[1]) is fresh per wrap.
        XCTAssertNotEqual(stanza1.args[1], stanza2.args[1])
    }

    func testWrongIdentityReturnsNil() throws {
        let (_, pubA) = makeKeypair()
        let (seedB, pubB) = makeKeypair()
        let recipient = try SSHEd25519Recipient(edPublicKey: pubA)
        let wrongIdentity = try SSHEd25519Identity(edSeed: seedB, edPublicKey: pubB)

        let stanza = try recipient.wrap(fileKey: randomFileKey())
        let unwrapped = try wrongIdentity.unwrap(stanza: stanza)
        // Tag won't match → returns nil immediately.
        XCTAssertNil(unwrapped)
    }

    func testReturnsNilForNonSSHEd25519Stanza() throws {
        let (seed, pub) = makeKeypair()
        let identity = try SSHEd25519Identity(edSeed: seed, edPublicKey: pub)
        let strangerStanza = Stanza(type: "X25519", args: ["abc"], body: Data(repeating: 0, count: 32))
        XCTAssertNil(try identity.unwrap(stanza: strangerStanza))
    }

    func testReturnsNilForMalformedStanza() throws {
        let (seed, pub) = makeKeypair()
        let identity = try SSHEd25519Identity(edSeed: seed, edPublicKey: pub)

        // Wrong arg count
        let s1 = Stanza(type: "ssh-ed25519", args: ["abc"], body: Data())
        XCTAssertNil(try identity.unwrap(stanza: s1))

        // Wrong tag length
        let s2 = Stanza(
            type: "ssh-ed25519",
            args: [Stanza.base64NoPad(Data([0x01, 0x02, 0x03])), Stanza.base64NoPad(Data(repeating: 0, count: 32))],
            body: Data(repeating: 0, count: 32)
        )
        XCTAssertNil(try identity.unwrap(stanza: s2))

        // Wrong body length
        let s3 = Stanza(
            type: "ssh-ed25519",
            args: [Stanza.base64NoPad(Data(repeating: 0, count: 4)), Stanza.base64NoPad(Data(repeating: 0, count: 32))],
            body: Data(repeating: 0, count: 16)  // wrong; should be 32
        )
        XCTAssertNil(try identity.unwrap(stanza: s3))
    }

    func testTagMatchButCorruptedBodyReturnsNil() throws {
        let (seed, pub) = makeKeypair()
        let recipient = try SSHEd25519Recipient(edPublicKey: pub)
        let identity = try SSHEd25519Identity(edSeed: seed, edPublicKey: pub)

        var stanza = try recipient.wrap(fileKey: randomFileKey())
        // Flip a body bit — Poly1305 will reject.
        var body = stanza.body
        body[0] ^= 0xff
        stanza = Stanza(type: stanza.type, args: stanza.args, body: body)

        XCTAssertNil(try identity.unwrap(stanza: stanza))
    }

    // MARK: - Convenience initializers

    func testRecipientFromSSHPublicKeyLine() throws {
        let (_, pub) = makeKeypair()
        let line = SSHKeyTests.makeSSHPublicKeyLine(pub: pub, comment: "user@host")
        let recipient = try SSHEd25519Recipient(sshPublicKeyLine: line)
        XCTAssertEqual(recipient.edPublicKey, pub)
    }

    func testIdentityFromOpenSSHPrivateKey() throws {
        let (seed, pub) = makeKeypair()
        let pem = SSHKeyTests.makeOpenSSHPrivateKeyPEM(seed: seed, pub: pub, comment: "test")
        let identity = try SSHEd25519Identity(openSSHPrivateKey: pem)
        XCTAssertEqual(identity.edSeed, seed)
        XCTAssertEqual(identity.edPublicKey, pub)
    }

    // MARK: - Integration with top-level Age API

    func testTopLevelEncryptDecryptWithSSHEd25519() throws {
        let (seed, pub) = makeKeypair()
        let recipient = try SSHEd25519Recipient(edPublicKey: pub)
        let identity = try SSHEd25519Identity(edSeed: seed, edPublicKey: pub)

        let plaintext = Data("hooves and hashes\n".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])
        let decrypted = try Age.decrypt(ciphertext: ciphertext, identities: [identity])
        XCTAssertEqual(decrypted, plaintext)
    }

    func testMixedRecipients_X25519AndSSHEd25519() throws {
        // Encrypt to two recipient types in one file.
        let (seed, pub) = makeKeypair()
        let sshRecipient = try SSHEd25519Recipient(edPublicKey: pub)
        let sshIdentity = try SSHEd25519Identity(edSeed: seed, edPublicKey: pub)
        let xIdentity = X25519Identity.generate()
        let xRecipient = try X25519Recipient(publicKey: xIdentity.publicKey)

        let plaintext = Data("multi-recipient hooves\n".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [sshRecipient, xRecipient])

        // Either identity should be able to decrypt.
        XCTAssertEqual(try Age.decrypt(ciphertext: ciphertext, identities: [sshIdentity]), plaintext)
        XCTAssertEqual(try Age.decrypt(ciphertext: ciphertext, identities: [xIdentity]), plaintext)
    }
}
