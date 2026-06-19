import XCTest
import CryptoKit
@testable import AgePonyCore

final class SSHRSATests: XCTestCase {
    func testRecipientFromTestFixturePub() throws {
        let r = try SSHRSARecipient(sshPublicKeyLine: RSAKeyTests.testPubLine)
        XCTAssertEqual(r.blockSize, 256)
    }

    func testIdentityFromTestFixturePrivPEM() throws {
        let i = try SSHRSAIdentity(openSSHPrivateKey: RSAKeyTests.testPrivPEM)
        XCTAssertEqual(i.blockSize, 256)
    }

    func testWrapUnwrapRoundTrip() throws {
        let recipient = try SSHRSARecipient(sshPublicKeyLine: RSAKeyTests.testPubLine)
        let identity  = try SSHRSAIdentity(openSSHPrivateKey: RSAKeyTests.testPrivPEM)
        let fileKey = Data(repeating: 0x33, count: 16)
        let stanza = try recipient.wrap(fileKey: fileKey)
        XCTAssertEqual(stanza.type, "ssh-rsa")
        XCTAssertEqual(stanza.args.count, 1)
        XCTAssertEqual(stanza.body.count, 256)
        let recovered = try identity.unwrap(stanza: stanza)
        XCTAssertEqual(recovered, fileKey)
    }

    func testWrapProducesExpectedTag() throws {
        // The wireBlob's SHA-256[:4] tag for our test fixture was computed offline:
        //   88c29d70  (b64: iMKdcA)
        let recipient = try SSHRSARecipient(sshPublicKeyLine: RSAKeyTests.testPubLine)
        let stanza = try recipient.wrap(fileKey: Data(repeating: 0x00, count: 16))
        XCTAssertEqual(stanza.args[0], "iMKdcA")
        // Independent check against the hash
        let expected = Data(SHA256.hash(data: recipient.wireBlob).prefix(4))
        XCTAssertEqual(expected.map { String(format: "%02x", $0) }.joined(), "88c29d70")
    }

    func testUnwrapWrongIdentityReturnsNil() throws {
        // Generate a different key by perturbing the message (different tag entirely).
        let recipient = try SSHRSARecipient(sshPublicKeyLine: RSAKeyTests.testPubLine)
        let stanza = try recipient.wrap(fileKey: Data(repeating: 0x00, count: 16))
        // Construct an identity whose wireBlob doesn't match (just supply a wrong blob).
        let parts = try SSHRSAKeyParser.parseOpenSSHPrivateKey(RSAKeyTests.testPrivPEM)
        let pub = try RSAKey.makePublic(n: parts.n, e: parts.e)
        let priv = try RSAKey.makePrivate(
            n: parts.n, e: parts.e, d: parts.d, p: parts.p, q: parts.q, iqmp: parts.iqmp
        )
        let wrongIdentity = try SSHRSAIdentity(
            rsaPrivateKey: priv, rsaPublicKey: pub,
            wireBlob: Data("totally different bytes that produce a different tag".utf8)
        )
        let result = try wrongIdentity.unwrap(stanza: stanza)
        XCTAssertNil(result)
    }

    func testUnwrapNonRSAStanzaReturnsNil() throws {
        let identity = try SSHRSAIdentity(openSSHPrivateKey: RSAKeyTests.testPrivPEM)
        let fake = Stanza(type: "X25519", args: ["abc"], body: Data())
        let result = try identity.unwrap(stanza: fake)
        XCTAssertNil(result)
    }

    func testUnwrapMalformedStanzaReturnsNil() throws {
        let identity = try SSHRSAIdentity(openSSHPrivateKey: RSAKeyTests.testPrivPEM)
        // Wrong arg count
        let stanza1 = Stanza(type: "ssh-rsa", args: [], body: Data(repeating: 0, count: 256))
        XCTAssertNil(try identity.unwrap(stanza: stanza1))
        // Right tag but wrong body size
        let recipient = try SSHRSARecipient(sshPublicKeyLine: RSAKeyTests.testPubLine)
        let tag = Stanza.base64NoPad(Data(SHA256.hash(data: recipient.wireBlob).prefix(4)))
        let stanza2 = Stanza(type: "ssh-rsa", args: [tag], body: Data(repeating: 0, count: 100))
        XCTAssertNil(try identity.unwrap(stanza: stanza2))
    }

    func testMixedRecipients_RSA_and_Ed25519() throws {
        // Encrypt once to both, decrypt with each identity
        let rsaRecipient = try SSHRSARecipient(sshPublicKeyLine: RSAKeyTests.testPubLine)
        let edKey = Curve25519.Signing.PrivateKey()
        let edRecipient = try SSHEd25519Recipient(edPublicKey: edKey.publicKey.rawRepresentation)
        let plaintext = Data("hello mixed recipients\n".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext,
                                         to: [rsaRecipient, edRecipient])

        let rsaIdentity = try SSHRSAIdentity(openSSHPrivateKey: RSAKeyTests.testPrivPEM)
        let edIdentity = try SSHEd25519Identity(edSeed: edKey.rawRepresentation,
                                                edPublicKey: edKey.publicKey.rawRepresentation)
        // Decrypt with RSA identity
        let viaRSA = try Age.decrypt(ciphertext: ciphertext, identities: [rsaIdentity])
        XCTAssertEqual(viaRSA, plaintext)
        // Decrypt with Ed25519 identity
        let viaEd = try Age.decrypt(ciphertext: ciphertext, identities: [edIdentity])
        XCTAssertEqual(viaEd, plaintext)
    }
}
