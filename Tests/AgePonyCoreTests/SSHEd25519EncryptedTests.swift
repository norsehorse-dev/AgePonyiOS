import XCTest
@testable import AgePonyCore

final class SSHEd25519EncryptedTests: XCTestCase {

    /// Raw 32-byte ed25519 public key extracted from EncryptedPEMFixtures.edPubLine.
    /// Embedded directly to avoid coupling the test to a specific pub-line parser.
    private static let rawEdPub = Data([
        0xe9, 0xd3, 0xd3, 0xcb, 0x48, 0x07, 0x8d, 0x77,
        0x85, 0x0e, 0xdb, 0xa4, 0xce, 0xe4, 0x2d, 0x0a,
        0x6f, 0x20, 0x67, 0x8b, 0xfc, 0x82, 0x51, 0xd9,
        0xaf, 0x98, 0xfd, 0x8f, 0xef, 0xec, 0x21, 0xdb,
    ])

    func testInit_encryptedPEM_correctPassphrase() throws {
        XCTAssertNoThrow(
            try SSHEd25519Identity(
                openSSHPrivateKey: EncryptedPEMFixtures.edEncrypted,
                passphrase: EncryptedPEMFixtures.passphrase
            )
        )
    }

    func testInit_encryptedPEM_wrongPassphrase() {
        XCTAssertThrowsError(
            try SSHEd25519Identity(
                openSSHPrivateKey: EncryptedPEMFixtures.edEncrypted,
                passphrase: "totally-wrong"
            )
        ) { error in
            guard case OpenSSHEncryptedKeyError.wrongPassphrase = error else {
                return XCTFail("expected wrongPassphrase, got \(error)")
            }
        }
    }

    func testInit_encryptedPEM_nilPassphraseRejected() {
        XCTAssertThrowsError(
            try SSHEd25519Identity(
                openSSHPrivateKey: EncryptedPEMFixtures.edEncrypted,
                passphrase: nil
            )
        ) { error in
            guard case OpenSSHEncryptedKeyError.passphraseRequired = error else {
                return XCTFail("expected passphraseRequired, got \(error)")
            }
        }
    }

    func testInit_unencryptedPEM_nilPassphrase() throws {
        XCTAssertNoThrow(
            try SSHEd25519Identity(
                openSSHPrivateKey: EncryptedPEMFixtures.edUnencrypted,
                passphrase: nil
            )
        )
    }

    /// Full round-trip: encrypt with pub recipient, decrypt with encrypted-PEM identity.
    func testEndToEnd_wrapUnwrap() throws {
        let recipient = try SSHEd25519Recipient(edPublicKey: Self.rawEdPub)
        let identity = try SSHEd25519Identity(
            openSSHPrivateKey: EncryptedPEMFixtures.edEncrypted,
            passphrase: EncryptedPEMFixtures.passphrase
        )
        let plaintext = Data("hello from a passphrase-protected ed25519 identity\n".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])
        let recovered = try Age.decrypt(ciphertext: ciphertext, identities: [identity])
        XCTAssertEqual(recovered, plaintext)
    }

    func testEndToEnd_unencryptedIdentity() throws {
        let recipient = try SSHEd25519Recipient(edPublicKey: Self.rawEdPub)
        let identity = try SSHEd25519Identity(
            openSSHPrivateKey: EncryptedPEMFixtures.edUnencrypted,
            passphrase: nil
        )
        let plaintext = Data("payload for unencrypted ed25519 identity\n".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])
        let recovered = try Age.decrypt(ciphertext: ciphertext, identities: [identity])
        XCTAssertEqual(recovered, plaintext)
    }
}
