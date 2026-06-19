import XCTest
@testable import AgePonyCore

final class SSHRSAEncryptedTests: XCTestCase {

    /// Construct identity from encrypted PEM with the correct passphrase.
    func testInit_encryptedPEM_correctPassphrase() throws {
        XCTAssertNoThrow(
            try SSHRSAIdentity(
                openSSHPrivateKey: EncryptedPEMFixtures.rsaEncrypted,
                passphrase: EncryptedPEMFixtures.passphrase
            )
        )
    }

    func testInit_encryptedPEM_wrongPassphrase() {
        XCTAssertThrowsError(
            try SSHRSAIdentity(
                openSSHPrivateKey: EncryptedPEMFixtures.rsaEncrypted,
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
            try SSHRSAIdentity(
                openSSHPrivateKey: EncryptedPEMFixtures.rsaEncrypted,
                passphrase: nil
            )
        ) { error in
            guard case OpenSSHEncryptedKeyError.passphraseRequired = error else {
                return XCTFail("expected passphraseRequired, got \(error)")
            }
        }
    }

    /// nil passphrase is fine when the PEM is already unencrypted.
    func testInit_unencryptedPEM_nilPassphrase() throws {
        XCTAssertNoThrow(
            try SSHRSAIdentity(
                openSSHPrivateKey: EncryptedPEMFixtures.rsaUnencrypted,
                passphrase: nil
            )
        )
    }

    /// Full round-trip: encrypt with pub recipient, decrypt with encrypted-PEM identity.
    func testEndToEnd_wrapUnwrap() throws {
        let recipient = try SSHRSARecipient(sshPublicKeyLine: EncryptedPEMFixtures.rsaPubLine)
        let identity = try SSHRSAIdentity(
            openSSHPrivateKey: EncryptedPEMFixtures.rsaEncrypted,
            passphrase: EncryptedPEMFixtures.passphrase
        )
        let plaintext = Data("hello from a passphrase-protected RSA identity\n".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])
        let recovered = try Age.decrypt(ciphertext: ciphertext, identities: [identity])
        XCTAssertEqual(recovered, plaintext)
    }

    /// Same round-trip but using the unencrypted PEM for the identity — verifies the
    /// underlying recipient still works the same way regardless of which form we load.
    func testEndToEnd_unencryptedIdentity() throws {
        let recipient = try SSHRSARecipient(sshPublicKeyLine: EncryptedPEMFixtures.rsaPubLine)
        let identity = try SSHRSAIdentity(
            openSSHPrivateKey: EncryptedPEMFixtures.rsaUnencrypted,
            passphrase: nil
        )
        let plaintext = Data("payload for unencrypted RSA identity\n".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])
        let recovered = try Age.decrypt(ciphertext: ciphertext, identities: [identity])
        XCTAssertEqual(recovered, plaintext)
    }
}
