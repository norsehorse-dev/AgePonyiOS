import XCTest
@testable import AgePonyCore

final class OpenSSHEncryptedKeyTests: XCTestCase {

    /// Decrypting the encrypted RSA PEM should produce a synthesized PEM whose decoded
    /// inner blob byte-equals the inner blob of the corresponding unencrypted PEM —
    /// EXCEPT for the first 8 bytes (check1, check2), which are random uint32s freshly
    /// generated on each call to Python's `cryptography.private_bytes`. They'll differ
    /// between the two PEMs even though the underlying key is identical.
    func testRSA_decryptedBlobMatchesUnencrypted() throws {
        let decBlobs = try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.rsaEncrypted,
            passphrase: EncryptedPEMFixtures.passphrase
        )
        let unencBlobs = try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.rsaUnencrypted,
            passphrase: nil
        )
        // publicBlob must match exactly (not encrypted; same key)
        XCTAssertEqual(decBlobs.publicBlob, unencBlobs.publicBlob)
        // For the inner blob, skip the first 8 bytes (check1+check2) and trim the trailing
        // 20 bytes (padding+comment terminator may differ between cipher block sizes).
        let from = 8
        let until = min(decBlobs.innerBlob.count, unencBlobs.innerBlob.count) - 20
        XCTAssertGreaterThan(until, from)
        let decSlice = decBlobs.innerBlob.subdata(
            in: decBlobs.innerBlob.startIndex.advanced(by: from)
                ..< decBlobs.innerBlob.startIndex.advanced(by: until))
        let unencSlice = unencBlobs.innerBlob.subdata(
            in: unencBlobs.innerBlob.startIndex.advanced(by: from)
                ..< unencBlobs.innerBlob.startIndex.advanced(by: until))
        XCTAssertEqual(decSlice, unencSlice)
    }

    func testEd25519_decryptedBlobMatchesUnencrypted() throws {
        let decBlobs = try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.edEncrypted,
            passphrase: EncryptedPEMFixtures.passphrase
        )
        let unencBlobs = try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.edUnencrypted,
            passphrase: nil
        )
        XCTAssertEqual(decBlobs.publicBlob, unencBlobs.publicBlob)
        let from = 8
        let until = min(decBlobs.innerBlob.count, unencBlobs.innerBlob.count) - 20
        XCTAssertGreaterThan(until, from)
        let decSlice = decBlobs.innerBlob.subdata(
            in: decBlobs.innerBlob.startIndex.advanced(by: from)
                ..< decBlobs.innerBlob.startIndex.advanced(by: until))
        let unencSlice = unencBlobs.innerBlob.subdata(
            in: unencBlobs.innerBlob.startIndex.advanced(by: from)
                ..< unencBlobs.innerBlob.startIndex.advanced(by: until))
        XCTAssertEqual(decSlice, unencSlice)
    }

    func testWrongPassphraseRejected_RSA() {
        XCTAssertThrowsError(try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.rsaEncrypted,
            passphrase: "wrong-passphrase"
        )) { error in
            guard case OpenSSHEncryptedKeyError.wrongPassphrase = error else {
                return XCTFail("expected wrongPassphrase, got \(error)")
            }
        }
    }

    func testWrongPassphraseRejected_Ed25519() {
        XCTAssertThrowsError(try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.edEncrypted,
            passphrase: "wrong-passphrase"
        )) { error in
            guard case OpenSSHEncryptedKeyError.wrongPassphrase = error else {
                return XCTFail("expected wrongPassphrase, got \(error)")
            }
        }
    }

    func testMissingPassphraseRejected() {
        XCTAssertThrowsError(try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.rsaEncrypted,
            passphrase: nil
        )) { error in
            guard case OpenSSHEncryptedKeyError.passphraseRequired = error else {
                return XCTFail("expected passphraseRequired, got \(error)")
            }
        }
    }

    func testUnencryptedPEMPassthrough() throws {
        // Passing an unencrypted PEM with passphrase=nil should succeed and return
        // identical bytes to what we'd get if we treated it as already-decrypted.
        let result1 = try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.rsaUnencrypted, passphrase: nil)
        let result2 = try OpenSSHEncryptedKey.decryptedBlobs(
            pem: EncryptedPEMFixtures.rsaUnencrypted, passphrase: "ignored")
        XCTAssertEqual(result1.innerBlob, result2.innerBlob)
        XCTAssertEqual(result1.publicBlob, result2.publicBlob)
    }

    func testDecryptedPEMRoundsThroughExistingParser() throws {
        // After decryptedPEM produces a synthesized unencrypted PEM, the existing
        // SSHRSAKeyParser.parseOpenSSHPrivateKey should parse it cleanly.
        let synthesized = try OpenSSHEncryptedKey.decryptedPEM(
            pem: EncryptedPEMFixtures.rsaEncrypted,
            passphrase: EncryptedPEMFixtures.passphrase
        )
        let parts = try SSHRSAKeyParser.parseOpenSSHPrivateKey(synthesized)
        XCTAssertEqual(parts.e, Data([0x01, 0x00, 0x01]))
        XCTAssertEqual(parts.n.count, 256)
    }
}
