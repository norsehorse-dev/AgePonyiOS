//
//  TextDecryptVerifyTests.swift
//  AgePonyTests
//
//  5.1.1 (L-1): Text decrypt checks a signature the way the file flow does, for
//  a header stanza and for a signed bundle. (L-3): a failed verdict changes the
//  decrypt headline and tints the summary line.
//

import XCTest
import AgePonyCore
@testable import AgePony

@MainActor
final class TextDecryptVerifyTests: XCTestCase {

    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("TextVerify-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func signingIdentity() -> (identity: StoredIdentity, seed: Data, pub: Data) {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let identity = StoredIdentity(
            name: "Signer",
            type: .sshEd25519,
            publicKeyMaterial: SSHSig.ed25519PublicKeyWire(pub),
            privateKeyMaterial: seed + pub,
            sshComment: "test"
        )
        return (identity, seed, pub)
    }

    private func input(_ text: String) throws -> URL {
        let url = dir.appendingPathComponent("note.txt")
        try Data(text.utf8).write(to: url)
        return url
    }

    // MARK: - Signature stanza (key files)

    func testKeySignedTextVerifies() throws {
        let (signer, _, _) = signingIdentity()
        let x = X25519Identity.generate()
        let out = try SignEncryptService.signEncrypt(
            inputURL: try input("meet at noon"),
            recipients: [try X25519Recipient(publicKey: x.publicKey)],
            passphrase: nil,
            armor: true,
            signingIdentity: signer
        )
        defer { FileEncryptor.cleanupTempFile(at: out.encryptedURL) }
        let armored = try String(contentsOf: out.encryptedURL, encoding: .utf8)
        let binary = try AgeArmor.decode(armored)

        let own = try TextDecryptor.decrypt(binary: binary, identities: [x], passphrase: nil,
                                            storedIdentities: [signer], recipients: [], signers: [])
        XCTAssertEqual(own.text, "meet at noon")
        XCTAssertEqual(own.signature?.trust, .trusted(signerName: "Signer", isOwnIdentity: true))

        let stranger = try TextDecryptor.decrypt(binary: binary, identities: [x], passphrase: nil,
                                                 storedIdentities: [], recipients: [], signers: [])
        XCTAssertEqual(stranger.signature?.trust, .validUnknownKey)
    }

    func testUnsignedTextHasNoVerdict() throws {
        let x = X25519Identity.generate()
        let binary = try Age.encrypt(plaintext: Data("plain".utf8), to: [try X25519Recipient(publicKey: x.publicKey)])
        let outcome = try TextDecryptor.decrypt(binary: binary, identities: [x], passphrase: nil,
                                                storedIdentities: [], recipients: [], signers: [])
        XCTAssertEqual(outcome.text, "plain")
        XCTAssertNil(outcome.signature)
    }

    // MARK: - Signed bundle (passphrase files)

    func testPassphraseSignedBundleIsUnwrappedAndVerified() throws {
        let (signer, _, _) = signingIdentity()
        let out = try SignEncryptService.signEncrypt(
            inputURL: try input("bundle body"),
            recipients: [],
            passphrase: "a long test passphrase",
            armor: false,
            signingIdentity: signer,
            workFactor: 10
        )
        defer { FileEncryptor.cleanupTempFile(at: out.encryptedURL) }
        let binary = try Data(contentsOf: out.encryptedURL)

        let outcome = try TextDecryptor.decrypt(binary: binary, identities: [], passphrase: "a long test passphrase",
                                                storedIdentities: [signer], recipients: [], signers: [])
        XCTAssertEqual(outcome.text, "bundle body", "the bundle wrapper is stripped")
        XCTAssertEqual(outcome.signature?.trust, .trusted(signerName: "Signer", isOwnIdentity: true))
    }

    func testWrongPassphraseIsReportedAsSuch() throws {
        let binary = try Age.encrypt(plaintext: Data("x".utf8), passphrase: "right", workFactor: 10)
        XCTAssertThrowsError(try TextDecryptor.decrypt(binary: binary, identities: [], passphrase: "wrong",
                                                       storedIdentities: [], recipients: [], signers: [])) {
            XCTAssertEqual($0 as? AgeError, .wrongPassphrase)
        }
    }

    func testForgedBundleFailsLoudly() throws {
        let (_, seed, pub) = signingIdentity()
        let payload = Data("forged".utf8)
        // A real signature, over something else.
        let sig = try SSHSigner.signEd25519(message: Data("other".utf8), seed: seed, publicKey: pub)
        let bundle = try SignedBundle.buildV2(originalName: "a.txt", payload: payload, signatureArmored: sig)
        let x = X25519Identity.generate()
        let binary = try Age.encrypt(plaintext: bundle, to: [try X25519Recipient(publicKey: x.publicKey)])

        let outcome = try TextDecryptor.decrypt(binary: binary, identities: [x], passphrase: nil,
                                                storedIdentities: [], recipients: [], signers: [])
        XCTAssertEqual(outcome.text, "forged")
        let verdict = try XCTUnwrap(outcome.signature)
        XCTAssertTrue(verdict.trust.isFailure)

        XCTAssertEqual(DecryptHeadline.kind(for: verdict), .failure)
        XCTAssertNotEqual(DecryptHeadline.text(for: verdict), DecryptHeadline.text(for: nil))
    }

    func testDamagedBundleIsNotShownAsText() throws {
        let (_, seed, pub) = signingIdentity()
        let sig = try SSHSigner.signEd25519(message: Data("x".utf8), seed: seed, publicKey: pub)
        let bundle = try SignedBundle.buildV2(originalName: "a.txt", payload: Data("x".utf8), signatureArmored: sig)
        // The marker entry's header block alone: announces a bundle, isn't one.
        let truncated = Data(bundle.prefix(512))
        XCTAssertTrue(SignedBundle.looksLikeBundle(truncated))
        let x = X25519Identity.generate()
        let binary = try Age.encrypt(plaintext: truncated, to: [try X25519Recipient(publicKey: x.publicKey)])

        XCTAssertThrowsError(try TextDecryptor.decrypt(binary: binary, identities: [x], passphrase: nil,
                                                       storedIdentities: [], recipients: [], signers: [])) {
            guard case .bundleDamaged? = $0 as? FileEncryptorError else {
                return XCTFail("expected bundleDamaged, got \($0)")
            }
        }
    }

    // MARK: - Verdict presentation (L-3)

    func testOnlyAFailedVerdictIsAFailure() {
        XCTAssertTrue(SignatureTrust.invalid(reason: "x").isFailure)
        XCTAssertFalse(SignatureTrust.validUnknownKey.isFailure)
        XCTAssertFalse(SignatureTrust.trusted(signerName: "a", isOwnIdentity: true).isFailure)
    }

    func testHeadlineKinds() {
        func result(_ trust: SignatureTrust) -> FileVerificationResult {
            FileVerificationResult(trust: trust, signerKeyType: nil, signerFingerprint: nil,
                                   signerPublicKeyWire: nil, namespace: nil)
        }
        let plain = DecryptHeadline.text(for: nil)
        XCTAssertEqual(DecryptHeadline.kind(for: nil), .success)
        XCTAssertEqual(DecryptHeadline.kind(for: result(.validUnknownKey)), .success)
        XCTAssertEqual(DecryptHeadline.text(for: result(.validUnknownKey)), plain)
        XCTAssertEqual(DecryptHeadline.text(for: result(.trusted(signerName: "a", isOwnIdentity: false))), plain)
        XCTAssertEqual(DecryptHeadline.kind(for: result(.invalid(reason: "x"))), .failure)
        XCTAssertNotEqual(DecryptHeadline.text(for: result(.invalid(reason: "x"))), plain)
    }
}
