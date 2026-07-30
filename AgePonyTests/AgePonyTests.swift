//
//  AgePonyTests.swift
//  AgePonyTests
//
//  Created by NorseHorse on 5/27/26.
//

import Testing
import Foundation
import AgePonyCore
@testable import AgePony

struct AgePonyTests {

    @Test func example() async throws {
        // Write your test here and use APIs like `#expect(...)` to check expected conditions.
        // Swift Testing Documentation
        // https://developer.apple.com/documentation/testing
    }

    // MARK: - FileSigner (C0)

    /// Sign a temp file with a generated Ed25519 identity, then verify the
    /// produced .sig against the same key. Exercises the full app-layer path
    /// (FileSigner -> AgePonyCore SSHSigner -> SSHSigVerifier).
    @Test func fileSignerRoundTrip() async throws {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let identity = StoredIdentity(
            name: "Signing key",
            type: .sshEd25519,
            publicKeyMaterial: SSHSig.ed25519PublicKeyWire(pub),
            privateKeyMaterial: seed + pub,
            sshComment: "agepony"
        )

        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-test-\(UUID().uuidString.prefix(8)).txt")
        let message = Data("sign me, then verify me".utf8)
        try message.write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let sigURL = try FileSigner.sign(inputURL: tmp, identity: identity)
        defer { FileSigner.cleanupTempFile(at: sigURL) }

        #expect(sigURL.lastPathComponent == tmp.lastPathComponent + ".sig")

        let armored = try String(contentsOf: sigURL, encoding: .utf8)
        let result = try SSHSigVerifier.verify(message: message, armoredSignature: armored)
        #expect(result.publicKeyWire == SSHSig.ed25519PublicKeyWire(pub))
        #expect(result.namespace == SSHSig.defaultNamespace)
    }

    /// An X25519 identity must be rejected: it can't sign.
    @Test func fileSignerRejectsX25519() async throws {
        let x = X25519Identity.generate()
        let identity = StoredIdentity(
            name: "age key",
            type: .x25519,
            publicKeyMaterial: x.publicKey,
            privateKeyMaterial: x.privateKey,
            sshComment: nil
        )
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-test-\(UUID().uuidString.prefix(8)).txt")
        try Data("x".utf8).write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        #expect(throws: FileSignerError.self) {
            _ = try FileSigner.sign(inputURL: tmp, identity: identity)
        }
    }

    // MARK: - FileVerifier (C1)

    /// Helper used by the C1 verifier tests: a fresh Ed25519 identity plus its
    /// raw seed/pub so the test can sign directly.
    private func makeEd25519Identity(name: String) -> (identity: StoredIdentity, seed: Data, pub: Data) {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let identity = StoredIdentity(
            name: name,
            type: .sshEd25519,
            publicKeyMaterial: SSHSig.ed25519PublicKeyWire(pub),
            privateKeyMaterial: seed + pub,
            sshComment: "agepony"
        )
        return (identity, seed, pub)
    }

    /// A signature from one of the user's own identities verifies as trusted.
    @Test func fileVerifierTrustsOwnIdentity() async throws {
        let (identity, seed, pub) = makeEd25519Identity(name: "Work key")
        let message = Data("attribute me to my own identity".utf8)
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub)

        let outcome = FileVerifier.verify(
            message: message,
            signatureText: sig,
            identities: [identity],
            recipients: []
        )
        #expect(outcome.trust == .trusted(signerName: "Work key", isOwnIdentity: true))
        #expect(outcome.signerKeyType == "ssh-ed25519")
        #expect(outcome.signerFingerprint?.hasPrefix("SHA256:") == true)
    }

    /// A signature from a key saved as a recipient verifies as trusted (not own).
    @Test func fileVerifierTrustsRecipient() async throws {
        let (_, seed, pub) = makeEd25519Identity(name: "ignored")
        let recipient = StoredRecipient(
            name: "Alice",
            type: .sshEd25519,
            publicKeyMaterial: SSHSig.ed25519PublicKeyWire(pub),
            source: .pasteSSH
        )
        let message = Data("from alice".utf8)
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub)

        let outcome = FileVerifier.verify(
            message: message,
            signatureText: sig,
            identities: [],
            recipients: [recipient]
        )
        #expect(outcome.trust == .trusted(signerName: "Alice", isOwnIdentity: false))
    }

    /// A valid signature from a key the vault doesn't know is "valid, unknown".
    @Test func fileVerifierValidUnknownKey() async throws {
        let (_, seed, pub) = makeEd25519Identity(name: "stranger")
        let message = Data("from a stranger".utf8)
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub)

        let outcome = FileVerifier.verify(
            message: message,
            signatureText: sig,
            identities: [],
            recipients: []
        )
        #expect(outcome.trust == .validUnknownKey)
        #expect(outcome.signerFingerprint?.hasPrefix("SHA256:") == true)
    }

    /// A signature that doesn't match the file is invalid.
    @Test func fileVerifierRejectsTamperedFile() async throws {
        let (identity, seed, pub) = makeEd25519Identity(name: "key")
        let sig = try SSHSigner.signEd25519(message: Data("original".utf8), seed: seed, publicKey: pub)

        let outcome = FileVerifier.verify(
            message: Data("tampered".utf8),
            signatureText: sig,
            identities: [identity],
            recipients: []
        )
        if case .invalid = outcome.trust {
            // expected
        } else {
            Issue.record("Expected .invalid for a mismatched file, got \(outcome.trust)")
        }
    }

    /// Garbage in the signature slot is reported as not-a-signature, not a crash.
    @Test func fileVerifierRejectsGarbage() async throws {
        let outcome = FileVerifier.verify(
            message: Data("x".utf8),
            signatureText: "this is not a signature",
            identities: [],
            recipients: []
        )
        if case .invalid = outcome.trust {
            // expected
        } else {
            Issue.record("Expected .invalid for garbage, got \(outcome.trust)")
        }
    }

    // MARK: - StoredSigner / trusted signers (C2)

    /// A StoredSigner round-trips through the allowed_signers format.
    @Test func storedSignerAllowedSignersRoundTrip() async throws {
        let (_, _, pub) = makeEd25519Identity(name: "ignored")
        let signer = StoredSigner(
            name: "alice@example.com",
            keyType: "ssh-ed25519",
            publicKeyWire: SSHSig.ed25519PublicKeyWire(pub),
            comment: "laptop",
            source: .pasteKey
        )
        let text = AllowedSigners.serialize([signer.toAllowedSigner()])
        let parsed = AllowedSigners.parse(text)
        #expect(parsed.count == 1)
        let back = StoredSigner.from(allowedSigner: parsed[0], source: .importAllowedSigners)
        #expect(back?.name == "alice@example.com")
        #expect(back?.publicKeyWire == signer.publicKeyWire)
        #expect(back?.keyType == "ssh-ed25519")
    }

    /// A signature from a key in the trusted-signers store attributes by name.
    @Test func fileVerifierTrustsSignerStore() async throws {
        let (_, seed, pub) = makeEd25519Identity(name: "ignored")
        let signer = StoredSigner(
            name: "Bob",
            keyType: "ssh-ed25519",
            publicKeyWire: SSHSig.ed25519PublicKeyWire(pub),
            source: .pasteKey
        )
        let message = Data("from bob".utf8)
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub)

        let outcome = FileVerifier.verify(
            message: message,
            signatureText: sig,
            identities: [],
            recipients: [],
            signers: [signer]
        )
        #expect(outcome.trust == .trusted(signerName: "Bob", isOwnIdentity: false))
        #expect(outcome.signerPublicKeyWire == SSHSig.ed25519PublicKeyWire(pub))
    }

    /// An unknown valid signer still exposes its wire blob so the UI can offer
    /// to add it as a trusted signer.
    @Test func fileVerifierUnknownExposesWire() async throws {
        let (_, seed, pub) = makeEd25519Identity(name: "stranger")
        let message = Data("unknown".utf8)
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub)
        let outcome = FileVerifier.verify(
            message: message,
            signatureText: sig,
            identities: [],
            recipients: [],
            signers: []
        )
        #expect(outcome.trust == .validUnknownKey)
        #expect(outcome.signerPublicKeyWire == SSHSig.ed25519PublicKeyWire(pub))
    }

    // MARK: - SignEncryptService (C3)

    /// Sign-then-encrypt: one file goes out, and what it decrypts to is a signed
    /// bundle whose signature covers the *plaintext*, not the ciphertext.
    @Test func signEncryptProducesOneFileCarryingItsSignature() async throws {
        let (signer, _, signerPub) = makeEd25519Identity(name: "Signer")
        let x = X25519Identity.generate()
        let recipient = try X25519Recipient(publicKey: x.publicKey)

        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-c3-\(UUID().uuidString.prefix(8)).bin")
        let plaintext = Data("hello combined".utf8)
        try plaintext.write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let out = try SignEncryptService.signEncrypt(
            inputURL: tmp,
            recipients: [recipient],
            passphrase: nil,
            armor: false,
            signingIdentity: signer
        )
        defer { FileEncryptor.cleanupTempFile(at: out.encryptedURL) }

        // One output, named after the input. No detached signature beside it.
        #expect(out.encryptedURL.lastPathComponent == tmp.lastPathComponent + ".age")
        #expect(out.payloadSize == Int64(plaintext.count))
        let siblings = try FileManager.default.contentsOfDirectory(
            atPath: out.encryptedURL.deletingLastPathComponent().path
        )
        #expect(siblings == [out.encryptedURL.lastPathComponent])

        // The ciphertext decrypts to a bundle, not to the plaintext directly.
        let ageBytes = try Data(contentsOf: out.encryptedURL)
        let inner = try Age.decrypt(ciphertext: ageBytes, identities: [x])
        #expect(inner != plaintext)
        #expect(SignedBundle.looksLikeBundle(inner))

        let bundle = try #require(SignedBundle.parse(inner))
        #expect(bundle.name == tmp.lastPathComponent)
        #expect(bundle.payload == plaintext)

        // The signature covers the plaintext.
        let v = try SSHSigVerifier.verify(
            message: plaintext,
            armoredSignature: bundle.signatureArmored,
            expectedNamespace: SSHSig.defaultNamespace
        )
        #expect(v.publicKeyWire == SSHSig.ed25519PublicKeyWire(signerPub))

        // And not the ciphertext -- the 2.0 shape is genuinely gone.
        #expect(throws: SSHSigError.signatureInvalid) {
            _ = try SSHSigVerifier.verify(
                message: ageBytes,
                armoredSignature: bundle.signatureArmored,
                expectedNamespace: SSHSig.defaultNamespace
            )
        }
    }

    /// An X25519 identity can't be a signing identity for the combined flow.
    @Test func signEncryptRejectsNonSigningIdentity() async throws {
        let x = X25519Identity.generate()
        let xIdentity = StoredIdentity(
            name: "age key",
            type: .x25519,
            publicKeyMaterial: x.publicKey,
            privateKeyMaterial: x.privateKey,
            sshComment: nil
        )
        let recipient = try X25519Recipient(publicKey: x.publicKey)
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-c3-\(UUID().uuidString.prefix(8)).bin")
        try Data("x".utf8).write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        #expect(throws: SignEncryptError.self) {
            _ = try SignEncryptService.signEncrypt(
                inputURL: tmp,
                recipients: [recipient],
                passphrase: nil,
                armor: false,
                signingIdentity: xIdentity
            )
        }
    }

    // MARK: - Sign-then-encrypt, all the way back (10c)

    /// The whole 3.0 shape end to end, through the real services: sign, encrypt,
    /// decrypt, verify.
    ///
    /// The encrypted file is renamed before decrypting, so the original filename
    /// can only come from the bundle's manifest -- stripping `.age` would give
    /// "opaque", not "quarterly report.pdf".
    @Test(arguments: [false, true])
    func signedFileDecryptsToItsPayloadAndVerifies(armor: Bool) async throws {
        let (signer, _, signerPub) = makeEd25519Identity(name: "Signer")
        let x = X25519Identity.generate()
        let recipient = try X25519Recipient(publicKey: x.publicKey)

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-10c-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let original = dir.appendingPathComponent("quarterly report.pdf")
        let plaintext = Data((0..<300_000).map { UInt8($0 % 251) })
        try plaintext.write(to: original)

        let out = try SignEncryptService.signEncrypt(
            inputURL: original,
            recipients: [recipient],
            passphrase: nil,
            armor: armor,
            signingIdentity: signer
        )
        defer { FileEncryptor.cleanupTempFile(at: out.encryptedURL) }

        // Launder the filename: whatever comes back now had to come from inside.
        let opaque = dir.appendingPathComponent("opaque.age")
        try FileManager.default.copyItem(at: out.encryptedURL, to: opaque)

        let outcome = try FileEncryptor.decrypt(
            inputURL: opaque, identities: [x], passphrase: nil
        )
        defer { FileEncryptor.cleanupTempFile(at: outcome.url) }

        #expect(outcome.isSigned)
        #expect(outcome.url.lastPathComponent == "quarterly report.pdf")
        let recovered = try Data(contentsOf: outcome.url)
        #expect(recovered == plaintext)

        // Attributed against the vault, from the streamed digests alone.
        let bundle = try #require(outcome.signedBundle)
        #expect(bundle.payloadSize == Int64(plaintext.count))
        let verdict = FileVerifier.verify(bundle: bundle, identities: [signer], recipients: [])
        #expect(verdict.trust == .trusted(signerName: "Signer", isOwnIdentity: true))
        #expect(verdict.signerPublicKeyWire == SSHSig.ed25519PublicKeyWire(signerPub))
    }

    /// An unsigned file is unaffected: no wrapper, no verdict, name derived from
    /// stripping `.age` as it always was. This is the 2.0-file path.
    @Test func plainEncryptedFileDecryptsWithNoSignature() async throws {
        let x = X25519Identity.generate()
        let recipient = try X25519Recipient(publicKey: x.publicKey)

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-10c-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let original = dir.appendingPathComponent("notes.txt")
        let plaintext = Data("nothing signed here".utf8)
        try plaintext.write(to: original)

        let encrypted = try FileEncryptor.encrypt(
            inputURL: original, recipients: [recipient], passphrase: nil, armor: false
        )
        defer { FileEncryptor.cleanupTempFile(at: encrypted) }

        let outcome = try FileEncryptor.decrypt(
            inputURL: encrypted, identities: [x], passphrase: nil
        )
        defer { FileEncryptor.cleanupTempFile(at: outcome.url) }

        #expect(!outcome.isSigned)
        #expect(outcome.signedBundle == nil)
        #expect(outcome.url.lastPathComponent == "notes.txt")
        let recovered = try Data(contentsOf: outcome.url)
        #expect(recovered == plaintext)
    }

    /// Re-encrypting must not strip a signature, so the migrate path decrypts with
    /// the bundle left whole.
    @Test func decryptCanLeaveTheBundleWrapped() async throws {
        let (signer, _, _) = makeEd25519Identity(name: "Signer")
        let x = X25519Identity.generate()
        let recipient = try X25519Recipient(publicKey: x.publicKey)

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-10c-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let original = dir.appendingPathComponent("memo.txt")
        let plaintext = Data("keep the signature".utf8)
        try plaintext.write(to: original)

        let out = try SignEncryptService.signEncrypt(
            inputURL: original,
            recipients: [recipient],
            passphrase: nil,
            armor: false,
            signingIdentity: signer
        )
        defer { FileEncryptor.cleanupTempFile(at: out.encryptedURL) }

        let outcome = try FileEncryptor.decrypt(
            inputURL: out.encryptedURL,
            identities: [x],
            passphrase: nil,
            unwrapSignedBundle: false
        )
        defer { FileEncryptor.cleanupTempFile(at: outcome.url) }

        // No verdict, because nothing was unwrapped -- but the bundle is intact on
        // disk, ready to be re-encrypted with its signature still inside.
        #expect(outcome.signedBundle == nil)
        let onDisk = try Data(contentsOf: outcome.url)
        #expect(SignedBundle.looksLikeBundle(onDisk))
        let bundle = try #require(SignedBundle.parse(onDisk))
        #expect(bundle.name == "memo.txt")
        #expect(bundle.payload == plaintext)
    }
}
