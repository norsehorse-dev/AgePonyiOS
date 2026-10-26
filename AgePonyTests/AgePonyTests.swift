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

    /// A signature from a key saved only as a recipient is valid but not trusted
    /// (5.0.1, audit M-9): recipients are never trusted as signers.
    @Test func fileVerifierDoesNotTrustRecipient() async throws {
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
        #expect(outcome.trust == .validUnknownKey)
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

    // MARK: - SignEncryptService (C3, 5.0.1 formats)

    /// Sign-then-encrypt to a key: one file goes out, and it is a plain age file
    /// (plain age returns the original bytes) carrying a v2 signature stanza over
    /// the plaintext and the recipient stanzas (5.0.1, audit L-8).
    @Test func signEncryptToKeyWritesSignatureStanzaV2() async throws {
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

        // Plain age gives back the bytes themselves, with no wrapper.
        let ageBytes = try Data(contentsOf: out.encryptedURL)
        let recovered = try Age.decryptAndRecoverSignature(ciphertext: ageBytes, identities: [x])
        #expect(recovered.plaintext == plaintext)

        // The header's signature stanza is v2 and verifies over that plaintext.
        let opened = try #require(recovered.signature.opened)
        #expect(opened.version == 2)
        #expect(opened.coversRecipients)
        let v = try opened.verify(plaintext: plaintext)
        #expect(v.publicKeyWire == SSHSig.ed25519PublicKeyWire(signerPub))
        #expect(v.namespace == SignatureStanza.namespaceV2)
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

    // MARK: - Sign-then-encrypt, all the way back (10c, 5.0.1)

    /// Signed to a key, end to end through the real services: the decrypt outcome
    /// carries the stanza, and FileVerifier attributes it from the written file.
    @Test(arguments: [false, true])
    func signedToKeyDecryptsAndVerifies(armor: Bool) async throws {
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

        let outcome = try FileEncryptor.decrypt(
            inputURL: out.encryptedURL, identities: [x], passphrase: nil
        )
        defer { FileEncryptor.cleanupTempFile(at: outcome.url) }

        #expect(outcome.isSigned)
        #expect(outcome.signedBundle == nil)
        #expect(outcome.url.lastPathComponent == "quarterly report.pdf")
        #expect(try Data(contentsOf: outcome.url) == plaintext)

        let verdict = try #require(FileVerifier.verify(
            stanza: outcome.signatureStanza, plaintextURL: outcome.url, identities: [signer], recipients: []
        ))
        #expect(verdict.trust == .trusted(signerName: "Signer", isOwnIdentity: true))
        #expect(verdict.signerPublicKeyWire == SSHSig.ed25519PublicKeyWire(signerPub))
        #expect(verdict.note == nil)
    }

    /// Signed with a passphrase: a v2 bundle, whose signature also covers the name.
    /// The encrypted file is renamed before decrypting, so the original filename can
    /// only come from the bundle's manifest.
    @Test func signedWithPassphraseIsBundleV2AndVerifies() async throws {
        let (signer, _, _) = makeEd25519Identity(name: "Signer")

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-10c-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let original = dir.appendingPathComponent("memo.txt")
        let plaintext = Data("signed with a passphrase".utf8)
        try plaintext.write(to: original)

        let out = try SignEncryptService.signEncrypt(
            inputURL: original,
            recipients: [],
            passphrase: "correct horse battery staple",
            armor: false,
            signingIdentity: signer,
            workFactor: 16
        )
        defer { FileEncryptor.cleanupTempFile(at: out.encryptedURL) }

        let opaque = dir.appendingPathComponent("opaque.age")
        try FileManager.default.copyItem(at: out.encryptedURL, to: opaque)

        let outcome = try FileEncryptor.decrypt(
            inputURL: opaque, identities: [], passphrase: "correct horse battery staple"
        )
        defer { FileEncryptor.cleanupTempFile(at: outcome.url) }

        let bundle = try #require(outcome.signedBundle)
        #expect(bundle.version == 2)
        #expect(bundle.nameCovered)
        #expect(outcome.url.lastPathComponent == "memo.txt")
        #expect(try Data(contentsOf: outcome.url) == plaintext)
        let verdict = FileVerifier.verify(bundle: bundle, identities: [signer], recipients: [])
        #expect(verdict.trust == .trusted(signerName: "Signer", isOwnIdentity: true))
        #expect(verdict.note == nil)
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
    /// a bundle (passphrase files) left whole.
    @Test func decryptCanLeaveTheBundleWrapped() async throws {
        let (signer, _, _) = makeEd25519Identity(name: "Signer")

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-10c-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let original = dir.appendingPathComponent("memo.txt")
        let plaintext = Data("keep the signature".utf8)
        try plaintext.write(to: original)

        let out = try SignEncryptService.signEncrypt(
            inputURL: original,
            recipients: [],
            passphrase: "keep it whole please",
            armor: false,
            signingIdentity: signer,
            workFactor: 16
        )
        defer { FileEncryptor.cleanupTempFile(at: out.encryptedURL) }

        let outcome = try FileEncryptor.decrypt(
            inputURL: out.encryptedURL,
            identities: [],
            passphrase: "keep it whole please",
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

    /// A key-signed file can't be migrated to new recipients: its v2 signature
    /// covers the old ones, and dropping it quietly would lose provenance.
    @Test func migrateRefusesASignatureStanzaFile() async throws {
        let (signer, _, _) = makeEd25519Identity(name: "Signer")
        let x = X25519Identity.generate()
        let other = X25519Identity.generate()

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-mig-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = dir.appendingPathComponent("a.txt")
        try Data("signed".utf8).write(to: original)

        let out = try SignEncryptService.signEncrypt(
            inputURL: original,
            recipients: [try X25519Recipient(publicKey: x.publicKey)],
            passphrase: nil,
            armor: false,
            signingIdentity: signer
        )
        defer { FileEncryptor.cleanupTempFile(at: out.encryptedURL) }

        #expect(throws: MigrateError.signatureWouldBeLost) {
            _ = try MigrateService.migrate(
                inputURL: out.encryptedURL,
                identities: [x],
                passphrase: nil,
                to: [try X25519Recipient(publicKey: other.publicKey)],
                armor: false
            )
        }
    }
}
