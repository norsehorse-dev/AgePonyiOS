//
//  ReferenceCLITests.swift
//  AgePonyCoreTests
//
//  Cross-implementation compatibility tests against Filippo's reference `age` CLI.
//
//  These tests are SKIPPED automatically if the `age` binary isn't found in
//  one of the standard locations (Homebrew on Apple Silicon / Intel, or /usr/bin).
//  To enable on macOS:
//
//      brew install age
//
//  These are the only tests that prove our wire format actually interoperates
//  with the reference impl. Self-round-trip tests pass even if both sides
//  share the same bug.
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

final class ReferenceCLITests: XCTestCase {

    /// Find the `age` binary, or return nil if missing.
    private func ageBinary() -> URL? {
        let candidates = [
            "/opt/homebrew/bin/age",     // Apple Silicon Homebrew
            "/usr/local/bin/age",        // Intel Homebrew
            "/usr/bin/age",              // system
        ]
        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                return URL(fileURLWithPath: path)
            }
        }
        return nil
    }

    private func runProcess(
        url: URL,
        arguments: [String],
        stdin: Data? = nil
    ) throws -> (stdout: Data, stderr: Data, status: Int32) {
        let proc = Process()
        proc.executableURL = url
        proc.arguments = arguments
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        let stdinPipe = Pipe()
        proc.standardOutput = stdoutPipe
        proc.standardError = stderrPipe
        proc.standardInput = stdinPipe

        try proc.run()
        if let stdin {
            try stdinPipe.fileHandleForWriting.write(contentsOf: stdin)
        }
        try stdinPipe.fileHandleForWriting.close()

        let outData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return (outData, errData, proc.terminationStatus)
    }

    // MARK: - Encrypt with AgePony, decrypt with reference CLI

    func test_AgePonyEncrypt_ReferenceDecrypt_X25519() throws {
        guard let age = ageBinary() else {
            throw XCTSkip("age CLI not installed; install with: brew install age")
        }
        let identity = X25519Identity.generate()
        let plaintext = Data("Round-trip via AgePony → reference age CLI\n".utf8)
        let recipient = try X25519Recipient(ageRecipient: identity.ageRecipient)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])

        // Write identity to a temp file so `age -d -i <file>` can read it.
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-test-\(UUID().uuidString).key")
        try identity.ageIdentityString.write(to: tmp, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let result = try runProcess(
            url: age,
            arguments: ["-d", "-i", tmp.path],
            stdin: ciphertext
        )
        XCTAssertEqual(result.status, 0,
                       "age CLI exited \(result.status); stderr=\(String(data: result.stderr, encoding: .utf8) ?? "")")
        XCTAssertEqual(result.stdout, plaintext)
    }

    // MARK: - Encrypt with reference CLI, decrypt with AgePony

    func test_ReferenceEncrypt_AgePonyDecrypt_X25519() throws {
        guard let age = ageBinary() else {
            throw XCTSkip("age CLI not installed; install with: brew install age")
        }
        let identity = X25519Identity.generate()
        let plaintext = Data("Round-trip via reference age CLI → AgePony\n".utf8)

        let result = try runProcess(
            url: age,
            arguments: ["-r", identity.ageRecipient],
            stdin: plaintext
        )
        XCTAssertEqual(result.status, 0,
                       "age CLI exited \(result.status); stderr=\(String(data: result.stderr, encoding: .utf8) ?? "")")
        let ciphertext = result.stdout
        XCTAssertGreaterThan(ciphertext.count, 0)

        let decrypted = try Age.decrypt(ciphertext: ciphertext, identities: [identity])
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Passphrase round-trip

    func test_ReferenceEncrypt_AgePonyDecrypt_Passphrase() throws {
        guard ageBinary() != nil else {
            throw XCTSkip("age CLI not installed; install with: brew install age")
        }
        // The reference CLI normally prompts for the passphrase on stdin's TTY.
        // It doesn't support env-var passphrase input either, so a non-interactive
        // round-trip via stdin pipes isn't cleanly possible.
        //
        // Passphrase correctness is covered by the RFC 7914 vectors plus self
        // round-trip. The wire-format compatibility check via the X25519 tests
        // above already proves our header/payload structure is correct, and the
        // scrypt stanza shares the same header/payload pipeline.
        throw XCTSkip("CLI passphrase round-trip requires TTY; covered by RFC vectors + self round-trip")
    }

    // MARK: - Armored output via the CLI

    func test_ReferenceArmoredEncrypt_AgePonyDecrypt() throws {
        guard let age = ageBinary() else {
            throw XCTSkip("age CLI not installed; install with: brew install age")
        }
        let identity = X25519Identity.generate()
        let plaintext = Data("armored compat\n".utf8)

        let result = try runProcess(
            url: age,
            arguments: ["-a", "-r", identity.ageRecipient],
            stdin: plaintext
        )
        XCTAssertEqual(result.status, 0,
                       "stderr=\(String(data: result.stderr, encoding: .utf8) ?? "")")
        let armored = String(data: result.stdout, encoding: .utf8) ?? ""
        XCTAssertTrue(armored.contains("-----BEGIN AGE ENCRYPTED FILE-----"))

        let binary = try AgeArmor.decode(armored)
        let decrypted = try Age.decrypt(ciphertext: binary, identities: [identity])
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - SSH Ed25519 round-trips

    /// AgePony encrypts to an SSH Ed25519 pubkey; reference CLI decrypts with the
    /// matching OpenSSH private key file.
    func test_AgePonyEncrypt_ReferenceDecrypt_SSHEd25519() throws {
        guard let age = ageBinary() else {
            throw XCTSkip("age CLI not installed; install with: brew install age")
        }
        let edKey = Curve25519.Signing.PrivateKey()
        let seed = edKey.rawRepresentation
        let pub = edKey.publicKey.rawRepresentation

        // Build AgePony recipient.
        let recipient = try SSHEd25519Recipient(edPublicKey: pub)
        let plaintext = Data("AgePony → reference age, ssh-ed25519\n".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])

        // Write OpenSSH private key file for the reference CLI to use as identity.
        let pem = SSHKeyTests.makeOpenSSHPrivateKeyPEM(seed: seed, pub: pub, comment: "test")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-test-ssh-\(UUID().uuidString).key")
        try pem.write(to: tmp, atomically: true, encoding: .utf8)
        // OpenSSH private key files should be mode 0600; age may refuse otherwise.
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: tmp.path
        )
        defer { try? FileManager.default.removeItem(at: tmp) }

        let result = try runProcess(
            url: age,
            arguments: ["-d", "-i", tmp.path],
            stdin: ciphertext
        )
        XCTAssertEqual(result.status, 0,
                       "age CLI exited \(result.status); stderr=\(String(data: result.stderr, encoding: .utf8) ?? "")")
        XCTAssertEqual(result.stdout, plaintext)
    }

    /// Reference CLI encrypts to an SSH Ed25519 pubkey; AgePony decrypts with the
    /// matching identity.
    func test_ReferenceEncrypt_AgePonyDecrypt_SSHEd25519() throws {
        guard let age = ageBinary() else {
            throw XCTSkip("age CLI not installed; install with: brew install age")
        }
        let edKey = Curve25519.Signing.PrivateKey()
        let seed = edKey.rawRepresentation
        let pub = edKey.publicKey.rawRepresentation

        // Build the recipient string in the SSH public key text format.
        let recipientLine = SSHKeyTests.makeSSHPublicKeyLine(pub: pub, comment: "test")

        let plaintext = Data("reference age → AgePony, ssh-ed25519\n".utf8)
        let result = try runProcess(
            url: age,
            arguments: ["-r", recipientLine],
            stdin: plaintext
        )
        XCTAssertEqual(result.status, 0,
                       "age CLI exited \(result.status); stderr=\(String(data: result.stderr, encoding: .utf8) ?? "")")
        let ciphertext = result.stdout
        XCTAssertGreaterThan(ciphertext.count, 0)

        let identity = try SSHEd25519Identity(edSeed: seed, edPublicKey: pub)
        let decrypted = try Age.decrypt(ciphertext: ciphertext, identities: [identity])
        XCTAssertEqual(decrypted, plaintext)
    }
}
