import XCTest
@testable import AgePonyCore

/// Cross-implementation tests against the reference `age` CLI for ssh-rsa stanzas.
/// Mirror of the ssh-ed25519 cross-impl tests in `ReferenceCLITests.swift`. Skipped if
/// the `age` binary is not found on disk.
final class ReferenceCLIRSATests: XCTestCase {

    private func ageBinary() -> URL? {
        let candidates = [
            "/opt/homebrew/bin/age",
            "/usr/local/bin/age",
            "/usr/bin/age",
        ]
        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                return URL(fileURLWithPath: path)
            }
        }
        return nil
    }

    private struct ProcessResult {
        let status: Int32
        let stdout: Data
        let stderr: String
    }

    private func runProcess(url: URL, arguments: [String], stdin: Data? = nil) throws -> ProcessResult {
        let proc = Process()
        proc.executableURL = url
        proc.arguments = arguments
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        if let stdin = stdin {
            let inPipe = Pipe()
            proc.standardInput = inPipe
            try proc.run()
            inPipe.fileHandleForWriting.write(stdin)
            try inPipe.fileHandleForWriting.close()
        } else {
            try proc.run()
        }
        let stdout = outPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = errPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return ProcessResult(
            status: proc.terminationStatus,
            stdout: stdout,
            stderr: String(data: stderrData, encoding: .utf8) ?? ""
        )
    }

    private func tempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agepony-rsa-test-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// AgePony encrypts to an ssh-rsa recipient, the age CLI decrypts using the matching private key.
    func test_AgePonyEncrypt_ReferenceDecrypt_SSHRSA() throws {
        guard let age = ageBinary() else {
            throw XCTSkip("`age` binary not found on PATH or in standard locations")
        }
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let keyPath = dir.appendingPathComponent("id_rsa")
        try RSAKeyTests.testPrivPEM.write(to: keyPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: keyPath.path
        )

        let plaintext = Data("hello from AgePony ssh-rsa\n".utf8)
        let recipient = try SSHRSARecipient(sshPublicKeyLine: RSAKeyTests.testPubLine)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])

        let result = try runProcess(
            url: age,
            arguments: ["-d", "-i", keyPath.path],
            stdin: ciphertext
        )
        XCTAssertEqual(result.status, 0, "age decrypt failed: \(result.stderr)")
        XCTAssertEqual(result.stdout, plaintext)
    }

    /// The age CLI encrypts to the ssh-rsa public line; AgePony decrypts with the matching private key.
    func test_ReferenceEncrypt_AgePonyDecrypt_SSHRSA() throws {
        guard let age = ageBinary() else {
            throw XCTSkip("`age` binary not found on PATH or in standard locations")
        }
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let pubPath = dir.appendingPathComponent("id_rsa.pub")
        try RSAKeyTests.testPubLine.write(to: pubPath, atomically: true, encoding: .utf8)

        let plaintext = Data("hello from age CLI ssh-rsa\n".utf8)

        let result = try runProcess(
            url: age,
            arguments: ["-R", pubPath.path],
            stdin: plaintext
        )
        XCTAssertEqual(result.status, 0, "age encrypt failed: \(result.stderr)")

        let identity = try SSHRSAIdentity(openSSHPrivateKey: RSAKeyTests.testPrivPEM)
        let recovered = try Age.decrypt(ciphertext: result.stdout, identities: [identity])
        XCTAssertEqual(recovered, plaintext)
    }
}
