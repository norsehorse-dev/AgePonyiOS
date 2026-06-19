//
//  SSHKeyTests.swift
//  AgePonyCoreTests
//
//  Parser tests using synthesized SSH key blobs. We can't ship hardcoded test
//  vectors (since SSH key generation depends on a CSPRNG and we have no test
//  fixture files), so we round-trip: build a key blob ourselves, parse it,
//  and verify the parsed structure matches what we put in.
//
//  Cross-implementation validation against keys actually produced by
//  `ssh-keygen -t ed25519` is covered indirectly by ReferenceCLITests, which
//  uses keys the age CLI accepts.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class SSHKeyTests: XCTestCase {

    // MARK: - Test helpers (format builders)

    /// Build an `ssh-ed25519 BASE64 [comment]` line from a 32-byte public key.
    static func makeSSHPublicKeyLine(pub: Data, comment: String?) -> String {
        var w = SSHWireWriter()
        w.writeString("ssh-ed25519")
        w.writeString(pub)
        let b64 = w.data.base64EncodedString()
        if let c = comment {
            return "ssh-ed25519 \(b64) \(c)"
        }
        return "ssh-ed25519 \(b64)"
    }

    /// Build an unencrypted OpenSSH private key PEM from a 32-byte seed + 32-byte pub.
    static func makeOpenSSHPrivateKeyPEM(seed: Data, pub: Data, comment: String) -> String {
        // Inner public-key blob (the same as the .pub format).
        var pubW = SSHWireWriter()
        pubW.writeString("ssh-ed25519")
        pubW.writeString(pub)
        let publicBlob = pubW.data

        // Inner private section.
        var privW = SSHWireWriter()
        let checkInt: UInt32 = 0xdead_beef
        privW.writeUInt32(checkInt)
        privW.writeUInt32(checkInt)
        privW.writeString("ssh-ed25519")
        privW.writeString(pub)
        privW.writeString(seed + pub)  // 64 bytes
        privW.writeString(comment)
        // Pad to multiple of 8 (block size for "none" cipher is taken as 8).
        var padIdx: UInt8 = 1
        while privW.data.count % 8 != 0 {
            privW.writeByte(padIdx)
            padIdx += 1
        }
        let privateBlob = privW.data

        // Top-level OpenSSH blob.
        var top = Data("openssh-key-v1\0".utf8)
        var meta = SSHWireWriter()
        meta.writeString("none")             // cipher
        meta.writeString("none")             // kdf
        meta.writeString(Data())             // kdf options
        meta.writeUInt32(1)                  // num keys
        meta.writeString(publicBlob)
        meta.writeString(privateBlob)
        top.append(meta.data)

        let b64 = top.base64EncodedString()
        // PEM line-wrap at 70 cols (OpenSSH convention).
        var wrapped = ""
        var idx = b64.startIndex
        while idx < b64.endIndex {
            let end = b64.index(idx, offsetBy: 70, limitedBy: b64.endIndex) ?? b64.endIndex
            wrapped += b64[idx..<end] + "\n"
            idx = end
        }

        return """
        -----BEGIN OPENSSH PRIVATE KEY-----
        \(wrapped)-----END OPENSSH PRIVATE KEY-----
        """
    }

    // MARK: - Public key parsing

    func testParseSSHPublicKey_basic() throws {
        let pub = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let line = Self.makeSSHPublicKeyLine(pub: pub, comment: "user@host")

        let parsed = try SSHKey.parsePublicKey(line)
        guard case .ed25519(let parsedPub) = parsed.type else {
            return XCTFail("Expected ed25519 key type")
        }
        XCTAssertEqual(parsedPub, pub)
        XCTAssertEqual(parsed.comment, "user@host")
    }

    func testParseSSHPublicKey_noComment() throws {
        let pub = Data(repeating: 0xab, count: 32)
        let line = Self.makeSSHPublicKeyLine(pub: pub, comment: nil)
        let parsed = try SSHKey.parsePublicKey(line)
        guard case .ed25519(let parsedPub) = parsed.type else {
            return XCTFail("Expected ed25519")
        }
        XCTAssertEqual(parsedPub, pub)
        XCTAssertNil(parsed.comment)
    }

    func testParseSSHPublicKey_multiWordComment() throws {
        let pub = Data(repeating: 0x77, count: 32)
        let line = Self.makeSSHPublicKeyLine(pub: pub, comment: "Kevin's Laptop 2026")
        let parsed = try SSHKey.parsePublicKey(line)
        XCTAssertEqual(parsed.comment, "Kevin's Laptop 2026")
    }

    func testParseSSHPublicKey_rejectsMalformed() {
        XCTAssertThrowsError(try SSHKey.parsePublicKey(""))
        XCTAssertThrowsError(try SSHKey.parsePublicKey("ssh-ed25519"))
        XCTAssertThrowsError(try SSHKey.parsePublicKey("not-base64-data!!!"))
        XCTAssertThrowsError(try SSHKey.parsePublicKey("ssh-ed25519 not-valid-base64-data"))
    }

    func testParseSSHPublicKey_rejectsUnknownType() throws {
        // Build an ssh-rsa-looking line (type unsupported in this slice).
        var w = SSHWireWriter()
        w.writeString("ssh-rsa")
        w.writeString(Data(repeating: 0x01, count: 5))
        let b64 = w.data.base64EncodedString()
        let line = "ssh-rsa \(b64)"
        XCTAssertThrowsError(try SSHKey.parsePublicKey(line)) { err in
            guard case SSHKeyError.unsupportedKeyType(let t) = err else {
                return XCTFail("Wrong error: \(err)")
            }
            XCTAssertEqual(t, "ssh-rsa")
        }
    }

    func testParseSSHPublicKey_rejectsWireBlobMismatch() throws {
        // Build a line where the prefix says "ssh-ed25519" but the wire blob
        // says something different. The parser must catch this.
        var w = SSHWireWriter()
        w.writeString("ssh-rsa")  // wrong type inside the blob
        w.writeString(Data(repeating: 0x01, count: 32))
        let b64 = w.data.base64EncodedString()
        let line = "ssh-ed25519 \(b64) c"
        XCTAssertThrowsError(try SSHKey.parsePublicKey(line))
    }

    // MARK: - Private key parsing

    func testParseOpenSSHPrivateKey_basic() throws {
        // Generate a real Ed25519 keypair via CryptoKit so seed and pub agree.
        let key = Curve25519.Signing.PrivateKey()
        let seed = key.rawRepresentation
        let pub = key.publicKey.rawRepresentation

        let pem = Self.makeOpenSSHPrivateKeyPEM(seed: seed, pub: pub, comment: "test@agepony")
        let parsed = try SSHKey.parseOpenSSHPrivateKey(pem)
        guard case .ed25519(let parsedSeed, let parsedPub) = parsed.type else {
            return XCTFail("Expected ed25519")
        }
        XCTAssertEqual(parsedSeed, seed)
        XCTAssertEqual(parsedPub, pub)
        XCTAssertEqual(parsed.comment, "test@agepony")
    }

    func testParseOpenSSHPrivateKey_acceptsCRLF() throws {
        let key = Curve25519.Signing.PrivateKey()
        let pem = Self.makeOpenSSHPrivateKeyPEM(
            seed: key.rawRepresentation,
            pub: key.publicKey.rawRepresentation,
            comment: "host"
        )
        let crlf = pem.replacingOccurrences(of: "\n", with: "\r\n")
        XCTAssertNoThrow(try SSHKey.parseOpenSSHPrivateKey(crlf))
    }

    func testParseOpenSSHPrivateKey_rejectsMissingFraming() {
        XCTAssertThrowsError(try SSHKey.parseOpenSSHPrivateKey("not a key"))
        XCTAssertThrowsError(try SSHKey.parseOpenSSHPrivateKey(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
        ))
    }

    func testParseOpenSSHPrivateKey_rejectsInvalidBase64() {
        let bad = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        !!!not-base64-data!!!
        -----END OPENSSH PRIVATE KEY-----
        """
        XCTAssertThrowsError(try SSHKey.parseOpenSSHPrivateKey(bad))
    }
}
