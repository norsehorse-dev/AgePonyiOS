//
//  AllowedSignersTests.swift
//  AgePonyCoreTests
//
//  Tests for parsing and serializing the OpenSSH allowed_signers format and
//  the principal+key matching used by the trusted-signers store.
//

import XCTest
@testable import AgePonyCore

final class AllowedSignersTests: XCTestCase {

    private let edKeyB64 =
        "AAAAC3NzaC1lZDI1NTE5AAAAILr/NVvNaGxfkVp8Ni/Z3ubM8/k89JoVOg8oMJeid1tU"

    func testParseSimpleLine() {
        let line = "alice@example.com ssh-ed25519 \(edKeyB64)"
        let signers = AllowedSigners.parse(line)
        XCTAssertEqual(signers.count, 1)
        XCTAssertEqual(signers[0].principals, ["alice@example.com"])
        XCTAssertNil(signers[0].options)
        XCTAssertEqual(signers[0].keyType, "ssh-ed25519")
        XCTAssertEqual(signers[0].keyBase64, edKeyB64)
        XCTAssertNil(signers[0].comment)
    }

    func testParseMultiplePrincipals() {
        let line = "alice@example.com,bob@example.com ssh-ed25519 \(edKeyB64) team key"
        let s = AllowedSigners.parse(line)[0]
        XCTAssertEqual(s.principals, ["alice@example.com", "bob@example.com"])
        XCTAssertEqual(s.comment, "team key")
    }

    func testParseWithOptions() {
        let line = "alice@example.com namespaces=\"agepony\" ssh-ed25519 \(edKeyB64)"
        let s = AllowedSigners.parse(line)[0]
        XCTAssertEqual(s.options, "namespaces=\"agepony\"")
        XCTAssertEqual(s.keyType, "ssh-ed25519")
        XCTAssertEqual(s.keyBase64, edKeyB64)
    }

    func testSkipsCommentsAndBlanks() {
        let text = """
        # this is a comment

        alice@example.com ssh-ed25519 \(edKeyB64)
        # another comment
        """
        XCTAssertEqual(AllowedSigners.parse(text).count, 1)
    }

    func testSkipsUnparseableLines() {
        let text = """
        garbage line with no key
        alice@example.com ssh-ed25519 \(edKeyB64)
        bob ecdsa-sha2-nistp256 not-valid-base64-!!!
        """
        // Only alice's line is well-formed.
        let signers = AllowedSigners.parse(text)
        XCTAssertEqual(signers.count, 1)
        XCTAssertEqual(signers[0].principals, ["alice@example.com"])
    }

    func testSerializeRoundTrip() {
        let original = AllowedSigner(
            principals: ["alice@example.com", "bob@example.com"],
            options: "namespaces=\"agepony\"",
            keyType: "ssh-ed25519",
            keyBase64: edKeyB64,
            comment: "shared key"
        )
        let text = AllowedSigners.serialize([original])
        let parsed = AllowedSigners.parse(text)
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(parsed[0], original)
    }

    func testMatches() {
        let s = AllowedSigners.parse("alice@example.com ssh-ed25519 \(edKeyB64)")[0]
        let wire = Data(base64Encoded: edKeyB64)!
        XCTAssertTrue(s.matches(principal: "alice@example.com", publicKeyWire: wire))
        // Wrong principal.
        XCTAssertFalse(s.matches(principal: "eve@example.com", publicKeyWire: wire))
        // Wrong key.
        XCTAssertFalse(s.matches(principal: "alice@example.com", publicKeyWire: Data([0x00])))
    }

    func testPublicKeyWireDecodes() {
        let s = AllowedSigners.parse("alice@example.com ssh-ed25519 \(edKeyB64)")[0]
        XCTAssertEqual(s.publicKeyWire, Data(base64Encoded: edKeyB64))
    }

    func testMakeSignerFromPubLine() {
        let pubLine = "ssh-ed25519 \(edKeyB64) agepony-test@norsehor.se"
        let signer = AllowedSigners.makeSigner(
            principals: ["alice@example.com"],
            sshPublicKeyLine: pubLine,
            namespaceRestricted: true
        )
        XCTAssertNotNil(signer)
        XCTAssertEqual(signer?.keyType, "ssh-ed25519")
        XCTAssertEqual(signer?.keyBase64, edKeyB64)
        XCTAssertEqual(signer?.comment, "agepony-test@norsehor.se")
        XCTAssertEqual(signer?.options, "namespaces=\"agepony\"")
    }

    func testMakeSignerRejectsBadLine() {
        XCTAssertNil(AllowedSigners.makeSigner(
            principals: ["x"],
            sshPublicKeyLine: "not-a-key"
        ))
    }
}
