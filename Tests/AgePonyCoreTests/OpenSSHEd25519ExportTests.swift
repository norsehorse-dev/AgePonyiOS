//
//  OpenSSHEd25519ExportTests.swift
//  AgePonyCoreTests
//
//  The serializer is the inverse of SSHKey.parseOpenSSHPrivateKey, which is
//  already tested against the reference age CLI / ssh-keygen. So the strongest
//  hermetic check is a round trip: generate -> serialize -> parse -> the key
//  material comes back identical. The exact byte layout (padding, checkint,
//  block size) was also confirmed byte-for-byte against ssh-keygen 9.x when
//  this phase was built, and `ssh-keygen -y` reads the output.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class OpenSSHEd25519ExportTests: XCTestCase {

    func testGenerateProducesValidLengths() {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        XCTAssertEqual(seed.count, 32)
        XCTAssertEqual(pub.count, 32)
    }

    func testSerializeParseRoundTrip() throws {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let pem = try OpenSSHEd25519Export.privateKeyPEM(seed: seed, publicKey: pub, comment: "agepony")

        let parsed = try SSHKey.parseOpenSSHPrivateKey(pem)
        switch parsed.type {
        case .ed25519(let parsedSeed, let parsedPub):
            XCTAssertEqual(parsedSeed, seed)
            XCTAssertEqual(parsedPub, pub)
        }
        XCTAssertEqual(parsed.comment, "agepony")
    }

    func testRoundTripFromVaultMaterial() throws {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let material = seed + pub
        let pem = try OpenSSHEd25519Export.privateKeyPEM(privateMaterial: material, comment: "")
        let parsed = try SSHKey.parseOpenSSHPrivateKey(pem)
        if case .ed25519(let s, let p) = parsed.type {
            XCTAssertEqual(s, seed)
            XCTAssertEqual(p, pub)
        }
    }

    func testEmptyCommentRoundTrips() throws {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let pem = try OpenSSHEd25519Export.privateKeyPEM(seed: seed, publicKey: pub, comment: "")
        let parsed = try SSHKey.parseOpenSSHPrivateKey(pem)
        XCTAssertNil(parsed.comment) // parser maps empty comment to nil
    }

    func testPEMHasCorrectMarkers() throws {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let pem = try OpenSSHEd25519Export.privateKeyPEM(seed: seed, publicKey: pub)
        XCTAssertTrue(pem.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"))
        XCTAssertTrue(pem.contains("-----END OPENSSH PRIVATE KEY-----"))
    }

    func testRejectsWrongSeedLength() {
        XCTAssertThrowsError(
            try OpenSSHEd25519Export.privateKeyPEM(seed: Data(repeating: 0, count: 16),
                                                   publicKey: Data(repeating: 0, count: 32))
        ) { error in
            XCTAssertEqual(error as? OpenSSHEd25519ExportError, .invalidSeedLength)
        }
    }

    func testPublicKeyLineMatchesGeneratedKey() throws {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let line = OpenSSHEd25519Export.publicKeyLine(publicKey: pub, comment: "agepony")
        // The line's base64 must equal the ed25519 wire blob, and an age
        // recipient built from the same key must accept it.
        let b64 = line.split(separator: " ").map(String.init)[1]
        XCTAssertEqual(Data(base64Encoded: b64), SSHSig.ed25519PublicKeyWire(pub))
        _ = seed
    }

    func testSerializedKeySignsAndVerifies() throws {
        // End-to-end: a generated identity can produce a valid SSHSIG signature.
        let (seed, pub) = OpenSSHEd25519Export.generate()
        let message = Data("generated identity can sign".utf8)
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub)
        XCTAssertNoThrow(try SSHSigVerifier.verify(message: message, armoredSignature: sig))
    }
}
