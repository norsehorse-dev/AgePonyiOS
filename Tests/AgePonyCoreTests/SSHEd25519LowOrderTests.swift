//
//  SSHEd25519LowOrderTests.swift
//  AgePonyCoreTests
//
//  5.1.1 (M-1): a small-order ssh-ed25519 key converts to a low-order X25519
//  point. CryptoKit returns an all-zero shared secret for such a point instead
//  of throwing, so without a check a file encrypted to the key could be opened
//  by anyone. These pin the refusal at every step.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class SSHEd25519LowOrderTests: XCTestCase {

    /// y = p-1 (order 2); converts to Montgomery u = 0.
    private var yIsPMinus1: Data {
        var d = Data(repeating: 0xFF, count: 32)
        d[0] = 0xEC; d[31] = 0x7F
        return d
    }

    /// 32 zero bytes: y = 0 (order 4); converts to u = 1.
    private var allZero: Data { Data(count: 32) }

    /// A point of order 8 (from the usual small-order blocklist).
    private var orderEight: Data {
        Data([0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
              0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05])
    }

    func testCryptoKitBehaviourForALowOrderPoint() throws {
        // Records what CryptoKit does today. AgePony refuses either way; if this
        // starts throwing, the explicit checks are still right.
        let priv = Curve25519.KeyAgreement.PrivateKey()
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(count: 32))
        if let shared = try? priv.sharedSecretFromKeyAgreement(with: pub) {
            XCTAssertTrue(X25519Identity.isAllZero(shared), "a low-order point must give zero or throw")
        }
    }

    func testSmallOrderKeysAreRefusedAsRecipients() {
        XCTAssertThrowsError(try SSHEd25519Recipient(edPublicKey: yIsPMinus1)) {
            XCTAssertEqual($0 as? SSHEd25519Error, .lowOrderPublicKey)
        }
        XCTAssertThrowsError(try SSHEd25519Recipient(edPublicKey: allZero)) {
            XCTAssertEqual($0 as? SSHEd25519Error, .lowOrderPublicKey)
        }
        // Refused one way or another (the validator or the low-order check).
        XCTAssertThrowsError(try SSHEd25519Recipient(edPublicKey: orderEight))
    }

    func testSmallOrderKeyLineIsRefused() throws {
        var w = SSHWireWriter()
        w.writeString("ssh-ed25519")
        w.writeString(yIsPMinus1)
        let line = "ssh-ed25519 " + w.data.base64EncodedString() + " crafted"
        XCTAssertThrowsError(try SSHEd25519Recipient(sshPublicKeyLine: line))
    }

    func testUnwrapIgnoresALowOrderEphemeralShare() throws {
        let k = Curve25519.Signing.PrivateKey()
        let identity = try SSHEd25519Identity(edSeed: k.rawRepresentation, edPublicKey: k.publicKey.rawRepresentation)
        let tag = Stanza.base64NoPad(sshEd25519Tag(wireBlob: identity.wireBlob))
        for share in [Data(count: 32), { var d = Data(count: 32); d[0] = 1; return d }()] {
            let stanza = Stanza(type: "ssh-ed25519",
                                args: [tag, Stanza.base64NoPad(share)],
                                body: Data(count: 32))
            XCTAssertNil(try identity.unwrap(stanza: stanza))
        }
    }

    func testNormalKeysStillRoundTrip() throws {
        let k = Curve25519.Signing.PrivateKey()
        let recipient = try SSHEd25519Recipient(edPublicKey: k.publicKey.rawRepresentation)
        let identity = try SSHEd25519Identity(edSeed: k.rawRepresentation, edPublicKey: k.publicKey.rawRepresentation)
        let plaintext = Data("small-order check".utf8)
        let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])
        XCTAssertEqual(try Age.decrypt(ciphertext: ciphertext, identities: [identity]), plaintext)
    }
}
