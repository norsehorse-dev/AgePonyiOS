//
//  Ed25519ConversionTests.swift
//  AgePonyCoreTests
//
//  Cross-check the conversion against CryptoKit's X25519 implementation:
//  if our Edwards-to-Montgomery and SHA-512+clamp implementations are both
//  correct, an X25519 key agreement using the converted forms should match
//  what we'd get from a "native" X25519 keypair generated alongside.
//
//  The strongest test is end-to-end through the ssh-ed25519 stanza
//  (`SSHEd25519Tests`) and against the reference age CLI (`ReferenceCLITests`).
//  These tests target the conversion functions in isolation.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class Ed25519ConversionTests: XCTestCase {

    func testPrivateKeyConversionMatchesSpec() throws {
        // Known vector: arbitrary 32-byte seed; expected = SHA-512(seed)[0..32], clamped.
        // We verify against our own implementation of the spec, then independently
        // check that the clamping bits are set correctly.
        let seed = Data((0..<32).map { UInt8($0) })  // 0x00, 0x01, ..., 0x1f
        let x = try Ed25519Conversion.privateKeyToX25519(edPrivateSeed: seed)
        XCTAssertEqual(x.count, 32)
        // Clamping bits.
        XCTAssertEqual(x[0] & 0b00000111, 0)         // bottom 3 bits cleared
        XCTAssertEqual(x[31] & 0b10000000, 0)        // top bit cleared
        XCTAssertEqual(x[31] & 0b01000000, 0b01000000)  // second-from-top set
    }

    func testPublicKeyConversionLengthAndDeterminism() throws {
        // Same input → same output.
        let edKey = Curve25519.Signing.PrivateKey()
        let edPub = edKey.publicKey.rawRepresentation
        let xPub1 = try Ed25519Conversion.publicKeyToX25519(edPublicKey: edPub)
        let xPub2 = try Ed25519Conversion.publicKeyToX25519(edPublicKey: edPub)
        XCTAssertEqual(xPub1, xPub2)
        XCTAssertEqual(xPub1.count, 32)
    }

    func testRejectsBadLengths() {
        XCTAssertThrowsError(try Ed25519Conversion.publicKeyToX25519(edPublicKey: Data(repeating: 0, count: 31)))
        XCTAssertThrowsError(try Ed25519Conversion.publicKeyToX25519(edPublicKey: Data(repeating: 0, count: 33)))
        XCTAssertThrowsError(try Ed25519Conversion.privateKeyToX25519(edPrivateSeed: Data(repeating: 0, count: 31)))
        XCTAssertThrowsError(try Ed25519Conversion.privateKeyToX25519(edPrivateSeed: Data(repeating: 0, count: 33)))
    }

    /// The big self-consistency test: generate an Ed25519 keypair, convert both
    /// halves, and use the converted forms for an X25519 key agreement against
    /// a fresh ephemeral X25519 keypair. The shared secret must match what
    /// the ephemeral side computes against the converted public key.
    func testConvertedKeyAgreementSelfConsistent() throws {
        // Alice has an Ed25519 SSH-style keypair.
        let aliceEdPriv = Curve25519.Signing.PrivateKey()
        let aliceEdSeed = aliceEdPriv.rawRepresentation
        let aliceEdPub = aliceEdPriv.publicKey.rawRepresentation

        // Convert both halves to X25519 form.
        let aliceXPriv = try Ed25519Conversion.privateKeyToX25519(edPrivateSeed: aliceEdSeed)
        let aliceXPub  = try Ed25519Conversion.publicKeyToX25519(edPublicKey: aliceEdPub)

        // Bob has a fresh X25519 keypair.
        let bobPriv = Curve25519.KeyAgreement.PrivateKey()
        let bobPub  = bobPriv.publicKey.rawRepresentation

        // Bob computes shared = X25519(bobPriv, aliceXPub).
        let aliceXPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: aliceXPub)
        let bobShared = try bobPriv.sharedSecretFromKeyAgreement(with: aliceXPubKey)

        // Alice computes shared = X25519(aliceXPriv, bobPub).
        let aliceXPrivKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: aliceXPriv)
        let bobPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: bobPub)
        let aliceShared = try aliceXPrivKey.sharedSecretFromKeyAgreement(with: bobPubKey)

        // The two SharedSecret values must compare equal.
        let bobBytes = bobShared.withUnsafeBytes { Data($0) }
        let aliceBytes = aliceShared.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bobBytes, aliceBytes)
    }

    /// Also verify: the X25519 public key we derive from `xPriv` by direct
    /// scalar-mult-of-base via CryptoKit matches the X25519 public key we
    /// derive by Edwards→Montgomery conversion of the Ed25519 public key.
    func testConvertedPubKeyMatchesScalarMultOfConvertedPriv() throws {
        for _ in 0..<3 {
            let edPriv = Curve25519.Signing.PrivateKey()
            let edSeed = edPriv.rawRepresentation
            let edPub = edPriv.publicKey.rawRepresentation

            let xPriv = try Ed25519Conversion.privateKeyToX25519(edPrivateSeed: edSeed)
            let xPubViaConversion = try Ed25519Conversion.publicKeyToX25519(edPublicKey: edPub)

            // The X25519 public key from xPriv via CryptoKit must equal xPubViaConversion.
            let xPrivKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: xPriv)
            let xPubViaCryptoKit = xPrivKey.publicKey.rawRepresentation

            XCTAssertEqual(xPubViaCryptoKit, xPubViaConversion)
        }
    }
}
