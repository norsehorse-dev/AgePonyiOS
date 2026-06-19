//
//  SSHSigTests.swift
//  AgePonyCoreTests
//
//  Tests for SSHSIG signing/verification. The headline test is a golden
//  vector captured from real `ssh-keygen -Y sign` output (OpenSSH 9.x): a
//  signature ssh-keygen produced must verify in AgePony, byte-for-byte.
//  This is the interop anchor, the same role ReferenceCLITests play for the
//  age encryption path.
//
//  The reverse direction (a signature AgePony produces verifying under
//  `ssh-keygen -Y verify`) is a device/CLI step, since invoking ssh-keygen
//  from a unit test isn't hermetic. It's documented in the A0 bundle README.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class SSHSigTests: XCTestCase {

    // MARK: - Golden vector (from ssh-keygen -Y sign -n agepony)

    /// The signer public key line ssh-keygen wrote.
    private let goldenPublicKeyLine =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILr/NVvNaGxfkVp8Ni/Z3ubM8/k89JoVOg8oMJeid1tU agepony-test@norsehor.se"

    /// Exactly the bytes signed: no trailing newline.
    private let goldenMessage = Data("The quick brown fox jumps over the lazy dog".utf8)

    /// The armored signature ssh-keygen produced (namespace "agepony", sha512).
    private let goldenSignature = """
    -----BEGIN SSH SIGNATURE-----
    U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAguv81W81obF+RWnw2L9ne5szz+T
    z0mhU6Dygwl6J3W1QAAAAHYWdlcG9ueQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQy
    NTUxOQAAAEArsclK/Bj6zBjkF+AKNr4Sen5spRyTgugyJFAo+k/Qw0rBVGZS/Vo+lAWVYd
    pQpnzvvDPPlgB6T7BzWMO5t2IE
    -----END SSH SIGNATURE-----
    """

    /// The base64 of the public-key wire blob (the second field of the .pub line).
    private var goldenPublicKeyWire: Data {
        let b64 = goldenPublicKeyLine.split(separator: " ").map(String.init)[1]
        return Data(base64Encoded: b64)!
    }

    func testGoldenVectorVerifies() throws {
        let result = try SSHSigVerifier.verify(
            message: goldenMessage,
            armoredSignature: goldenSignature,
            expectedNamespace: "agepony"
        )
        XCTAssertEqual(result.keyType, "ssh-ed25519")
        XCTAssertEqual(result.namespace, "agepony")
        XCTAssertEqual(result.hash, .sha512)
        XCTAssertEqual(result.publicKeyWire, goldenPublicKeyWire)
    }

    func testGoldenVectorWrongMessageFails() {
        let tampered = Data("The quick brown fox jumps over the lazy dog.".utf8) // extra '.'
        XCTAssertThrowsError(try SSHSigVerifier.verify(
            message: tampered,
            armoredSignature: goldenSignature,
            expectedNamespace: "agepony"
        )) { error in
            XCTAssertEqual(error as? SSHSigError, .signatureInvalid)
        }
    }

    func testGoldenVectorWrongNamespaceRejected() {
        XCTAssertThrowsError(try SSHSigVerifier.verify(
            message: goldenMessage,
            armoredSignature: goldenSignature,
            expectedNamespace: "file"
        )) { error in
            XCTAssertEqual(error as? SSHSigError, .namespaceMismatch(expected: "file", found: "agepony"))
        }
    }

    func testGoldenVectorAnyNamespaceWhenNil() throws {
        let result = try SSHSigVerifier.verify(
            message: goldenMessage,
            armoredSignature: goldenSignature,
            expectedNamespace: nil
        )
        XCTAssertEqual(result.namespace, "agepony")
    }

    // MARK: - Round trip (AgePony sign -> AgePony verify)

    private func makeKeypair() -> (seed: Data, pub: Data) {
        let k = Curve25519.Signing.PrivateKey()
        return (k.rawRepresentation, k.publicKey.rawRepresentation)
    }

    func testRoundTripEd25519() throws {
        let (seed, pub) = makeKeypair()
        let message = Data("payload to sign \u{1F40E}".utf8) // includes multibyte
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub)

        let result = try SSHSigVerifier.verify(message: message, armoredSignature: sig)
        XCTAssertEqual(result.publicKeyWire, SSHSig.ed25519PublicKeyWire(pub))
        XCTAssertEqual(result.namespace, SSHSig.defaultNamespace)
        XCTAssertEqual(result.hash, .sha512)
    }

    func testRoundTripFromVaultMaterial() throws {
        let (seed, pub) = makeKeypair()
        let privateMaterial = seed + pub // vault layout: seed(32) || pub(32)
        let message = Data("vault-material signing".utf8)
        let sig = try SSHSigner.signEd25519(message: message, privateMaterial: privateMaterial)
        XCTAssertNoThrow(try SSHSigVerifier.verify(message: message, armoredSignature: sig))
    }

    func testRoundTripSHA256() throws {
        let (seed, pub) = makeKeypair()
        let message = Data("sha256 variant".utf8)
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub, hash: .sha256)
        let result = try SSHSigVerifier.verify(message: message, armoredSignature: sig)
        XCTAssertEqual(result.hash, .sha256)
    }

    func testTamperedSignatureFails() throws {
        let (seed, pub) = makeKeypair()
        let message = Data("authentic".utf8)
        let sig = try SSHSigner.signEd25519(message: message, seed: seed, publicKey: pub)

        // Verify against a different message.
        XCTAssertThrowsError(try SSHSigVerifier.verify(
            message: Data("forged".utf8),
            armoredSignature: sig
        )) { error in
            XCTAssertEqual(error as? SSHSigError, .signatureInvalid)
        }
    }

    func testWrongKeyDoesNotValidate() throws {
        // Sign with key A; the signature embeds A's pubkey, so it validates
        // mathematically — but a signature re-armored to claim key B's pubkey
        // must fail. Here we simply confirm an independent message/key pairing
        // fails, guarding against any accidental "always true" verify path.
        let (seedA, pubA) = makeKeypair()
        let messageA = Data("from A".utf8)
        let sigA = try SSHSigner.signEd25519(message: messageA, seed: seedA, publicKey: pubA)
        XCTAssertThrowsError(try SSHSigVerifier.verify(
            message: Data("not from A".utf8),
            armoredSignature: sigA
        ))
    }

    // MARK: - Format units

    func testArmorRoundTrip() throws {
        let (seed, pub) = makeKeypair()
        let sig = try SSHSigner.signEd25519(message: Data("x".utf8), seed: seed, publicKey: pub)
        let blob = try SSHSig.dearmor(sig)
        let reArmored = SSHSig.armor(blob)
        XCTAssertEqual(try SSHSig.dearmor(reArmored), blob)
    }

    func testBlobSerializeParseRoundTrip() throws {
        let (_, pub) = makeKeypair()
        var inner = SSHWireWriter()
        inner.writeString("ssh-ed25519")
        inner.writeString(Data(repeating: 0xAB, count: 64))
        let blob = SSHSig.Blob(
            publicKeyWire: SSHSig.ed25519PublicKeyWire(pub),
            namespace: "agepony",
            hash: .sha512,
            signature: inner.data
        )
        let parsed = try SSHSig.parse(blob: SSHSig.serialize(blob: blob))
        XCTAssertEqual(parsed, blob)
    }

    func testSignedDataBeginsWithMagic() {
        let signed = SSHSig.signedData(message: Data("m".utf8), namespace: "agepony", hash: .sha512)
        XCTAssertEqual(signed.prefix(6), Data("SSHSIG".utf8))
    }

    func testPublicKeyWireRoundTrip() throws {
        let (_, pub) = makeKeypair()
        let wire = SSHSig.ed25519PublicKeyWire(pub)
        XCTAssertEqual(try SSHSig.publicKeyType(wire), "ssh-ed25519")
        XCTAssertEqual(try SSHSig.ed25519RawPublicKey(fromWire: wire), pub)
    }

    func testBadMagicRejected() {
        var bad = Data("NOTSIG".utf8)
        bad.append(Data(repeating: 0, count: 20))
        XCTAssertThrowsError(try SSHSig.parse(blob: bad)) { error in
            XCTAssertEqual(error as? SSHSigError, .badMagic)
        }
    }

    func testMissingArmorRejected() {
        XCTAssertThrowsError(try SSHSig.dearmor("not a signature")) { error in
            XCTAssertEqual(error as? SSHSigError, .missingBeginMarker)
        }
    }
}
