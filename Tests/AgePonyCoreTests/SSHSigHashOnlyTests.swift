//
//  SSHSigHashOnlyTests.swift
//  AgePonyCoreTests
//
//  Signing and verifying from a precomputed digest must be indistinguishable
//  from doing it with the message in hand. That equivalence is what lets a
//  signed bundle be verified after its payload has already streamed past.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class SSHSigHashOnlyTests: XCTestCase {

    private func message(_ n: Int) -> Data {
        Data((0..<n).map { UInt8(($0 &* 29 &+ 3) % 251) })
    }

    // MARK: - signedData

    func testSignedDataFromHashMatchesFromMessage() {
        for n in [0, 1, 1000, 100_000] {
            let m = message(n)
            for hash in [SSHSigHash.sha256, .sha512] {
                XCTAssertEqual(
                    SSHSig.signedData(message: m, namespace: "agepony", hash: hash),
                    SSHSig.signedData(
                        messageHash: hash.digest(m),
                        namespace: "agepony",
                        hash: hash
                    ),
                    "\(hash) differs at \(n) bytes"
                )
            }
        }
    }

    /// The streaming digest is the one a bundle actually uses.
    func testSignedDataFromStreamedHashMatches() throws {
        let m = message(200_000)
        for hash in [SSHSigHash.sha256, .sha512] {
            let streamed = try hash.digest(streaming: InputStream(data: m))
            XCTAssertEqual(
                SSHSig.signedData(message: m, namespace: "agepony", hash: hash),
                SSHSig.signedData(messageHash: streamed, namespace: "agepony", hash: hash)
            )
        }
    }

    // MARK: - Verification

    private func signedFixture(_ m: Data, hash: SSHSigHash) throws -> (String, Data) {
        let seed = Data((0..<32).map { UInt8($0) })
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let armored = try SSHSigner.signEd25519(
            message: m,
            privateMaterial: seed + key.publicKey.rawRepresentation,
            namespace: SSHSig.defaultNamespace,
            hash: hash
        )
        return (armored, key.publicKey.rawRepresentation)
    }

    func testVerifyFromHashAcceptsAValidSignature() throws {
        let m = message(50_000)
        let (armored, _) = try signedFixture(m, hash: .sha512)

        // The provider is asked for whichever algorithm the signature names.
        var asked: SSHSigHash?
        let result = try SSHSigVerifier.verify(
            armoredSignature: armored,
            messageHash: { algorithm in
                asked = algorithm
                return algorithm.digest(m)
            }
        )
        XCTAssertEqual(asked, .sha512)
        XCTAssertFalse(result.publicKeyWire.isEmpty)
    }

    func testVerifyFromHashRejectsTheWrongDigest() throws {
        let m = message(50_000)
        let (armored, _) = try signedFixture(m, hash: .sha512)
        let other = message(50_001)

        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                armoredSignature: armored,
                messageHash: { $0.digest(other) }
            )
        )
    }

    /// Both entry points must reach the same verdict on the same input.
    func testHashPathAgreesWithMessagePath() throws {
        for hash in [SSHSigHash.sha256, .sha512] {
            let m = message(9_999)
            let (armored, _) = try signedFixture(m, hash: hash)

            let viaMessage = try SSHSigVerifier.verify(message: m, armoredSignature: armored)
            let viaHash = try SSHSigVerifier.verify(
                armoredSignature: armored,
                messageHash: { $0.digest(m) }
            )
            XCTAssertEqual(viaMessage.publicKeyWire, viaHash.publicKeyWire)
        }
    }

    // MARK: - End to end through a signed bundle
    //
    // The point of all of this: a bundle whose payload has already been written
    // out and discarded can still have its signature checked, using the digests
    // the unwrapping sink computed on the way past.

    func testSignedBundlePayloadVerifiesFromStreamedHashes() throws {
        let payload = message(120_000)
        let (armored, _) = try signedFixture(payload, hash: .sha512)

        let bundle = try SignedBundle.build(
            originalName: "report.pdf",
            payload: payload,
            signatureArmored: armored
        )

        // Push the bundle through the sink the decrypt path uses.
        let out = OutputStream.toMemory()
        out.open()
        let sink = SignedBundleUnwrappingSink(payloadOut: out)
        sink.open()
        try AgePayload.writeAll(bundle, to: sink)
        try sink.finish()
        out.close()

        let parsed = try XCTUnwrap(try sink.result())
        XCTAssertEqual(parsed.name, "report.pdf")

        // Verify without the payload: only the digests taken while it streamed.
        let verification = try SSHSigVerifier.verify(
            armoredSignature: parsed.signatureArmored,
            messageHash: { parsed.hash($0) }
        )
        XCTAssertFalse(verification.publicKeyWire.isEmpty)

        // And the payload really did come through intact.
        let recovered = out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
        XCTAssertEqual(recovered, payload)
    }

    // MARK: - Digest-taking signers
    //
    // Every signer now has a form that takes a digest instead of a message. The
    // two must be interchangeable, or a file signed after streaming would not
    // verify against the same file read whole.

    /// Signing a digest and signing the message are interchangeable.
    ///
    /// Deliberately not a byte comparison. Ed25519 is deterministic in the RFC,
    /// but CryptoKit's is not: Apple hedges signing with fresh randomness, so two
    /// signatures over identical input differ. What has to match is everything a
    /// verifier reads -- the key, the namespace, the hash algorithm -- and that
    /// both signatures check out against the message they claim to cover.
    ///
    /// The bytes that *are* required to be identical are the signed-data blob,
    /// and `testSignedDataFromHashMatchesFromMessage` compares those directly.
    func testEd25519SignsEquivalentlyFromAHash() throws {
        let seed = Data((0..<32).map { UInt8($0) })
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let pub = key.publicKey.rawRepresentation
        let m = message(70_000)

        for hash in [SSHSigHash.sha256, .sha512] {
            let fromMessage = try SSHSigner.signEd25519(
                message: m, seed: seed, publicKey: pub, hash: hash)
            let fromHash = try SSHSigner.signEd25519(
                messageHash: hash.digest(m), seed: seed, publicKey: pub, hash: hash)
            // ...and via the stored-material convenience, which is what the app uses.
            let viaMaterial = try SSHSigner.signEd25519(
                messageHash: hash.digest(m), privateMaterial: seed + pub, hash: hash)

            let reference = try SSHSig.parseArmored(fromMessage)
            for (label, armored) in [("fromHash", fromHash), ("viaMaterial", viaMaterial)] {
                let where_ = "\(label) \(hash)"
                let blob = try SSHSig.parseArmored(armored)
                XCTAssertEqual(blob.publicKeyWire, reference.publicKeyWire, where_)
                XCTAssertEqual(blob.namespace, reference.namespace, where_)
                XCTAssertEqual(blob.hash, reference.hash, where_)

                let v = try SSHSigVerifier.verify(message: m, armoredSignature: armored)
                XCTAssertEqual(v.publicKeyWire, SSHSig.ed25519PublicKeyWire(pub), where_)
            }
        }
    }

    func testEd25519SignsFromAStreamedHash() throws {
        let seed = Data((0..<32).map { UInt8($0 &+ 7) })
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let pub = key.publicKey.rawRepresentation
        let m = message(300_000)

        let streamed = try SSHSigHash.sha512.digest(streaming: InputStream(data: m))
        let armored = try SSHSigner.signEd25519(
            messageHash: streamed, privateMaterial: seed + pub)

        // Verified the ordinary way, against the whole message.
        let v = try SSHSigVerifier.verify(message: m, armoredSignature: armored)
        XCTAssertEqual(v.publicKeyWire, SSHSig.ed25519PublicKeyWire(pub))
    }

    /// ECDSA is randomised, so this checks the signature verifies rather than
    /// that the bytes match.
    func testECDSAP256SignsFromAHash() throws {
        let key = P256.Signing.PrivateKey()
        let m = message(40_000)

        for hash in [SSHSigHash.sha256, .sha512] {
            let armored = try SSHSigner.signECDSAP256(
                messageHash: hash.digest(m), privateKey: key, hash: hash)
            let v = try SSHSigVerifier.verify(message: m, armoredSignature: armored)
            XCTAssertEqual(v.keyType, "ecdsa-sha2-nistp256")
            XCTAssertEqual(v.hash, hash)
        }
    }

    // MARK: - Wrong-length digests

    // A digest of the wrong length produces a well-formed signature that simply
    // never verifies. Caught at the door instead, so the failure names its cause.

    func testSigningRejectsAWrongLengthDigest() throws {
        let seed = Data((0..<32).map { UInt8($0) })
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let material = seed + key.publicKey.rawRepresentation

        // A SHA-256 digest handed to a signature that says sha512, and vice versa.
        let short = SSHSigHash.sha256.digest(Data("x".utf8))
        let long = SSHSigHash.sha512.digest(Data("x".utf8))

        XCTAssertThrowsError(
            try SSHSigner.signEd25519(messageHash: short, privateMaterial: material, hash: .sha512)
        ) { XCTAssertEqual($0 as? SSHSigError, .malformedMessageHash) }

        XCTAssertThrowsError(
            try SSHSigner.signEd25519(messageHash: long, privateMaterial: material, hash: .sha256)
        ) { XCTAssertEqual($0 as? SSHSigError, .malformedMessageHash) }

        XCTAssertThrowsError(
            try SSHSigner.signECDSAP256(
                messageHash: Data(), privateKey: P256.Signing.PrivateKey(), hash: .sha512)
        ) { XCTAssertEqual($0 as? SSHSigError, .malformedMessageHash) }
    }

    func testVerifyRejectsAWrongLengthDigestFromTheProvider() throws {
        let m = message(1_000)
        let (armored, _) = try signedFixture(m, hash: .sha512)

        // A provider that hands back a SHA-256 digest for a sha512 signature is
        // a bug in the caller, and is named as one rather than reported as a
        // failed signature.
        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                armoredSignature: armored,
                messageHash: { _ in SSHSigHash.sha256.digest(m) }
            )
        ) { XCTAssertEqual($0 as? SSHSigError, .malformedMessageHash) }
    }
}
