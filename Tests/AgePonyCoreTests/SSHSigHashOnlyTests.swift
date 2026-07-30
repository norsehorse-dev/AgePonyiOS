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
}
