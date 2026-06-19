//
//  SSHSigECDSATests.swift
//  AgePonyCoreTests
//
//  E0: ecdsa-sha2-nistp256 SSHSIG signing and verification.
//
//  Coverage mirrors the Ed25519 and RSA suites:
//    1. Interop — a signature produced by the real `ssh-keygen -Y sign` (an
//       ecdsa-sha2-nistp256 key, namespace "agepony") verifies through
//       SSHSigVerifier. This pins the byte layout: the public key is
//       `string("ecdsa-sha2-nistp256") || string("nistp256") || string(Q)`
//       with Q the uncompressed point 0x04||X||Y; the inner signature nests
//       `string(mpint r) || string(mpint s)`; the ECDSA itself is over SHA-256
//       of the signed-data blob while the message digest field stays sha512.
//    2. Round trip — sign with an in-process P-256 key via signECDSAP256,
//       verify, confirm the inner algorithm and that tampering fails.
//
//  The signature bytes are identical whether the P-256 key lives in the
//  Secure Enclave or in-process, so this same format carries the SE signing
//  path that lands next; the SE-specific key generation and vault storage are
//  a separate increment.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class SSHSigECDSATests: XCTestCase {

    private let goldenMessage = "sign me with ecdsa for agepony"

    // ecdsa-sha2-nistp256 public-key wire blob (base64), from id_ecdsa.pub.
    private let goldenPubWireB64 =
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCSXvifSs8+c1itwJlTtXPGUsAslwZ+AOL26ASFmHqMp8JpEL0IdNY5Jc+34InF141oFATvy+2zfEtCOd0wQOQ="

    // Produced by: ssh-keygen -Y sign -f id_ecdsa -n agepony msg.txt
    private let goldenSignature = """
    -----BEGIN SSH SIGNATURE-----
    U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
    EEwJJe+J9Kzz5zWK3AmVO1c8ZSwCyXBn4A4vboBIWYeoynwmkQvQh01jklz7fgicXXjWgU
    BO/L7bN8S0I53TBA5AAAAAdhZ2Vwb255AAAAAAAAAAZzaGE1MTIAAABkAAAAE2VjZHNhLX
    NoYTItbmlzdHAyNTYAAABJAAAAIHCzjn46/mSGQ15v8otFusU9bv25YnQGxkqwZcZWoJ8i
    AAAAIQDFPSGnT0htw6VlRqJe/H6IE0bJdszLsWjdKBFc0hPJng==
    -----END SSH SIGNATURE-----
    """

    // MARK: - Interop with ssh-keygen

    func testGoldenECDSAVectorVerifies() throws {
        let result = try SSHSigVerifier.verify(
            message: Data(goldenMessage.utf8),
            armoredSignature: goldenSignature,
            expectedNamespace: "agepony"
        )
        XCTAssertEqual(result.keyType, "ecdsa-sha2-nistp256")
        XCTAssertEqual(result.namespace, "agepony")
        XCTAssertEqual(result.hash, .sha512)
        XCTAssertEqual(result.publicKeyWire, Data(base64Encoded: goldenPubWireB64))
    }

    func testGoldenECDSAVectorWrongMessageFails() throws {
        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                message: Data("not the signed message".utf8),
                armoredSignature: goldenSignature,
                expectedNamespace: "agepony"
            )
        )
    }

    func testGoldenECDSAVectorWrongNamespaceRejected() throws {
        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                message: Data(goldenMessage.utf8),
                armoredSignature: goldenSignature,
                expectedNamespace: "git"
            )
        ) { error in
            guard case SSHSigError.namespaceMismatch = error else {
                return XCTFail("expected namespaceMismatch, got \(error)")
            }
        }
    }

    // MARK: - Sign / verify round trip (in-process P-256)

    func testECDSASignVerifyRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("round trip ecdsa over agepony".utf8)

        let armored = try SSHSigner.signECDSAP256(message: message, privateKey: key)

        let result = try SSHSigVerifier.verify(
            message: message,
            armoredSignature: armored,
            expectedNamespace: SSHSig.defaultNamespace
        )
        XCTAssertEqual(result.keyType, "ecdsa-sha2-nistp256")
        XCTAssertEqual(
            result.publicKeyWire,
            SSHSig.ecdsaP256PublicKeyWire(x963Q: key.publicKey.x963Representation)
        )
        XCTAssertEqual(result.namespace, "agepony")
    }

    func testECDSASignedInnerAlgorithmIsNistp256() throws {
        let key = P256.Signing.PrivateKey()
        let armored = try SSHSigner.signECDSAP256(message: Data("inner algo".utf8), privateKey: key)
        let blob = try SSHSig.parseArmored(armored)
        let (innerType, _) = try SSHSig.parseInnerSignature(blob.signature)
        XCTAssertEqual(innerType, "ecdsa-sha2-nistp256")
    }

    func testECDSARoundTripTamperedMessageFails() throws {
        let key = P256.Signing.PrivateKey()
        let armored = try SSHSigner.signECDSAP256(message: Data("original".utf8), privateKey: key)
        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                message: Data("tampered".utf8),
                armoredSignature: armored,
                expectedNamespace: SSHSig.defaultNamespace
            )
        )
    }

    func testECDSADifferentKeyDoesNotVerify() throws {
        let signingKey = P256.Signing.PrivateKey()
        let message = Data("bound to one key".utf8)
        let armored = try SSHSigner.signECDSAP256(message: message, privateKey: signingKey)

        // Re-wrap the same inner signature under a different public key blob and
        // confirm it no longer validates (the signature is bound to its key).
        let other = P256.Signing.PrivateKey()
        let blob = try SSHSig.parseArmored(armored)
        let forged = SSHSig.Blob(
            publicKeyWire: SSHSig.ecdsaP256PublicKeyWire(x963Q: other.publicKey.x963Representation),
            namespace: blob.namespace,
            hash: blob.hash,
            signature: blob.signature
        )
        let forgedArmored = SSHSig.armor(SSHSig.serialize(blob: forged))
        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                message: message,
                armoredSignature: forgedArmored,
                expectedNamespace: SSHSig.defaultNamespace
            )
        )
    }

    // MARK: - Wire helpers

    func testECDSAX963RoundTripThroughWire() throws {
        let key = P256.Signing.PrivateKey()
        let q = key.publicKey.x963Representation
        let wire = SSHSig.ecdsaP256PublicKeyWire(x963Q: q)
        let recovered = try SSHSig.ecdsaP256X963(fromWire: wire)
        XCTAssertEqual(recovered, q)
    }

    func testECDSAInnerSignatureRejectsWrongRawLength() {
        XCTAssertThrowsError(try SSHSigner.ecdsaP256InnerSignature(rawRS: Data(repeating: 0, count: 63)))
    }
}
