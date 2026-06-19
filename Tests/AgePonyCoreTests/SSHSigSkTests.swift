//
//  SSHSigSkTests.swift
//  AgePonyCoreTests
//
//  E1: FIDO security-key SSHSIG formats —
//      sk-ssh-ed25519@openssh.com and sk-ecdsa-sha2-nistp256@openssh.com.
//
//  These are the signatures an external NFC security key (YubiKey 5 NFC and
//  friends) produces. The key difference from a plain SSHSIG is that the
//  authenticator doesn't sign the SSHSIG signed-data directly — it signs
//  `SHA256(application) || flags || counter || SHA256(signedData)` (the
//  WebAuthn authenticatorData || clientDataHash), and the public key and inner
//  signature carry the application / flags / counter.
//
//  Coverage:
//    1. Interop — golden vectors that `ssh-keygen -Y verify` accepts (verifying
//       an sk signature needs no hardware), for both sk types.
//    2. Round trip — a simulated authenticator (an in-process key signing the
//       same authenticator message) assembled via SSHSigner.assembleSk*, then
//       verified, plus tamper / wrong-key negatives.
//
//  Signing on real hardware (the NFC/CTAP2 transport) is the app-layer
//  increment that follows; this pins the wire format both sides depend on.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class SSHSigSkTests: XCTestCase {

    private let goldenMessage = "sign me with a security key for agepony"

    // ssh-keygen -Y verify accepts both of these (hand-built, hardware-free).
    private let edPubWireB64 =
        "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIK0c5+fUMjCdpHbACAoQaoppA6kisQLWckhNUCkwcwFuAAAABHNzaDo="
    private let edSignature = """
    -----BEGIN SSH SIGNATURE-----
    U1NIU0lHAAAAAQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAgrRzn59
    QyMJ2kdsAIChBqimkDqSKxAtZySE1QKTBzAW4AAAAEc3NoOgAAAAdhZ2Vwb255AAAAAAAA
    AAZzaGE1MTIAAABnAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAQDltTps7Dy
    S8YxeyVvhe2jwn3UD+2Ze8nmUL9zovJuvXZfHDpBdfD+4culvvZi/GEcIFlEeJWQhm+/cn
    5belGQoBAAAABw==
    -----END SSH SIGNATURE-----
    """

    private let ecPubWireB64 =
        "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBN8TcmRBP3MuoNM9LOXDyBnnTheDhTop/1JBjaHkJGOSQe9Dqcl8aq+dNgjFakbvg9mM1UEPqBnvIlhZUXHnv5gAAAAEc3NoOg=="
    private let ecSignature = """
    -----BEGIN SSH SIGNATURE-----
    U1NIU0lHAAAAAQAAAH8AAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBvcGVuc3NoLmNvbQ
    AAAAhuaXN0cDI1NgAAAEEE3xNyZEE/cy6g0z0s5cPIGedOF4OFOin/UkGNoeQkY5JB70Op
    yXxqr502CMVqRu+D2YzVQQ+oGe8iWFlRcee/mAAAAARzc2g6AAAAB2FnZXBvbnkAAAAAAA
    AABnNoYTUxMgAAAHcAAAAic2stZWNkc2Etc2hhMi1uaXN0cDI1NkBvcGVuc3NoLmNvbQAA
    AEgAAAAgS4g5nKGy+4va1rX08J0RFFGgxm+LlWRGgg6V5C6V9vgAAAAgMGaod97lGBDxFV
    Y0rUc0czZSbtWTRhXHNwjRU7aewSIBAAAABw==
    -----END SSH SIGNATURE-----
    """

    private let application = Data("ssh:".utf8)

    // MARK: - Interop (ssh-keygen golden vectors)

    func testGoldenSkEd25519Verifies() throws {
        let r = try SSHSigVerifier.verify(
            message: Data(goldenMessage.utf8),
            armoredSignature: edSignature,
            expectedNamespace: "agepony"
        )
        XCTAssertEqual(r.keyType, "sk-ssh-ed25519@openssh.com")
        XCTAssertEqual(r.namespace, "agepony")
        XCTAssertEqual(r.publicKeyWire, Data(base64Encoded: edPubWireB64))
    }

    func testGoldenSkEcdsaVerifies() throws {
        let r = try SSHSigVerifier.verify(
            message: Data(goldenMessage.utf8),
            armoredSignature: ecSignature,
            expectedNamespace: "agepony"
        )
        XCTAssertEqual(r.keyType, "sk-ecdsa-sha2-nistp256@openssh.com")
        XCTAssertEqual(r.namespace, "agepony")
        XCTAssertEqual(r.publicKeyWire, Data(base64Encoded: ecPubWireB64))
    }

    func testGoldenSkEd25519WrongMessageFails() {
        XCTAssertThrowsError(try SSHSigVerifier.verify(
            message: Data("different".utf8),
            armoredSignature: edSignature,
            expectedNamespace: "agepony"
        ))
    }

    func testGoldenSkEcdsaWrongMessageFails() {
        XCTAssertThrowsError(try SSHSigVerifier.verify(
            message: Data("different".utf8),
            armoredSignature: ecSignature,
            expectedNamespace: "agepony"
        ))
    }

    // MARK: - Round trip with a simulated authenticator

    /// Stand in for a FIDO authenticator: sign the exact authenticator message
    /// the verifier will reconstruct.
    private func authenticatorMessage(
        message: Data, flags: UInt8, counter: UInt32
    ) -> Data {
        let signed = SSHSig.signedData(
            message: message, namespace: SSHSig.defaultNamespace, hash: .sha512
        )
        return SSHSig.skAuthenticatorMessage(
            application: application, flags: flags, counter: counter, signedData: signed
        )
    }

    func testSkEd25519RoundTrip() throws {
        let key = Curve25519.Signing.PrivateKey()
        let message = Data("round trip sk ed25519".utf8)
        let flags: UInt8 = 0x01
        let counter: UInt32 = 42

        let authMsg = authenticatorMessage(message: message, flags: flags, counter: counter)
        let rawSig = try key.signature(for: authMsg)

        let armored = try SSHSigner.assembleSkEd25519(
            publicKey: key.publicKey.rawRepresentation,
            application: application,
            rawSig: rawSig,
            flags: flags,
            counter: counter
        )

        let r = try SSHSigVerifier.verify(
            message: message, armoredSignature: armored, expectedNamespace: "agepony"
        )
        XCTAssertEqual(r.keyType, "sk-ssh-ed25519@openssh.com")
        XCTAssertEqual(
            r.publicKeyWire,
            SSHSig.skEd25519PublicKeyWire(
                rawPublicKey: key.publicKey.rawRepresentation, application: application
            )
        )
    }

    func testSkEcdsaRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("round trip sk ecdsa".utf8)
        let flags: UInt8 = 0x01
        let counter: UInt32 = 99

        let authMsg = authenticatorMessage(message: message, flags: flags, counter: counter)
        let rawRS = try key.signature(for: authMsg).rawRepresentation

        let armored = try SSHSigner.assembleSkEcdsaP256(
            publicKeyX963: key.publicKey.x963Representation,
            application: application,
            rawRS: rawRS,
            flags: flags,
            counter: counter
        )

        let r = try SSHSigVerifier.verify(
            message: message, armoredSignature: armored, expectedNamespace: "agepony"
        )
        XCTAssertEqual(r.keyType, "sk-ecdsa-sha2-nistp256@openssh.com")
        XCTAssertEqual(
            r.publicKeyWire,
            SSHSig.skEcdsaP256PublicKeyWire(
                x963Q: key.publicKey.x963Representation, application: application
            )
        )
    }

    func testSkEd25519TamperedCounterFails() throws {
        let key = Curve25519.Signing.PrivateKey()
        let message = Data("counter binds".utf8)
        let authMsg = authenticatorMessage(message: message, flags: 0x01, counter: 5)
        let rawSig = try key.signature(for: authMsg)

        // Assemble with a different counter than was signed → must not verify.
        let armored = try SSHSigner.assembleSkEd25519(
            publicKey: key.publicKey.rawRepresentation,
            application: application,
            rawSig: rawSig,
            flags: 0x01,
            counter: 6
        )
        XCTAssertThrowsError(try SSHSigVerifier.verify(
            message: message, armoredSignature: armored, expectedNamespace: "agepony"
        ))
    }

    func testSkEcdsaWrongKeyFails() throws {
        let key = P256.Signing.PrivateKey()
        let other = P256.Signing.PrivateKey()
        let message = Data("bound to key".utf8)
        let authMsg = authenticatorMessage(message: message, flags: 0x01, counter: 1)
        let rawRS = try key.signature(for: authMsg).rawRepresentation

        // Package the real signature under a different public key.
        let armored = try SSHSigner.assembleSkEcdsaP256(
            publicKeyX963: other.publicKey.x963Representation,
            application: application,
            rawRS: rawRS,
            flags: 0x01,
            counter: 1
        )
        XCTAssertThrowsError(try SSHSigVerifier.verify(
            message: message, armoredSignature: armored, expectedNamespace: "agepony"
        ))
    }

    // MARK: - Wire helpers

    func testSkEd25519WireComponentsRoundTrip() throws {
        let key = Curve25519.Signing.PrivateKey()
        let wire = SSHSig.skEd25519PublicKeyWire(
            rawPublicKey: key.publicKey.rawRepresentation, application: application
        )
        let (pub, app) = try SSHSig.skEd25519Components(fromWire: wire)
        XCTAssertEqual(pub, key.publicKey.rawRepresentation)
        XCTAssertEqual(app, application)
    }

    func testSkEcdsaWireComponentsRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let wire = SSHSig.skEcdsaP256PublicKeyWire(
            x963Q: key.publicKey.x963Representation, application: application
        )
        let (q, app) = try SSHSig.skEcdsaP256Components(fromWire: wire)
        XCTAssertEqual(q, key.publicKey.x963Representation)
        XCTAssertEqual(app, application)
    }
}
