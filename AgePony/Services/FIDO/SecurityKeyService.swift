//
//  SecurityKeyService.swift
//  AgePony — FIDO security-key operations (app target, device-bound)
//
//  The two operations AgePony needs from an external security key, expressed in
//  AgePony's own terms:
//
//    enroll()      -> tap once to create a credential; returns the credentialId
//                     and public key to store as an identity.
//    signSSHSIG()  -> tap once to sign; returns a finished armored sk-* SSHSIG.
//
//  Everything format-related (CTAP2 requests/responses, COSE, the sk SSHSIG
//  assembly, DER->raw) is the reference-checked code in AgePonyCore. This file
//  only sequences it around an NFC tap.
//

import Foundation
#if canImport(CoreNFC)
import CryptoKit
import AgePonyCore

/// Which signature algorithm the enrolled credential uses. Determined by the
/// authenticator's choice from our preference list, read off the COSE key.
public enum SecurityKeyAlgorithm: Equatable {
    case ed25519        // sk-ssh-ed25519@openssh.com
    case ecdsaP256      // sk-ecdsa-sha2-nistp256@openssh.com
}

@available(iOS 13.0, *)
public enum SecurityKeyService {

    /// The FIDO relying-party / application string SSH uses.
    public static let application = Data("ssh:".utf8)

    public struct EnrollResult: Equatable {
        public let credentialId: Data
        public let algorithm: SecurityKeyAlgorithm
        /// Raw 32-byte Ed25519 public key, or 65-byte P-256 x963 point.
        public let publicKey: Data
        public let application: Data
    }

    /// Create a credential on a tapped security key. The clientDataHash is
    /// irrelevant to later signing (we ignore attestation), so it's random.
    public static func enroll(
        pin: String? = nil,
        alertMessage: String = "Hold your security key to the top of your iPhone."
    ) async throws -> EnrollResult {
        let clientDataHash = Data((0 ..< 32).map { _ in UInt8.random(in: UInt8.min ... UInt8.max) })

        let result = try await SecurityKeyTransport.run(alertMessage: alertMessage) { channel in
            // If the key has a FIDO PIN, exchange it for a token first (same tap).
            var pinAuthParam: Data?
            if let pin = pin {
                let token = try await obtainPinToken(channel: channel, pin: pin)
                pinAuthParam = PinProtocolV1.pinUvAuthParam(
                    pinToken: token, clientDataHash: clientDataHash)
            }
            let request = CTAP2.makeCredentialRequest(
                clientDataHash: clientDataHash,
                pinUvAuthParam: pinAuthParam,
                pinUvAuthProtocol: pinAuthParam == nil ? nil : PinProtocolV1.version
            )
            return try await CTAP2.parseMakeCredentialResponse(channel.sendCTAP(request))
        }

        switch result.publicKey {
        case .ed25519(let raw):
            return EnrollResult(
                credentialId: result.credentialId,
                algorithm: .ed25519,
                publicKey: raw,
                application: application
            )
        case .p256(let q):
            return EnrollResult(
                credentialId: result.credentialId,
                algorithm: .ecdsaP256,
                publicKey: q,
                application: application
            )
        }
    }

    /// Sign `message` with a tapped security key, producing a finished armored
    /// sk-* SSHSIG. `publicKey` is the stored raw Ed25519 key or P-256 x963
    /// point from enrolment; `credentialId` is the stored handle.
    public static func signSSHSIG(
        message: Data,
        credentialId: Data,
        algorithm: SecurityKeyAlgorithm,
        publicKey: Data,
        application: Data = SecurityKeyService.application,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512,
        pin: String? = nil,
        alertMessage: String = "Hold your security key to sign."
    ) async throws -> String {
        let signedData = SSHSig.signedData(message: message, namespace: namespace, hash: hash)
        let clientDataHash = Data(SHA256.hash(data: signedData))

        let assertion = try await SecurityKeyTransport.run(alertMessage: alertMessage) { channel in
            var pinAuthParam: Data?
            if let pin = pin {
                let token = try await obtainPinToken(channel: channel, pin: pin)
                pinAuthParam = PinProtocolV1.pinUvAuthParam(
                    pinToken: token, clientDataHash: clientDataHash)
            }
            let request = CTAP2.getAssertionRequest(
                clientDataHash: clientDataHash,
                allowCredentialIds: [credentialId],
                pinUvAuthParam: pinAuthParam,
                pinUvAuthProtocol: pinAuthParam == nil ? nil : PinProtocolV1.version
            )
            return try await CTAP2.parseGetAssertionResponse(channel.sendCTAP(request))
        }

        let flags = assertion.authenticatorData.flags
        let counter = assertion.authenticatorData.signCount

        switch algorithm {
        case .ed25519:
            return try SSHSigner.assembleSkEd25519(
                publicKey: publicKey,
                application: application,
                rawSig: assertion.signature,
                flags: flags,
                counter: counter,
                namespace: namespace,
                hash: hash
            )
        case .ecdsaP256:
            let rawRS = try CTAP2.rawP256Signature(fromDER: assertion.signature)
            return try SSHSigner.assembleSkEcdsaP256(
                publicKeyX963: publicKey,
                application: application,
                rawRS: rawRS,
                flags: flags,
                counter: counter,
                namespace: namespace,
                hash: hash
            )
        }
    }

    // MARK: - PIN token exchange (CTAP2 clientPin, PIN/UV protocol 1)

    /// Run the clientPin dance on an already-connected channel and return the
    /// decrypted PIN token. Issued within the same NFC session (same tap) as the
    /// makeCredential / getAssertion that uses it:
    ///   getKeyAgreement -> ECDH shared secret -> getPinToken -> decrypt.
    private static func obtainPinToken(channel: SecurityKeyChannel, pin: String) async throws -> Data {
        let kaResponse = try await channel.sendCTAP(CTAP2.getKeyAgreementRequest())
        let authKey = try CTAP2.parseGetKeyAgreementResponse(kaResponse)
        guard case .p256(let authX963) = authKey else {
            throw SecurityKeyError.pinAgreementNotP256
        }

        let (platformPrivate, platformPublicX963) = PinProtocolV1.generatePlatformKeyPair()
        let sharedSecret = try PinProtocolV1.sharedSecret(
            platformPrivate: platformPrivate, authenticatorPublicX963: authX963)

        let pinHashEnc = try PinProtocolV1.pinHashEnc(sharedSecret: sharedSecret, pin: pin)
        let platformCOSE = try COSEKey.encodeEC2(x963: platformPublicX963)

        let ptResponse = try await channel.sendCTAP(
            CTAP2.getPinTokenRequest(platformKeyAgreement: platformCOSE, pinHashEnc: pinHashEnc))
        let tokenEnc = try CTAP2.parseGetPinTokenResponse(ptResponse)

        return try PinProtocolV1.decryptPinToken(sharedSecret: sharedSecret, pinTokenEnc: tokenEnc)
    }
}
#endif
