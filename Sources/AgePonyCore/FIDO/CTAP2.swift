//
//  CTAP2.swift
//  AgePonyCore — FIDO support
//
//  The CTAP2 authenticator API, just the two commands SSH security keys use:
//  authenticatorMakeCredential (0x01) to enrol a key, and
//  authenticatorGetAssertion (0x02) to sign with it. Each request is a command
//  byte followed by a canonical CBOR map; each response is a CBOR map.
//
//  The bytes here are produced/parsed in pure Swift and pinned against
//  reference vectors. The CoreNFC transport that carries them to a physical key
//  (APDU framing, applet select, response chaining) is a separate, device-bound
//  layer.
//
//  Mapping to SSH sk SSHSIG (see SSHSig.skAuthenticatorMessage): set rp.id to
//  "ssh:" so the authenticator hashes the same rpIdHash ssh-keygen expects, and
//  pass clientDataHash = SHA256(SSHSIG signed-data). The authenticator then
//  signs rpIdHash || flags || signCount || clientDataHash, which is exactly the
//  sk authenticator message. The raw signature plus flags/signCount feed
//  SSHSigner.assembleSkEd25519 / assembleSkEcdsaP256.
//
//  One wire detail: an ES256 (P-256) authenticator returns its signature as
//  ASN.1 DER, while assembleSkEcdsaP256 wants raw r||s. Use
//  CTAP2.rawP256Signature(fromDER:) to convert. Ed25519 signatures are already
//  raw 64 bytes.
//

import Foundation
import CryptoKit

public enum CTAP2Error: Error, Equatable {
    case missingAuthenticatorData
    case missingSignature
    case missingAttestedCredentialData
    case missingKeyAgreement
    case missingPinToken
}

public enum CTAP2 {

    // Command bytes the NFC transport prepends to the CBOR request body.
    public static let cmdMakeCredential: UInt8 = 0x01
    public static let cmdGetAssertion: UInt8 = 0x02
    public static let cmdClientPin: UInt8 = 0x06

    // clientPin sub-commands (request key 2).
    public static let subGetKeyAgreement = 2
    public static let subGetPinToken = 5

    // COSE algorithm identifiers.
    public static let algEd25519 = -8   // EdDSA
    public static let algES256 = -7     // ECDSA P-256 / SHA-256

    // MARK: - Requests

    /// Build an authenticatorMakeCredential request (command byte + CBOR).
    ///
    /// Defaults match what SSH enrolment needs: rp.id "ssh:", a placeholder
    /// non-resident user, and Ed25519-then-ES256 algorithm preference. The
    /// `clientDataHash` is irrelevant to later signing (attestation is ignored),
    /// so callers may pass a random 32-byte value.
    public static func makeCredentialRequest(
        clientDataHash: Data,
        rpId: String = "ssh:",
        userId: Data = Data([0x01]),
        userName: String = "ssh:",
        algorithms: [Int] = [algEd25519, algES256],
        residentKey: Bool = false,
        pinUvAuthParam: Data? = nil,
        pinUvAuthProtocol: Int? = nil
    ) -> Data {
        let pubKeyCredParams = CBOR.array(algorithms.map { alg in
            CBOR.map([
                (.text("alg"), .int(alg)),
                (.text("type"), .text("public-key")),
            ])
        })
        var pairs: [(CBOR, CBOR)] = [
            (.int(1), .bytes(clientDataHash)),
            (.int(2), .map([(.text("id"), .text(rpId))])),
            (.int(3), .map([
                (.text("id"), .bytes(userId)),
                (.text("name"), .text(userName)),
            ])),
            (.int(4), pubKeyCredParams),
            (.int(7), .map([(.text("rk"), .bool(residentKey))])),
        ]
        if let param = pinUvAuthParam, let proto = pinUvAuthProtocol {
            pairs.append((.int(8), .bytes(param)))
            pairs.append((.int(9), .int(proto)))
        }
        return Data([cmdMakeCredential]) + CBOR.map(pairs).encoded()
    }

    /// Build an authenticatorGetAssertion request (command byte + CBOR).
    ///
    /// `clientDataHash` must be SHA256 of the SSHSIG signed-data blob.
    public static func getAssertionRequest(
        clientDataHash: Data,
        allowCredentialIds: [Data],
        rpId: String = "ssh:",
        userPresence: Bool = true,
        pinUvAuthParam: Data? = nil,
        pinUvAuthProtocol: Int? = nil
    ) -> Data {
        let allowList = CBOR.array(allowCredentialIds.map { id in
            CBOR.map([
                (.text("type"), .text("public-key")),
                (.text("id"), .bytes(id)),
            ])
        })
        var pairs: [(CBOR, CBOR)] = [
            (.int(1), .text(rpId)),
            (.int(2), .bytes(clientDataHash)),
            (.int(3), allowList),
            (.int(5), .map([(.text("up"), .bool(userPresence))])),
        ]
        if let param = pinUvAuthParam, let proto = pinUvAuthProtocol {
            // getAssertion uses keys 6/7 for pinUvAuthParam/pinUvAuthProtocol
            // (makeCredential uses 8/9 — the two commands differ here).
            pairs.append((.int(6), .bytes(param)))
            pairs.append((.int(7), .int(proto)))
        }
        return Data([cmdGetAssertion]) + CBOR.map(pairs).encoded()
    }

    // MARK: - Responses

    public struct MakeCredentialResult: Equatable {
        public let credentialId: Data
        public let publicKey: COSEPublicKey
        public let signCount: UInt32
    }

    public struct GetAssertionResult: Equatable {
        /// Present when the authenticator echoes the credential (it may omit it
        /// for a single-entry allow list); fall back to the id you requested.
        public let credentialId: Data?
        public let authenticatorData: AuthenticatorData
        public let signature: Data
    }

    /// Parse an authenticatorMakeCredential response. Response map keys:
    /// 1 fmt, 2 authData, 3 attStmt. We read the public key and credential id
    /// out of authData's attested credential data and ignore the attestation
    /// statement entirely.
    public static func parseMakeCredentialResponse(_ data: Data) throws -> MakeCredentialResult {
        let cbor = try CBORReader.decode(data)
        guard let authBytes = cbor.value(forIntKey: 2)?.bytesValue else {
            throw CTAP2Error.missingAuthenticatorData
        }
        let authData = try AuthenticatorData(authBytes)
        guard let acd = authData.attestedCredentialData else {
            throw CTAP2Error.missingAttestedCredentialData
        }
        return MakeCredentialResult(
            credentialId: acd.credentialId,
            publicKey: acd.credentialPublicKey,
            signCount: authData.signCount
        )
    }

    /// Parse an authenticatorGetAssertion response. Response map keys:
    /// 1 credential{type,id}, 2 authData, 3 signature, 4 user, 5 count.
    public static func parseGetAssertionResponse(_ data: Data) throws -> GetAssertionResult {
        let cbor = try CBORReader.decode(data)
        guard let authBytes = cbor.value(forIntKey: 2)?.bytesValue else {
            throw CTAP2Error.missingAuthenticatorData
        }
        guard let signature = cbor.value(forIntKey: 3)?.bytesValue else {
            throw CTAP2Error.missingSignature
        }
        let authData = try AuthenticatorData(authBytes)
        let credentialId = cbor.value(forIntKey: 1)?.value(forTextKey: "id")?.bytesValue
        return GetAssertionResult(
            credentialId: credentialId,
            authenticatorData: authData,
            signature: signature
        )
    }

    // MARK: - clientPin (PIN/UV auth protocol)

    /// getKeyAgreement (sub-command 2): ask the authenticator for its P-256
    /// key-agreement public key. Request map: { 1: protocol, 2: 2 }.
    public static func getKeyAgreementRequest(pinUvAuthProtocol: Int = PinProtocolV1.version) -> Data {
        let map = CBOR.map([
            (.int(1), .int(pinUvAuthProtocol)),
            (.int(2), .int(subGetKeyAgreement)),
        ])
        return Data([cmdClientPin]) + map.encoded()
    }

    /// Parse a getKeyAgreement response { 1: keyAgreement(COSE) } into the
    /// authenticator's P-256 public key.
    public static func parseGetKeyAgreementResponse(_ data: Data) throws -> COSEPublicKey {
        let cbor = try CBORReader.decode(data)
        guard let keyAgreement = cbor.value(forIntKey: 1) else {
            throw CTAP2Error.missingKeyAgreement
        }
        return try COSEKey.decode(keyAgreement)
    }

    /// getPinToken (sub-command 5): exchange the encrypted PIN hash for an
    /// encrypted PIN token. Request map: { 1: protocol, 2: 5, 3: platformKey, 6: pinHashEnc }.
    /// `platformKeyAgreement` is the platform key as a COSE_Key (see
    /// COSEKey.encodeEC2).
    public static func getPinTokenRequest(
        platformKeyAgreement: CBOR,
        pinHashEnc: Data,
        pinUvAuthProtocol: Int = PinProtocolV1.version
    ) -> Data {
        let map = CBOR.map([
            (.int(1), .int(pinUvAuthProtocol)),
            (.int(2), .int(subGetPinToken)),
            (.int(3), platformKeyAgreement),
            (.int(6), .bytes(pinHashEnc)),
        ])
        return Data([cmdClientPin]) + map.encoded()
    }

    /// Parse a getPinToken response { 2: pinUvAuthToken } into the *encrypted*
    /// PIN token (decrypt with PinProtocolV1.decryptPinToken).
    public static func parseGetPinTokenResponse(_ data: Data) throws -> Data {
        let cbor = try CBORReader.decode(data)
        guard let token = cbor.value(forIntKey: 2)?.bytesValue else {
            throw CTAP2Error.missingPinToken
        }
        return token
    }

    // MARK: - Signature conversion

    /// Convert a FIDO ES256 assertion signature (ASN.1 DER) into the raw 64-byte
    /// r||s that SSHSigner.assembleSkEcdsaP256 expects. Ed25519 signatures are
    /// already raw and need no conversion.
    public static func rawP256Signature(fromDER der: Data) throws -> Data {
        try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
    }
}
