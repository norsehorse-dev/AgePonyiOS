//
//  SecureEnclaveSigner.swift
//  AgePony
//
//  Hardware-backed signing with a Secure Enclave P-256 key. The private key is
//  generated inside the Secure Enclave and never leaves it — the vault stores
//  only the key's opaque `dataRepresentation` (an SE-encrypted blob that is
//  useless without this device's Enclave) and the public key in SSH wire form.
//
//  Signing produces an `ecdsa-sha2-nistp256` SSHSIG, byte-identical to what
//  `ssh-keygen -Y sign` would emit for an ecdsa key — the wire format is the
//  same whether the key lives in the Enclave or in software (see
//  SSHSigner.assembleECDSAP256 / SSHSigECDSATests). The Enclave just supplies
//  the raw r||s; AgePonyCore assembles the signature.
//
//  Presence is enforced by the app's existing biometric gate in the sign
//  flows, consistent with how the SSH signing identities behave. The Enclave
//  guarantees the private key is non-exportable and hardware-bound regardless.
//

import Foundation
import CryptoKit
import AgePonyCore

public enum SecureEnclaveSignerError: Error, Equatable {
    case unavailable
    case generationFailed(String)
    case malformedKeyData
    case signFailed(String)
}

public enum SecureEnclaveSigner {

    /// Whether this device has a Secure Enclave available for key generation.
    public static var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    /// Generate a fresh Secure Enclave P-256 signing key.
    ///
    /// - Returns:
    ///   - privateBlob: the SE key's `dataRepresentation` — persist this as the
    ///     identity's `privateKeyMaterial`. It cannot reconstruct the key on
    ///     any other device.
    ///   - publicWire: the `ecdsa-sha2-nistp256` SSH wire blob — persist this as
    ///     `publicKeyMaterial` (it matches verification and trusted-signer
    ///     comparison directly).
    public static func generate() throws -> (privateBlob: Data, publicWire: Data) {
        guard SecureEnclave.isAvailable else { throw SecureEnclaveSignerError.unavailable }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey()
            let wire = SSHSig.ecdsaP256PublicKeyWire(x963Q: key.publicKey.x963Representation)
            return (key.dataRepresentation, wire)
        } catch {
            throw SecureEnclaveSignerError.generationFailed(String(describing: error))
        }
    }

    /// Sign `message` with a Secure Enclave identity, producing an armored
    /// `ecdsa-sha2-nistp256` SSHSIG.
    public static func sign(
        message: Data,
        identity: StoredIdentity,
        namespace: String = SSHSig.defaultNamespace
    ) throws -> String {
        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: identity.privateKeyMaterial
            )
        } catch {
            throw SecureEnclaveSignerError.malformedKeyData
        }

        let signed = SSHSig.signedData(message: message, namespace: namespace, hash: .sha512)
        do {
            let sig = try key.signature(for: signed)
            return try SSHSigner.assembleECDSAP256(
                message: message,
                rawRS: sig.rawRepresentation,
                publicKeyX963: key.publicKey.x963Representation,
                namespace: namespace
            )
        } catch {
            throw SecureEnclaveSignerError.signFailed(String(describing: error))
        }
    }
}
