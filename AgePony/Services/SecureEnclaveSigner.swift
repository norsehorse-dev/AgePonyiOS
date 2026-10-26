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
//  Presence: keys made from 5.0.1 on carry `.userPresence` in their access
//  control (audit L-25), so the Enclave itself refuses to sign without Face ID,
//  Touch ID or the passcode, not only the app's gate in front of it. The sign
//  flows prompt through BiometricGate first and the Enclave reuses that
//  context, so it's still one prompt. Keys made before 5.0.1 keep the access
//  control they were made with; the Enclave can't change it.
//

import Foundation
import CryptoKit
import Security
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
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence], nil
            ) else {
                throw SecureEnclaveSignerError.generationFailed("access control")
            }
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
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
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        try sign(
            messageHash: hash.digest(message),
            identity: identity,
            namespace: namespace,
            hash: hash
        )
    }

    /// Sign a message *digest* with a Secure Enclave identity.
    ///
    /// SSHSIG covers only the hash, so the caller can have streamed a file of any
    /// size past a hasher rather than holding it. The Enclave signs the SSHSIG
    /// signed-data blob either way; nothing about the hardware path changes.
    public static func sign(
        messageHash: Data,
        identity: StoredIdentity,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: identity.privateKeyMaterial,
                authenticationContext: BiometricGate.recentContext()
            )
        } catch {
            throw SecureEnclaveSignerError.malformedKeyData
        }

        try hash.validate(digest: messageHash)
        let signed = SSHSig.signedData(messageHash: messageHash, namespace: namespace, hash: hash)
        do {
            let sig = try key.signature(for: signed)
            return try SSHSigner.assembleECDSAP256(
                rawRS: sig.rawRepresentation,
                publicKeyX963: key.publicKey.x963Representation,
                namespace: namespace,
                hash: hash
            )
        } catch {
            throw SecureEnclaveSignerError.signFailed(String(describing: error))
        }
    }
}
