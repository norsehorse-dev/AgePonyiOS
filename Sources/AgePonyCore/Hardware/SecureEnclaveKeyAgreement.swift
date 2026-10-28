//
//  SecureEnclaveKeyAgreement.swift
//  AgePonyCore
//
//  The Secure Enclave behind a `TagIdentity`: P-256 ECDH with a key that never
//  leaves this device's hardware. The vault keeps only the key's opaque
//  `dataRepresentation`, which no other device's Enclave can use.
//
//  By default not invalidated by Face ID / Touch ID re-enrolment (no
//  `.biometryCurrentSet`), matching Android, where a hardware key survives a new
//  fingerprint. With `.userPresence`, every use needs Face ID, Touch ID or the
//  passcode; an `LAContext` the app has just evaluated satisfies that without a
//  second prompt.
//
//  5.1.0 (E6): `.biometryCurrentSet` is the opt-in for the Face ID only vault
//  lock. Every use needs Face ID or Touch ID as enrolled when the key was made,
//  and the passcode never works. Resetting Face ID or adding a face destroys
//  the key for good. The access control is fixed when the key is made, so the
//  vault doesn't need to record it: the Enclave enforces it on every use.
//
//  Apple platforms only. `swift test` on Linux runs the same `TagIdentity` path with
//  `P256SoftwareKey`.
//

#if os(iOS) || os(macOS)
import Foundation
import CryptoKit
import LocalAuthentication
import Security

public enum SecureEnclaveKeyError: Error, Equatable {
    case unavailable
    case accessControl
    case invalidKeyData
    case keyAgreementFailed(String)
    /// A key with its ML-KEM half in the Secure Enclave (made on iOS 26 or later) used
    /// where that isn't available, e.g. a vault restored onto an older system (5.1.0 RC3).
    case requiresIOS26
}

/// What a new Enclave key asks for on each use (5.1.0, E6).
public enum SecureEnclaveKeyProtection: String, CaseIterable, Sendable {
    /// No prompt from the Enclave: the open vault and the app's own prompt are
    /// the gate.
    case noPrompt
    /// Face ID, Touch ID or the device passcode. Survives re-enrolment.
    case userPresence
    /// Face ID or Touch ID as currently enrolled, and nothing else. A reset or a
    /// new face or finger destroys the key for good.
    case biometryCurrentSet

    /// The flags the key is made with.
    public var accessControlFlags: SecAccessControlCreateFlags {
        switch self {
        case .noPrompt:           return [.privateKeyUsage]
        case .userPresence:       return [.privateKeyUsage, .userPresence]
        case .biometryCurrentSet: return [.privateKeyUsage, .biometryCurrentSet]
        }
    }
}

public struct SecureEnclaveKeyAgreement: P256KeyAgreement {
    let dataRepresentation: Data
    let context: LAContext?

    public init(dataRepresentation: Data, authenticationContext: LAContext? = nil) {
        self.dataRepresentation = dataRepresentation
        self.context = authenticationContext
    }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Make a new Enclave key. Returns its `dataRepresentation` (persist it) and the
    /// 65-byte uncompressed public point.
    public static func generate(requirePresence: Bool) throws -> (dataRepresentation: Data, publicUncompressed: Data) {
        try generate(protection: requirePresence ? .userPresence : .noPrompt)
    }

    /// Make a new Enclave key with the given per-use protection (5.1.0, E6).
    public static func generate(protection: SecureEnclaveKeyProtection) throws -> (dataRepresentation: Data, publicUncompressed: Data) {
        guard SecureEnclave.isAvailable else { throw SecureEnclaveKeyError.unavailable }
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, protection.accessControlFlags, nil
        ) else { throw SecureEnclaveKeyError.accessControl }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        return (key.dataRepresentation, key.publicKey.x963Representation)
    }

    /// The uncompressed public point, read back from the key (no prompt).
    public func publicUncompressed() throws -> Data {
        try key().publicKey.x963Representation
    }

    public func sharedX(peerUncompressed: Data) throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerUncompressed)
        let k = try key()
        do {
            let shared = try k.sharedSecretFromKeyAgreement(with: peer)
            return shared.withUnsafeBytes { Data($0) }
        } catch {
            throw SecureEnclaveKeyError.keyAgreementFailed(String(describing: error))
        }
    }

    private func key() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        do {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: dataRepresentation, authenticationContext: context
            )
        } catch {
            throw SecureEnclaveKeyError.invalidKeyData
        }
    }
}
#endif
