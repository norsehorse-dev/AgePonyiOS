//
//  SecureEnclaveKeyAgreement.swift
//  AgePonyCore
//
//  The Secure Enclave behind a `TagIdentity`: P-256 ECDH with a key that never
//  leaves this device's hardware. The vault keeps only the key's opaque
//  `dataRepresentation`, which no other device's Enclave can use.
//
//  Not invalidated by Face ID / Touch ID re-enrolment (no `.biometryCurrentSet`),
//  matching Android, where a hardware key survives a new fingerprint. With
//  `requirePresence`, every use needs Face ID, Touch ID or the passcode; an
//  `LAContext` the app has just evaluated satisfies that without a second prompt.
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
        guard SecureEnclave.isAvailable else { throw SecureEnclaveKeyError.unavailable }
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requirePresence { flags.insert(.userPresence) }
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil
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
