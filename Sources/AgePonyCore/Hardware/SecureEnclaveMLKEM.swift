//
//  SecureEnclaveMLKEM.swift
//  AgePonyCore
//
//  5.1.0 RC3 (E8): the ML-KEM-768 half of a new `age1tagpq1` hardware key, made and
//  kept in the Secure Enclave (CryptoKit `SecureEnclave.MLKEM768`, iOS 26 / macOS 26).
//  With the P-256 half already there (SecureEnclaveKeyAgreement), no part of the private
//  key is in the vault: it keeps two opaque `dataRepresentation` blobs that no other
//  device's Enclave can use (SecureEnclaveTagPQ.swift has the layout).
//
//  Same access control as the P-256 key, from the same `SecureEnclaveKeyProtection`:
//  `noPrompt`, `userPresence`, or E6's Face ID only `biometryCurrentSet`. The RC3 spike
//  (S4c) showed the Enclave accepts all three for ML-KEM keys. Hydration hands both keys
//  one `LAContext`, so a key that wants Face ID asks once for the pair.
//
//  Errors map onto `SecureEnclaveKeyError` the way SecureEnclaveKeyAgreement's do, so
//  the app words them the same.
//

#if (os(iOS) || os(macOS)) && compiler(>=6.2)
import Foundation
import CryptoKit
import LocalAuthentication
import Security

@available(iOS 26, macOS 26, *)
public struct SecureEnclaveMLKEM: MLKEMDecapsulation {
    /// The Enclave key's opaque handle. Useless outside this device's Enclave.
    public let dataRepresentation: Data
    /// The 1184-byte encapsulation key, as stored with the recipient, so building this
    /// doesn't need the Enclave.
    public let encapsulationKey: Data
    let context: LAContext?

    public init(dataRepresentation: Data, encapsulationKey: Data, authenticationContext: LAContext? = nil) {
        self.dataRepresentation = dataRepresentation
        self.encapsulationKey = encapsulationKey
        self.context = authenticationContext
    }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Make a new Enclave ML-KEM-768 key with the given per-use protection. Returns its
    /// `dataRepresentation` (persist it) and its 1184-byte encapsulation key.
    public static func generate(protection: SecureEnclaveKeyProtection) throws -> (dataRepresentation: Data, encapsulationKey: Data) {
        guard SecureEnclave.isAvailable else { throw SecureEnclaveKeyError.unavailable }
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, protection.accessControlFlags, nil
        ) else { throw SecureEnclaveKeyError.accessControl }
        let key = try SecureEnclave.MLKEM768.PrivateKey(accessControl: access)
        let ek = key.publicKey.rawRepresentation
        // The same FIPS 203 check every age1tagpq1 recipient gets when it's entered.
        guard AgePonyCore.MLKEM768.isValidEncapsulationKey(ek) else { throw SecureEnclaveKeyError.invalidKeyData }
        return (key.dataRepresentation, ek)
    }

    public func decapsulate(ciphertext: Data) throws -> Data {
        guard ciphertext.count == AgePonyCore.MLKEM768.ciphertextSize else { throw MLKEMError.invalidCiphertextLength }
        let key: SecureEnclave.MLKEM768.PrivateKey
        do {
            key = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: dataRepresentation,
                                                        authenticationContext: context)
        } catch {
            throw SecureEnclaveKeyError.invalidKeyData
        }
        // The Enclave key must be the one the stored recipient names (reading the public
        // key needs no prompt). RC3 review fix 2.
        guard key.publicKey.rawRepresentation == encapsulationKey else { throw SecureEnclaveKeyError.invalidKeyData }
        do {
            return try key.decapsulate(ciphertext).withUnsafeBytes { Data($0) }
        } catch {
            throw SecureEnclaveKeyError.keyAgreementFailed(String(describing: error))
        }
    }
}
#endif
