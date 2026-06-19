//
//  KeychainStore.swift
//  AgePony
//
//  Minimal Keychain wrapper specialized for AgePony's vault master key.
//  Mirrors the EntityDesk Phase 5 pattern: single 32-byte AES-GCM master
//  key, stored with kSecAttrAccessibleWhenUnlockedThisDeviceOnly and a
//  biometric ACL. Re-enrolling Face ID / Touch ID invalidates the entry,
//  which is a security feature surfaced in the About screen.
//

import Foundation
import Security

public enum KeychainError: Error, Equatable {
    case unhandled(OSStatus)
    case notFound
    case malformedData
    case accessControlFailed
}

public enum KeychainStore {

    /// Service identifier for the Keychain item holding the vault master key.
    /// One entry per app install per device, scoped to AgePony only.
    public static let masterKeyService = "com.agepony.app.vault.master"

    /// Attribute account used inside the Keychain item.
    public static let masterKeyAccount = "vault-master-v1"

    // MARK: - Master key

    /// Insert or replace the master key. Caller is responsible for generating
    /// a fresh 32-byte key via CryptoKit's SymmetricKey when bootstrapping a
    /// new vault.
    public static func storeMasterKey(_ key: Data) throws {
        // Try delete first so we always end in a known state.
        _ = try? deleteMasterKey()

        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode],
            nil
        ) else {
            throw KeychainError.accessControlFailed
        }

        let attrs: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecAttrAccount as String: masterKeyAccount,
            kSecValueData as String:   key,
            kSecAttrAccessControl as String: access
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandled(status)
        }
    }

    /// Fetch the master key. Triggers a biometric prompt via the OS — caller
    /// should provide a reason via `prompt`. Throws `notFound` if no key has
    /// been stored yet (first-launch / fresh-install case).
    public static func loadMasterKey(prompt: String) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecAttrAccount as String: masterKeyAccount,
            kSecMatchLimit as String:  kSecMatchLimitOne,
            kSecReturnData as String:  true,
            kSecUseOperationPrompt as String: prompt
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            throw KeychainError.notFound
        }
        guard status == errSecSuccess else {
            throw KeychainError.unhandled(status)
        }
        guard let data = item as? Data else {
            throw KeychainError.malformedData
        }
        _ = query  // silence unused for warning-cleanliness
        return data
    }

    /// Delete the master key. Used for "Reset App" flows.
    public static func deleteMasterKey() throws {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecAttrAccount as String: masterKeyAccount
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.unhandled(status)
        }
    }

    /// True if a master key has been provisioned. Does NOT trigger biometric.
    /// Implementation uses an attribute-only query with kSecReturnAttributes,
    /// which doesn't require the protected value to be read.
    public static func masterKeyExists() -> Bool {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecAttrAccount as String: masterKeyAccount,
            kSecMatchLimit as String:  kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        // `errSecInteractionNotAllowed` here means "exists but locked" — still
        // counts as existing. `errSecItemNotFound` is the only true absence.
        return status != errSecItemNotFound
    }
}
