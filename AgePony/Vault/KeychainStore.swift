//
//  KeychainStore.swift
//  AgePony
//
//  Minimal Keychain wrapper for AgePony's vault secrets:
//
//    - The vault master key, stored WhenUnlockedThisDeviceOnly, behind a
//      biometric ACL in Biometric mode or with no ACL in No lock mode.
//      Re-enrolling Face ID / Touch ID invalidates the biometric entry, which is
//      a security feature surfaced in the About screen.
//    - The password device secret (5.0.1, audit M-2): 32 random bytes mixed into
//      the app password's key-encryption key, so a copy of vault.key.pw is
//      useless off this phone. This-device-only, never in a backup.
//    - Small settings secrets such as the proxy password (5.0.1, audit L-21).
//
//  Replacing the master key (L-25): the new item is added under a staging
//  account before the old one is deleted, so a crash or a failed add between the
//  two never leaves the vault with no key. Loading falls back to the staging
//  item, which is what a crash in that window leaves behind.
//

import Foundation
import Security

public enum KeychainError: Error, Equatable {
    case unhandled(OSStatus)
    case notFound
    case malformedData
    case accessControlFailed
}

/// Words for the screen, with the OSStatus, so a report carries a real code
/// instead of "KeychainError error 0" (plan 2.8).
extension KeychainError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unhandled(let status):
            let detail = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown error"
            return "The Keychain refused the request (\(status): \(detail))."
        case .notFound:
            return "The vault key isn't in the Keychain."
        case .malformedData:
            return "The vault key in the Keychain is damaged."
        case .accessControlFailed:
            return "iOS couldn't set up the Keychain protection for the vault key."
        }
    }
}

public enum KeychainStore {

    /// Service identifier for the Keychain item holding the vault master key.
    public static let masterKeyService = "com.agepony.app.vault.master"

    /// Attribute account used inside the Keychain item.
    public static let masterKeyAccount = "vault-master-v1"
    static let stagingAccount = "vault-master-v1.staging"

    static let deviceSecretService = "com.agepony.app.vault.password"
    static let deviceSecretAccount = "password-bind-v1"

    static let settingsService = "com.agepony.app.settings"

    // MARK: - Master key

    /// Insert or replace the master key without a window in which none exists.
    public static func storeMasterKey(_ key: Data, biometric: Bool = true) throws {
        try delete(service: masterKeyService, account: stagingAccount)
        try addMasterKey(key, account: stagingAccount, biometric: biometric)
        try delete(service: masterKeyService, account: masterKeyAccount)
        try addMasterKey(key, account: masterKeyAccount, biometric: biometric)
        try? delete(service: masterKeyService, account: stagingAccount)
    }

    private static func addMasterKey(_ key: Data, account: String, biometric: Bool) throws {
        var attrs: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecAttrAccount as String: account,
            kSecValueData as String:   key,
        ]
        if biometric {
            // Biometric ACL: Face/Touch ID, or the device passcode as fallback.
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.biometryCurrentSet, .or, .devicePasscode],
                nil
            ) else {
                throw KeychainError.accessControlFailed
            }
            attrs[kSecAttrAccessControl as String] = access
        } else {
            // No OS gate (No lock without an app password): readable without a
            // prompt while the device is unlocked.
            attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unhandled(status) }
    }

    /// Fetch the master key. May show the system biometric prompt with `prompt`.
    /// Throws `notFound` if no key is stored.
    public static func loadMasterKey(prompt: String) throws -> Data {
        do {
            return try loadMasterKey(account: masterKeyAccount, prompt: prompt)
        } catch KeychainError.notFound {
            return try loadMasterKey(account: stagingAccount, prompt: prompt)
        }
    }

    private static func loadMasterKey(account: String, prompt: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String:  kSecMatchLimitOne,
            kSecReturnData as String:  true,
            kSecUseOperationPrompt as String: prompt
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { throw KeychainError.notFound }
        guard status == errSecSuccess else { throw KeychainError.unhandled(status) }
        guard let data = item as? Data else { throw KeychainError.malformedData }
        return data
    }

    /// Delete the master key (and any staging copy).
    public static func deleteMasterKey() throws {
        try delete(service: masterKeyService, account: masterKeyAccount)
        try delete(service: masterKeyService, account: stagingAccount)
    }

    /// True if a master key is stored. Does NOT trigger biometric: an
    /// attribute-only query that fails rather than prompting.
    public static func masterKeyExists() -> Bool {
        exists(service: masterKeyService, account: masterKeyAccount)
            || exists(service: masterKeyService, account: stagingAccount)
    }

    // MARK: - Password device secret (audit M-2)

    /// The device secret, creating one if there is none. `created` is true when
    /// it had to be made just now.
    public static func deviceSecret() throws -> (secret: Data, created: Bool) {
        if let existing = try data(service: deviceSecretService, account: deviceSecretAccount) {
            return (existing, false)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw KeychainError.unhandled(errSecAllocate)
        }
        let secret = Data(bytes)
        try setData(secret, service: deviceSecretService, account: deviceSecretAccount)
        return (secret, true)
    }

    /// Delete the device secret. Every password and duress blob sealed under it
    /// becomes permanently unopenable.
    public static func deleteDeviceSecret() throws {
        try delete(service: deviceSecretService, account: deviceSecretAccount)
    }

    // MARK: - Settings secrets (audit L-21)

    public static func settingString(_ account: String) -> String? {
        (try? data(service: settingsService, account: account)).flatMap { $0 }.map { String(decoding: $0, as: UTF8.self) }
    }

    /// Store a settings secret; nil or empty deletes it.
    public static func setSettingString(_ value: String?, account: String) {
        guard let value, !value.isEmpty else {
            try? delete(service: settingsService, account: account)
            return
        }
        try? setData(Data(value.utf8), service: settingsService, account: account)
    }

    public static func deleteAllSettingSecrets() {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: settingsService,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Plain items

    private static func data(service: String, account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String:  kSecMatchLimitOne,
            kSecReturnData as String:  true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.unhandled(status) }
        guard let data = item as? Data else { throw KeychainError.malformedData }
        return data
    }

    private static func setData(_ value: Data, service: String, account: String) throws {
        try delete(service: service, account: account)
        let attrs: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String:   value,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unhandled(status) }
    }

    private static func delete(service: String, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.unhandled(status)
        }
    }

    private static func exists(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String:  kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
        ]
        var item: CFTypeRef?
        // errSecInteractionNotAllowed means "exists but locked": still counts.
        return SecItemCopyMatching(query as CFDictionary, &item) != errSecItemNotFound
    }
}
