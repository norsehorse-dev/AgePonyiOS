//
//  KeychainStore.swift
//  AgePony
//
//  Minimal Keychain wrapper for AgePony's vault secrets:
//
//    - The vault master key, stored WhenUnlockedThisDeviceOnly, behind a
//      biometric ACL in Biometric mode, behind `.biometryCurrentSet` alone in
//      Face ID only mode (5.1.0, E6), or with no ACL in No lock mode.
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
import LocalAuthentication

public enum KeychainError: Error, Equatable {
    case unhandled(OSStatus)
    case notFound
    case malformedData
    case accessControlFailed
    /// Every protection in the setup ladder was refused (5.1.0). The codes are
    /// in the order they were tried.
    case protectionRefused([OSStatus])
    /// iOS wouldn't store the vault key behind Face ID or Touch ID alone
    /// (5.1.0, E6). The lock stays as it was.
    case biometryOnlyRefused(OSStatus)
    /// Face ID only: the item is gone or no longer opens, which is what a reset
    /// of Face ID or a new face does to it (E6). The app password opens the
    /// vault and puts a fresh item back.
    case biometryChanged
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
        case .protectionRefused(let codes):
            let list = codes.map(String.init).joined(separator: ", ")
            return "iOS wouldn't store the vault key behind Face ID, Touch ID or the passcode (codes \(list))."
        case .biometryOnlyRefused(let status):
            return String(localized: "iOS wouldn't store the vault key behind Face ID or Touch ID alone (code \(String(status))). The lock is unchanged.")
        case .biometryChanged:
            return String(localized: "Face ID or Touch ID changed on this iPhone, so it can't open the vault until the app password is entered once.")
        }
    }
}

/// How the vault key is protected in the Keychain when the lock uses the
/// system prompt (5.1.0).
///
/// Up to 5.0.1 there was only the first one, and when iOS refused it, setup
/// stopped with no way forward. Some iPhones with a passcode set refuse it with
/// errSecAuthFailed (-25293) before any prompt appears. Setup now walks down
/// this list, and every step still puts a system prompt in front of the key.
public enum MasterKeyProtection: String, CaseIterable, Sendable {
    /// Face ID or Touch ID as currently enrolled, or the passcode. A new face
    /// or finger invalidates it. What every version before 5.1.0 used.
    case currentBiometryOrPasscode
    /// Face ID or Touch ID with any enrolment, or the passcode (`.userPresence`).
    case userPresence
    /// The device passcode only.
    case passcodeOnly

    var flags: SecAccessControlCreateFlags {
        switch self {
        case .currentBiometryOrPasscode: return [.biometryCurrentSet, .or, .devicePasscode]
        case .userPresence:              return [.userPresence]
        case .passcodeOnly:              return [.devicePasscode]
        }
    }

    /// The order setup tries them in. Without enrolled biometrics the first
    /// step can't hold anyway, so it's skipped.
    static func ladder(biometryEnrolled: Bool) -> [MasterKeyProtection] {
        biometryEnrolled
            ? [.currentBiometryOrPasscode, .userPresence, .passcodeOnly]
            : [.userPresence, .passcodeOnly]
    }
}

/// The vault key's protection in Face ID only mode (5.1.0, E6): Face ID or
/// Touch ID as currently enrolled, and nothing else. No `.devicePasscode`, no
/// `.userPresence`, and never `.biometryAny`, which would let anyone with the
/// passcode add a face in Settings and then open the item.
///
/// Kept apart from `MasterKeyProtection` on purpose: that enum is the setup
/// ladder for the default lock, and every step of it keeps a passcode prompt.
enum BiometryOnlyKeyProtection {
    static var flags: SecAccessControlCreateFlags { [.biometryCurrentSet] }
    /// The tag on an item stored this way (`kSecAttrDescription`), also what
    /// `vault.keyProtection` records. The tag on the item is what counts: an
    /// older version that rewrites the item leaves it off.
    static let storedName = "biometryCurrentSetOnly"
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
    /// The staging copy is added first and decides the protection; the real
    /// item then gets the same one, so the two never differ.
    public static func storeMasterKey(_ key: Data, biometric: Bool = true) throws {
        try delete(service: masterKeyService, account: stagingAccount)
        let used = try addMasterKey(key, account: stagingAccount, biometric: biometric, ladder: nil)
        try delete(service: masterKeyService, account: masterKeyAccount)
        try addMasterKey(key, account: masterKeyAccount, biometric: biometric, ladder: used.map { [$0] })
        try? delete(service: masterKeyService, account: stagingAccount)
        recordProtection(used)
    }

    /// Insert or replace the master key behind Face ID or Touch ID alone (E6),
    /// with the same staging order as `storeMasterKey`. No ladder: if iOS refuses
    /// the staging copy, nothing has changed and `biometryOnlyRefused` says why.
    public static func storeBiometryOnlyMasterKey(_ key: Data) throws {
        try delete(service: masterKeyService, account: stagingAccount)
        try addBiometryOnlyMasterKey(key, account: stagingAccount)
        try delete(service: masterKeyService, account: masterKeyAccount)
        try addBiometryOnlyMasterKey(key, account: masterKeyAccount)
        try? delete(service: masterKeyService, account: stagingAccount)
        UserDefaults.standard.set(BiometryOnlyKeyProtection.storedName, forKey: protectionDefaultsKey)
    }

    private static func addBiometryOnlyMasterKey(_ key: Data, account: String) throws {
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, BiometryOnlyKeyProtection.flags, nil
        ) else { throw KeychainError.biometryOnlyRefused(errSecParam) }
        let attrs = biometryOnlyItemAttributes(key, account: account, access: access)
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.biometryOnlyRefused(status) }
    }

    @discardableResult
    private static func addMasterKey(_ key: Data, account: String, biometric: Bool,
                                     ladder fixed: [MasterKeyProtection]?) throws -> MasterKeyProtection? {
        let base: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecAttrAccount as String: account,
            kSecValueData as String:   key,
        ]
        guard biometric else {
            // No OS gate (No lock without an app password): readable without a
            // prompt while the device is unlocked.
            var attrs = base
            attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let status = SecItemAdd(attrs as CFDictionary, nil)
            guard status == errSecSuccess else { throw KeychainError.unhandled(status) }
            return nil
        }
        let ladder = fixed ?? MasterKeyProtection.ladder(
            biometryEnrolled: BiometricGate.availableBiometric() != .none)
        var refused: [OSStatus] = []
        for protection in ladder {
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, protection.flags, nil
            ) else {
                refused.append(errSecParam)
                continue
            }
            var attrs = base
            attrs[kSecAttrAccessControl as String] = access
            let status = SecItemAdd(attrs as CFDictionary, nil)
            if status == errSecSuccess { return protection }
            refused.append(status)
        }
        throw KeychainError.protectionRefused(refused)
    }

    // MARK: - Which protection the key got (5.1.0)

    static let protectionDefaultsKey = "vault.keyProtection"

    /// The protection the stored vault key got, or nil when it has none or was
    /// stored before 5.1.0 (those all used `.currentBiometryOrPasscode`).
    public static var storedProtection: MasterKeyProtection? {
        UserDefaults.standard.string(forKey: protectionDefaultsKey).flatMap(MasterKeyProtection.init(rawValue:))
    }

    /// The attributes a Face ID only item is added with, tag included.
    static func biometryOnlyItemAttributes(_ key: Data, account: String, access: SecAccessControl) -> [String: Any] {
        [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrService as String:       masterKeyService,
            kSecAttrAccount as String:       account,
            kSecAttrDescription as String:   BiometryOnlyKeyProtection.storedName,
            kSecValueData as String:         key,
            kSecAttrAccessControl as String: access,
        ]
    }

    /// An attribute-only query for a tagged item: no data, never a prompt.
    static func biometryOnlyTagQuery(account: String) -> [String: Any] {
        [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      masterKeyService,
            kSecAttrAccount as String:      account,
            kSecAttrDescription as String:  BiometryOnlyKeyProtection.storedName,
            kSecMatchLimit as String:       kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]
    }

    /// Whether the vault key in the Keychain carries the Face ID only tag (E6
    /// review: read from the item, not from preferences). Face ID only unlock
    /// reads the item only when this is true, so it never opens a copy the
    /// passcode could also open. The staging copy counts only when there is no
    /// real item, matching `loadMasterKey`.
    public static var storedIsBiometryOnly: Bool {
        let account = exists(service: masterKeyService, account: masterKeyAccount) ? masterKeyAccount : stagingAccount
        var item: CFTypeRef?
        let status = SecItemCopyMatching(biometryOnlyTagQuery(account: account) as CFDictionary, &item)
        // errSecInteractionNotAllowed: a tagged item exists but is locked.
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    private static func recordProtection(_ protection: MasterKeyProtection?) {
        if let protection {
            UserDefaults.standard.set(protection.rawValue, forKey: protectionDefaultsKey)
        } else {
            UserDefaults.standard.removeObject(forKey: protectionDefaultsKey)
        }
    }

    /// Fetch the master key. May show the system biometric prompt with `prompt`.
    /// Throws `notFound` if no key is stored. `context` is an `LAContext` the
    /// caller has already evaluated (Face ID only unlock, E6), used instead of a
    /// second prompt.
    public static func loadMasterKey(prompt: String, context: LAContext? = nil) throws -> Data {
        do {
            return try loadMasterKey(account: masterKeyAccount, prompt: prompt, context: context)
        } catch KeychainError.notFound {
            return try loadMasterKey(account: stagingAccount, prompt: prompt, context: context)
        }
    }

    private static func loadMasterKey(account: String, prompt: String, context: LAContext?) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String:  kSecMatchLimitOne,
            kSecReturnData as String:  true,
            kSecUseOperationPrompt as String: prompt
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
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
        recordProtection(nil)
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
