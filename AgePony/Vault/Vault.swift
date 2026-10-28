//
//  Vault.swift
//  AgePony
//
//  The Vault is the single source of truth for everything the user stores:
//  identities (private keys), recipients (public keys), encrypted notes, and
//  trusted signers (public keys recognized for signature verification).
//  It's an @Observable so SwiftUI views can bind to its arrays directly.
//
//  Architecture (mirrors EntityDesk Phase 5):
//    - A 32-byte AES-256-GCM master key lives in the Keychain with a
//      biometric ACL (kSecAttrAccessibleWhenUnlockedThisDeviceOnly +
//      biometryCurrentSet + devicePasscode fallback).
//    - The full vault contents are serialized to JSON, sealed with
//      ChaCha20-Poly1305 (CryptoKit's preferred AEAD on iOS — Apple's docs
//      note GCM is also fine, but ChaCha20-Poly1305 is the matching AEAD
//      used elsewhere in age and gives us a single AEAD in the app), and
//      written to `Application Support/AgePony/vault.dat`.
//    - The on-disk format is: 12-byte nonce || ciphertext || 16-byte tag.
//    - On each cold launch / app-foreground after a background interval the
//      master key is re-fetched via biometric, the file is decrypted, and
//      the @Observable arrays are populated.
//
//  Lock rules (5.0.1 security audit, matching Android 5.0.1):
//    - The Keychain copy of the vault key exists only when something should
//      open the vault without the app password: Biometric mode, or No lock with
//      no password. No lock plus a password is password-only (M-3).
//    - A duress password makes the vault password-only (H-1): the Keychain copy
//      is deleted and the lock mode is No lock, so a coerced unlock always goes
//      through the password field, where the decoy can fire.
//    - Face ID only (5.1.0, E6): the Keychain copy sits behind
//      `.biometryCurrentSet` alone and is read only after a Face ID or Touch ID
//      prompt with no passcode button. The mode needs the app password, which
//      opens the vault after a Face ID reset and puts a fresh item back.
//    - The password blob's key is bound to a this-device-only Keychain secret
//      (M-2) and every password attempt goes through a persisted backoff (M-1).
//    - The vault directory is excluded from backups (H-2).
//
//  Migration note (2.0): `signers` was added to the persisted snapshot as an
//  optional field, so vault files written before 2.0 (which have no signers
//  key) still decode — a missing key reads back as nil and is treated as an
//  empty list. Newly written vaults always include the key.
//

import Foundation
import CryptoKit
import Observation
import Security
import LocalAuthentication
import AgePonyCore

@Observable
@MainActor
public final class Vault {

    // MARK: - State

    public private(set) var isUnlocked: Bool = false
    public private(set) var identities: [StoredIdentity] = []
    public private(set) var recipients: [StoredRecipient] = []
    public private(set) var notes: [StoredNote] = []
    public private(set) var signers: [StoredSigner] = []

    /// Recycle bin (4.0.0): soft-deleted identities/recipients, newest first.
    /// Entries age out after `Self.trashRetentionDays`.
    public private(set) var trashedIdentities: [TrashedIdentity] = []
    public private(set) var trashedRecipients: [TrashedRecipient] = []

    // MARK: - Settings (persisted in UserDefaults, surfaced here for binding)

    public var biometricEnabled: Bool {
        get { UserDefaults.standard.object(forKey: SettingsKey.biometricEnabled) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKey.biometricEnabled) }
    }

    /// How the OS gate protects the vault (4.0.0). Defaults to `.biometric`, and
    /// honors a pre-4.0.0 `biometricEnabled = false` as `.none` on first read.
    public var lockMode: LockMode {
        get {
            if let raw = UserDefaults.standard.string(forKey: SettingsKey.lockMode) {
                return LockMode.fromKey(raw)
            }
            return biometricEnabled ? .biometric : .none
        }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: SettingsKey.lockMode) }
    }

    /// The stored lock mode, for code with no Vault at hand (BiometricGate's
    /// in-app prompts follow Face ID only, E6).
    static var storedLockMode: LockMode {
        UserDefaults.standard.string(forKey: SettingsKey.lockMode).map { LockMode.fromKey($0) } ?? .biometric
    }

    /// 5.0.1 (audit M-1): erase the vault once the app password has been entered
    /// wrong `UnlockAttempts.eraseAfter` times in a row. Off by default.
    public var eraseAfterFailedAttempts: Bool {
        get { UserDefaults.standard.bool(forKey: SettingsKey.eraseAfterFailedAttempts) }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKey.eraseAfterFailedAttempts) }
    }

    /// The failed-attempt counter for the app password (audit M-1).
    public let attempts = UnlockAttempts(file: Vault.vaultDirectoryURL().appendingPathComponent("unlock.attempts"))

    /// Which input the app password uses, or nil when no app password is set.
    public var unlockSecretKind: UnlockSecretKind? {
        get {
            guard hasAppPassword,
                  let raw = UserDefaults.standard.string(forKey: SettingsKey.unlockSecretKind)
            else { return nil }
            return UnlockSecretKind(rawValue: raw)
        }
        set { UserDefaults.standard.set(newValue?.rawValue, forKey: SettingsKey.unlockSecretKind) }
    }

    /// Whether an app-owned password/PIN is enrolled (a real key blob on disk).
    public var hasAppPassword: Bool {
        FileManager.default.fileExists(atPath: Self.passwordBlobURL().path)
    }

    /// Whether a duress password is enrolled.
    public var hasDuressPassword: Bool {
        FileManager.default.fileExists(atPath: Self.duressBlobURL().path)
    }

    /// scrypt work factor for passphrase encrypts.
    ///
    /// Clamped to the supported range on read, so a value written by a future
    /// build with a wider range cannot push this one into an allocation it
    /// cannot survive.
    public var scryptWorkFactor: Int {
        get {
            let stored = UserDefaults.standard.object(forKey: SettingsKey.scryptWorkFactor) as? Int
            let value = stored ?? ScryptMemory.defaultWorkFactor
            return min(max(value, ScryptMemory.minimumWorkFactor), ScryptMemory.maximumWorkFactor)
        }
        set {
            let clamped = min(max(newValue, ScryptMemory.minimumWorkFactor),
                              ScryptMemory.maximumWorkFactor)
            UserDefaults.standard.set(clamped, forKey: SettingsKey.scryptWorkFactor)
        }
    }

    public var encryptToSelfDefault: Bool {
        get { UserDefaults.standard.object(forKey: SettingsKey.encryptToSelfDefault) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKey.encryptToSelfDefault) }
    }

    /// A saved recipient ticked by default whenever something is encrypted
    /// (5.0.1): typically a backed-up key, so files encrypted to a hardware key
    /// that can't be backed up still have a second way in. nil for none.
    public var backupRecipientID: UUID? {
        get { UserDefaults.standard.string(forKey: SettingsKey.backupRecipientID).flatMap(UUID.init(uuidString:)) }
        set { UserDefaults.standard.set(newValue?.uuidString, forKey: SettingsKey.backupRecipientID) }
    }

    /// The backup recipient to preselect, when it is still a saved recipient.
    public var backupRecipientSelection: Set<UUID> {
        guard let id = backupRecipientID, recipients.contains(where: { $0.id == id }) else { return [] }
        return [id]
    }

    public var activeIdentityID: UUID? {
        get {
            if let s = UserDefaults.standard.string(forKey: SettingsKey.activeIdentityID) {
                return UUID(uuidString: s)
            }
            return nil
        }
        set {
            UserDefaults.standard.set(newValue?.uuidString, forKey: SettingsKey.activeIdentityID)
        }
    }

    /// Seconds AgePony waits after leaving the app before locking. 0 = immediately.
    public var autoLockGraceSeconds: Int {
        get { UserDefaults.standard.object(forKey: SettingsKey.autoLockGraceSeconds) as? Int ?? 30 }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKey.autoLockGraceSeconds) }
    }

    /// Proxy for the one network call (the GitHub key fetch). Stored as app
    /// preferences, not in the encrypted vault, matching Android.
    public var proxyConfig: ProxyConfig {
        get {
            let d = UserDefaults.standard
            let mode = ProxyConfig.Mode(rawValue: d.string(forKey: SettingsKey.proxyMode) ?? "off") ?? .off
            return ProxyConfig(
                mode: mode,
                host: d.string(forKey: SettingsKey.proxyHost) ?? "",
                port: d.integer(forKey: SettingsKey.proxyPort),
                username: KeychainStore.settingString(SettingsKey.proxyUsername),
                password: KeychainStore.settingString(SettingsKey.proxyPassword)
            )
        }
        set {
            let d = UserDefaults.standard
            d.set(newValue.mode.rawValue, forKey: SettingsKey.proxyMode)
            d.set(newValue.host, forKey: SettingsKey.proxyHost)
            d.set(newValue.port, forKey: SettingsKey.proxyPort)
            // Credentials live in the Keychain, not in preferences (audit L-21).
            KeychainStore.setSettingString(newValue.username, account: SettingsKey.proxyUsername)
            KeychainStore.setSettingString(newValue.password, account: SettingsKey.proxyPassword)
        }
    }

    public var hasCompletedOnboarding: Bool {
        get { UserDefaults.standard.bool(forKey: SettingsKey.hasCompletedOnboarding) }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKey.hasCompletedOnboarding) }
    }

    /// Whether the user has seen (or skipped) the feature walkthrough — the
    /// swipeable tour shown after first setup, separate from the required
    /// identity onboarding. Gates the first-run presentation in HomeView and
    /// can be flipped back on from Settings → "Show walkthrough again".
    public var hasSeenWalkthrough: Bool {
        get { UserDefaults.standard.bool(forKey: SettingsKey.hasSeenWalkthrough) }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKey.hasSeenWalkthrough) }
    }

    // MARK: - Private

    private var masterKey: SymmetricKey?

    /// Passphrase held in memory for a run of passphrase encrypts, dropped when
    /// the vault locks. Never written to disk (3.2.0 ergonomics).
    public var sessionPassphrase: String?

    public init() {
        Self.migrateLegacySettings()
        Self.excludeVaultFromBackup()
    }

    /// One-time fixes for settings older builds left implicit.
    ///   - L-25: a vault from before 4.0.0 has no stored lock mode and derived it
    ///     from the in-app biometric toggle, so flipping that toggle could change
    ///     how the vault locks. Pin the derived value once.
    ///   - L-21: move proxy credentials out of preferences into the Keychain.
    ///   - E6: Face ID only with no app password (5.0.1 can remove it after a
    ///     downgrade) becomes the default lock.
    private static func migrateLegacySettings() {
        let d = UserDefaults.standard
        if d.string(forKey: SettingsKey.lockMode) == nil, isProvisioned() {
            let bio = d.object(forKey: SettingsKey.biometricEnabled) as? Bool ?? true
            d.set((bio ? LockMode.biometric : LockMode.none).rawValue, forKey: SettingsKey.lockMode)
        }
        if let raw = d.string(forKey: SettingsKey.lockMode),
           let normalized = LockMode.fromKey(raw).normalized(hasAppPassword: FileManager.default.fileExists(atPath: passwordBlobURL().path)),
           normalized.rawValue != raw {
            d.set(normalized.rawValue, forKey: SettingsKey.lockMode)
        }
        for key in [SettingsKey.proxyUsername, SettingsKey.proxyPassword] {
            if let old = d.string(forKey: key) {
                if !old.isEmpty { KeychainStore.setSettingString(old, account: key) }
                d.removeObject(forKey: key)
            }
        }
    }

    /// Keep the vault, its key blobs and the attempt counter out of iCloud and
    /// computer backups (audit H-2). The blobs are bound to this device anyway,
    /// but a backup copy would still carry the encrypted vault off the phone.
    private static func excludeVaultFromBackup() {
        var dir = vaultDirectoryURL()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
    }

    // MARK: - Lifecycle

    /// True if a vault has been initialized on this device. Use to gate
    /// "first launch" UI vs. the lock screen. Any one of the vault's pieces
    /// counts (L-25): a vault whose Keychain copy is gone (password-only, or a
    /// lost item) must show the lock screen, never onboarding, which would write
    /// a new vault over it.
    public static func isProvisioned() -> Bool {
        let fm = FileManager.default
        return KeychainStore.masterKeyExists()
            || fm.fileExists(atPath: passwordBlobURL().path)
            || fm.fileExists(atPath: vaultFileURL().path)
    }

    /// Whether the vault file exists on disk.
    public var vaultFileExists: Bool {
        FileManager.default.fileExists(atPath: Self.vaultFileURL().path)
    }

    /// Bootstrap a fresh vault. Generates a master key, stores it under the
    /// biometric ACL, and writes an empty encrypted vault file. Triggers the
    /// system's biometric/passcode prompt (because the ACL fires on first
    /// write too on some iOS versions).
    ///
    /// `lockMode: .none` is for a phone with no passcode (plan 2.8), where iOS
    /// refuses the biometric ACL: the key is stored with no ACL, and the caller
    /// sets an app password straight away, which removes that copy (M-3).
    public func bootstrap(lockMode mode: LockMode = .biometric) async throws {
        // Face ID only needs an app password, which a fresh vault doesn't have
        // yet, so setup always starts from the default lock (E6).
        let initial: LockMode = mode == .biometricOnly ? .biometric : mode
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        try KeychainStore.storeMasterKey(keyData, biometric: initial.requiresBiometricACL)
        lockMode = initial
        attempts.reset()
        self.masterKey = key
        self.identities = []
        self.recipients = []
        self.notes = []
        self.signers = []
        self.trashedIdentities = []
        self.trashedRecipients = []
        try persist()
        self.isUnlocked = true
    }

    /// Unlock an existing vault. Triggers a biometric prompt via the OS.
    public func unlock(prompt: String = "Unlock AgePony") async throws {
        // Password-only while a duress password is set (H-1). A 4.x vault may
        // still hold a Keychain copy until its first password unlock removes it.
        if hasDuressPassword { throw KeychainError.notFound }
        // Face ID only without its password (removed by an older version):
        // the default lock, so the password-less vault still has a way in.
        if let normalized = lockMode.normalized(hasAppPassword: hasAppPassword), normalized != lockMode {
            lockMode = normalized
        }
        let biometryOnly = lockMode == .biometricOnly
        let keyBytes: Data
        if biometryOnly {
            keyBytes = try await loadBiometryOnlyKey(prompt: prompt)
        } else {
            keyBytes = try KeychainStore.loadMasterKey(prompt: prompt)
        }
        let key = SymmetricKey(data: keyBytes)
        let payload = try loadEncryptedVault()
        let snapshot = try decryptVault(payload: payload, key: key)
        self.masterKey = key
        self.identities = snapshot.identities
        self.recipients = snapshot.recipients
        self.notes = snapshot.notes
        self.signers = snapshot.signers ?? []
        self.trashedIdentities = snapshot.trashedIdentities ?? []
        self.trashedRecipients = snapshot.trashedRecipients ?? []
        self.isUnlocked = true
        purgeExpiredTrash()
        // A key that setup could only store behind the passcode (5.1.0) moves
        // up to Face ID / Touch ID once biometrics are enrolled. Best effort:
        // if iOS still refuses, the passcode-only copy stays.
        if !biometryOnly, KeychainStore.storedProtection == .passcodeOnly, BiometricGate.availableBiometric() != .none {
            try? KeychainStore.storeMasterKey(keyBytes, biometric: true)
        } else if !biometryOnly, KeychainStore.storedIsBiometryOnly {
            // A Face ID only item under the default lock (the mode was normalized
            // above): put the passcode back as a way in, through the setup ladder.
            try? KeychainStore.storeMasterKey(keyBytes, biometric: true)
        }
    }

    /// Face ID only (E6): a Face ID or Touch ID prompt with no passcode button,
    /// then the Keychain read with that prompt's context. The item is read only
    /// when it was written behind biometrics alone, so a copy the passcode could
    /// open is never used in this mode; the password unlock replaces it.
    ///
    /// A missing item, or one iOS refuses after biometrics said yes, is what a
    /// Face ID reset or a new face leaves: `biometryChanged`, and the lock screen
    /// asks for the password. `unlock` has already moved a password-less vault
    /// to the default lock, so a password is always there to fall back on.
    ///
    /// Whether the item is biometry-only comes from the tag on the item itself,
    /// not from preferences: an older version that rewrote it left the tag off.
    private func loadBiometryOnlyKey(prompt: String) async throws -> Data {
        if !KeychainStore.storedIsBiometryOnly { throw KeychainError.notFound }
        // Not kept for Secure Enclave keys, as with the default lock's prompt.
        let context = try await BiometricGate.biometricOnlyContext(reason: prompt, remember: false)
        // Anything beyond the biometry just evaluated fails with
        // errSecInteractionNotAllowed instead of showing passcode UI.
        context.interactionNotAllowed = true
        do {
            return try KeychainStore.loadMasterKey(prompt: prompt, context: context)
        } catch KeychainError.notFound {
            throw KeychainError.biometryChanged
        } catch KeychainError.unhandled(let status)
                    where status == errSecAuthFailed || status == errSecInteractionNotAllowed {
            throw KeychainError.biometryChanged
        }
    }

    /// Drop the master key from memory. Called when the app enters background.
    public func lock() {
        BiometricGate.forgetRecentContext()
        TempFileCleanup.sweepKeyFiles()
        masterKey = nil
        identities = []
        recipients = []
        notes = []
        signers = []
        trashedIdentities = []
        trashedRecipients = []
        sessionPassphrase = nil
        isUnlocked = false
    }

    // MARK: - Identity CRUD

    /// `activate: false` for keys that arrived from elsewhere (a transfer or a paper
    /// backup, 5.0.1): they never quietly become the encrypt-to-self key.
    @discardableResult
    public func addIdentity(_ identity: StoredIdentity, activate: Bool = true) throws -> StoredIdentity {
        identities.append(identity)
        // First identity becomes the active one for encrypt-to-self.
        if activate && activeIdentityID == nil {
            activeIdentityID = identity.id
        }
        try persist()
        return identity
    }

    public func renameIdentity(id: UUID, to newName: String) throws {
        guard let idx = identities.firstIndex(where: { $0.id == id }) else { return }
        identities[idx].name = newName
        try persist()
    }

    /// Store what a YubiKey tap learned about a slot's PIN policy (5.1.0 item 1), in
    /// place: same record, same position, same active identity.
    public func setYubiKeyPINPolicy(_ policy: YubiKeyPINPolicy, forIdentity id: UUID) throws {
        guard let idx = identities.firstIndex(where: { $0.id == id }),
              identities[idx].type == .yubikey,
              identities[idx].yubiKeyPINPolicy != policy else { return }
        identities[idx].pinPolicy = policy
        try persist()
    }

    public func deleteIdentity(id: UUID) throws {
        guard let idx = identities.firstIndex(where: { $0.id == id }) else { return }
        let removed = identities.remove(at: idx)
        if activeIdentityID == id {
            activeIdentityID = identities.first?.id
        }
        trashedIdentities.insert(TrashedIdentity(identity: removed, deletedAt: Date()), at: 0)
        try persist()
    }

    public func activeIdentity() -> StoredIdentity? {
        guard let id = activeIdentityID else { return identities.first }
        return identities.first(where: { $0.id == id }) ?? identities.first
    }

    // MARK: - Recipient CRUD (lightweight surface for 1c; expanded in 1e)

    @discardableResult
    public func addRecipient(_ recipient: StoredRecipient) throws -> StoredRecipient {
        recipients.append(recipient)
        try persist()
        return recipient
    }

    /// Rename in place, matching renameIdentity and renameSigner.
    ///
    /// The alternative -- delete then re-add -- has a window where the vault
    /// holds neither copy, and reorders the list on success.
    public func renameRecipient(id: UUID, to newName: String) throws {
        guard let idx = recipients.firstIndex(where: { $0.id == id }) else { return }
        recipients[idx].name = newName
        try persist()
    }

    public func deleteRecipient(id: UUID) throws {
        guard let idx = recipients.firstIndex(where: { $0.id == id }) else { return }
        let removed = recipients.remove(at: idx)
        trashedRecipients.insert(TrashedRecipient(recipient: removed, deletedAt: Date()), at: 0)
        try persist()
    }

    // MARK: - Recycle bin (4.0.0)

    static let trashRetentionDays = 30

    public func restoreIdentity(id: UUID) throws {
        guard let idx = trashedIdentities.firstIndex(where: { $0.identity.id == id }) else { return }
        let restored = trashedIdentities.remove(at: idx).identity
        identities.append(restored)
        if activeIdentityID == nil { activeIdentityID = restored.id }
        try persist()
    }

    public func purgeIdentity(id: UUID) throws {
        let before = trashedIdentities.count
        trashedIdentities.removeAll { $0.identity.id == id }
        if trashedIdentities.count != before { try persist() }
    }

    public func restoreRecipient(id: UUID) throws {
        guard let idx = trashedRecipients.firstIndex(where: { $0.recipient.id == id }) else { return }
        let restored = trashedRecipients.remove(at: idx).recipient
        recipients.append(restored)
        try persist()
    }

    public func purgeRecipient(id: UUID) throws {
        let before = trashedRecipients.count
        trashedRecipients.removeAll { $0.recipient.id == id }
        if trashedRecipients.count != before { try persist() }
    }

    /// Empty the whole recycle bin now.
    public func emptyTrash() throws {
        if trashedIdentities.isEmpty && trashedRecipients.isEmpty { return }
        trashedIdentities = []
        trashedRecipients = []
        try persist()
    }

    /// Drop bin entries older than `trashRetentionDays`. Persists only if something changed.
    public func purgeExpiredTrash() {
        let cutoff = Date().addingTimeInterval(-Double(Self.trashRetentionDays) * 24 * 60 * 60)
        let beforeI = trashedIdentities.count
        let beforeR = trashedRecipients.count
        trashedIdentities.removeAll { $0.deletedAt < cutoff }
        trashedRecipients.removeAll { $0.deletedAt < cutoff }
        if trashedIdentities.count != beforeI || trashedRecipients.count != beforeR {
            try? persist()
        }
    }

    // MARK: - Note CRUD (skeleton for 1c; expanded in 1f)

    @discardableResult
    public func addNote(_ note: StoredNote) throws -> StoredNote {
        notes.append(note)
        try persist()
        return note
    }

    public func deleteNote(id: UUID) throws {
        notes.removeAll { $0.id == id }
        try persist()
    }

    // MARK: - Signer CRUD (trusted signers for verification; added in 2.0 C2)

    /// Add a trusted signer. If a signer with the same public key already
    /// exists, its name/comment are updated instead of adding a duplicate.
    @discardableResult
    public func addSigner(_ signer: StoredSigner) throws -> StoredSigner {
        if let idx = signers.firstIndex(where: { $0.publicKeyWire == signer.publicKeyWire }) {
            signers[idx].name = signer.name
            signers[idx].comment = signer.comment
            try persist()
            return signers[idx]
        }
        signers.append(signer)
        try persist()
        return signer
    }

    public func renameSigner(id: UUID, to newName: String) throws {
        guard let idx = signers.firstIndex(where: { $0.id == id }) else { return }
        signers[idx].name = newName
        try persist()
    }

    public func deleteSigner(id: UUID) throws {
        signers.removeAll { $0.id == id }
        try persist()
    }

    /// Whether a public key (wire blob) is already a trusted signer.
    public func isTrustedSigner(publicKeyWire: Data) -> Bool {
        signers.contains { $0.publicKeyWire == publicKeyWire }
    }

    // MARK: - Reset

    /// Destroy the vault: the Keychain key, the vault file, both password blobs,
    /// the password device secret and the attempt counter. Used by Settings
    /// "Reset AgePony" and the lock screen's recovery button. Keeps encryption
    /// and network preferences but clears every lock-related one.
    public func reset() throws {
        try KeychainStore.deleteMasterKey()
        destroyVaultFiles()
        lock()
        let d = UserDefaults.standard
        for key in [SettingsKey.hasCompletedOnboarding, SettingsKey.hasSeenWalkthrough,
                    SettingsKey.activeIdentityID, SettingsKey.lockMode, SettingsKey.unlockSecretKind,
                    SettingsKey.biometricEnabled, SettingsKey.autoLockGraceSeconds,
                    SettingsKey.eraseAfterFailedAttempts, SettingsKey.backupRecipientID] {
            d.removeObject(forKey: key)
        }
        // Forget how many successful ops we'd counted toward a review prompt
        // so a re-onboarded user starts the rating journey from scratch.
        ReviewPrompter.resetState()
    }

    /// Everything a reset and a silent wipe both remove from disk and Keychain.
    private func destroyVaultFiles() {
        let fm = FileManager.default
        try? fm.removeItem(at: Self.vaultFileURL())
        try? fm.removeItem(at: Self.passwordBlobURL())
        try? fm.removeItem(at: Self.duressBlobURL())
        attempts.reset()
        // Makes any stray copy of an old password or duress blob unopenable (M-2).
        try? KeychainStore.deleteDeviceSecret()
    }

    /// The duress and erase-after-failed-attempts wipe (audit M-8). Beyond the
    /// vault itself, everything that could show the app was used: temporary
    /// files, payloads the share extension left, network caches and cookies,
    /// documents handed in by other apps, proxy settings and credentials, the
    /// review counters, and every preference. The onboarding and walkthrough
    /// flags survive: the result has to look like a long-time install that holds
    /// no keys, not a fresh one showing the intro tour.
    private func silentWipe() {
        identities = []
        recipients = []
        notes = []
        signers = []
        trashedIdentities = []
        trashedRecipients = []
        masterKey = nil
        sessionPassphrase = nil
        isUnlocked = false
        try? KeychainStore.deleteMasterKey()
        destroyVaultFiles()

        TempFileCleanup.sweepAll()
        SharedContainer.removeAll()
        URLCache.shared.removeAllCachedResponses()
        HTTPCookieStorage.shared.removeCookies(since: .distantPast)
        if let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            try? FileManager.default.removeItem(at: docs.appendingPathComponent("Inbox", isDirectory: true))
        }
        KeychainStore.deleteAllSettingSecrets()
        ReviewPrompter.resetState()

        let d = UserDefaults.standard
        let onboarded = hasCompletedOnboarding
        let sawWalkthrough = hasSeenWalkthrough
        if let domain = Bundle.main.bundleIdentifier {
            d.removePersistentDomain(forName: domain)
        }
        if onboarded { hasCompletedOnboarding = true }
        if sawWalkthrough { hasSeenWalkthrough = true }
    }

    // MARK: - App password / PIN + duress (4.0.0, hardened in 5.0.1)

    /// The password device binding, from the Keychain secret (created if absent).
    private func deviceBinding() throws -> SoftwareDeviceBinding {
        let (secret, created) = try KeychainStore.deviceSecret()
        return SoftwareDeviceBinding(key: secret, justCreated: created)
    }

    private func readBlob(_ url: URL) -> Data? {
        try? Data(contentsOf: url)
    }

    /// Whether the app password is the only way into the vault: removing it now
    /// would leave nothing that opens the vault at the next lock (audit L-16).
    public var passwordIsOnlyUnlock: Bool {
        hasAppPassword && (hasDuressPassword || lockMode == .none)
    }

    /// Enroll or replace the app-owned password/PIN. Wraps the current vault key
    /// under the new secret and writes `vault.key.pw`. Requires the vault to be
    /// unlocked. Refuses a secret below the minimum (M-1), one equal to the
    /// duress secret (L-17), and a switch between password and PIN while a duress
    /// secret is set (the decoy is typed on the same keyboard).
    public func setAppPassword(_ secret: String, kind: UnlockSecretKind) async throws {
        guard let key = masterKey else { throw VaultError.notUnlocked }
        if let problem = PasswordKeyBlob.policyError(secret: secret, isPIN: kind == .pin) {
            throw VaultError.weakSecret(problem)
        }
        let duress = hasDuressPassword ? readBlob(Self.duressBlobURL()) : nil
        if duress != nil, let current = unlockSecretKind, current != kind {
            throw VaultError.kindLockedByDuress
        }
        let vk = key.withUnsafeBytes { Data($0) }
        let binding = try deviceBinding()
        let blob = try await Task.detached(priority: .userInitiated) { () throws -> Data in
            if let duress, try PasswordKeyBlob.tryUnlock(secret: secret, realBlob: nil, duressBlob: duress,
                                                         binding: binding).isDuress {
                throw VaultError.realEqualsDuress
            }
            let blob = try PasswordKeyBlob.wrapVaultKey(secret: secret, vaultKey: vk, binding: binding)
            // Open it once before it counts: in No lock mode it becomes the only
            // way in as soon as the Keychain copy goes.
            guard case .real(let back, _) = try PasswordKeyBlob.tryUnlock(secret: secret, realBlob: blob,
                                                                         duressBlob: nil, binding: binding),
                  back == vk else { throw VaultError.decryptionFailed }
            return blob
        }.value
        try writeBlob(blob, to: Self.passwordBlobURL())
        unlockSecretKind = kind
        attempts.reset()
        if lockMode == .biometricOnly {
            // The password is saved either way. With Face ID not enrolled right
            // now the Face ID item can't be rewritten; the next password unlock
            // tries again (E6 review).
            try? enforceKeychainPolicy()
        } else {
            try enforceKeychainPolicy()
        }
    }

    /// Remove the app password and any duress password. Refused while the
    /// password is the only way in (L-16): the user picks Biometric first.
    /// Also refused in Face ID only mode, where the password is the way back in
    /// after a Face ID reset (E6).
    public func removeAppPassword() throws {
        guard !passwordIsOnlyUnlock, !lockMode.needsAppPassword else { throw VaultError.passwordIsOnlyUnlock }
        try? FileManager.default.removeItem(at: Self.duressBlobURL())
        try? FileManager.default.removeItem(at: Self.passwordBlobURL())
        UserDefaults.standard.removeObject(forKey: SettingsKey.unlockSecretKind)
        attempts.reset()
    }

    /// Enroll or replace the duress password. Refuses a decoy equal to the real
    /// password (which would make the real password wipe the vault). Requires an
    /// app password. Makes the vault password-only (H-1).
    public func setDuressPassword(_ secret: String) async throws {
        guard masterKey != nil else { throw VaultError.notUnlocked }
        guard hasAppPassword, let realBlob = readBlob(Self.passwordBlobURL()) else { throw VaultError.noAppPassword }
        if let problem = PasswordKeyBlob.policyError(secret: secret, isPIN: unlockSecretKind == .pin) {
            throw VaultError.weakSecret(problem)
        }
        let binding = try deviceBinding()
        let blob = try await Task.detached(priority: .userInitiated) { () throws -> Data in
            if case .real = try PasswordKeyBlob.tryUnlock(secret: secret, realBlob: realBlob, duressBlob: nil, binding: binding) {
                throw VaultError.duressEqualsReal
            }
            return try PasswordKeyBlob.duressBlob(secret: secret, binding: binding)
        }.value
        try writeBlob(blob, to: Self.duressBlobURL())
        lockMode = .none
        try enforceKeychainPolicy()
    }

    /// Remove the duress password only. The vault stays password-only until the
    /// user picks Biometric again.
    public func removeDuressPassword() throws {
        try? FileManager.default.removeItem(at: Self.duressBlobURL())
    }

    /// Change the OS gate. Requires the vault to be unlocked. Refused while a
    /// duress password is set (H-1). Face ID only also needs the app password
    /// (E6). If iOS refuses the new item, the previous mode and its item stay.
    public func setLockMode(_ mode: LockMode) throws {
        guard masterKey != nil else { throw VaultError.notUnlocked }
        if mode != .none && hasDuressPassword { throw VaultError.lockModeLockedByDuress }
        if mode.needsAppPassword && !hasAppPassword { throw VaultError.noAppPassword }
        let old = lockMode
        lockMode = mode
        do {
            try enforceKeychainPolicy()
        } catch {
            lockMode = old
            // A refusal at the staging copy leaves the old item as it was; this
            // also covers a failure after it, so the old mode always has its item.
            try? enforceKeychainPolicy()
            throw error
        }
    }

    /// Make the Keychain copy of the vault key match the lock rules: present
    /// (under the mode's ACL) in Biometric and Face ID only modes, or in No lock
    /// without a password; absent otherwise (M-3, H-1). Only deletes once the
    /// password blob exists, and only stores while the key is in memory.
    ///
    /// Runs after every password unlock too, which is how Face ID only gets a
    /// fresh item after a Face ID reset (E6).
    private func enforceKeychainPolicy() throws {
        if hasDuressPassword && lockMode != .none { lockMode = .none }
        // Face ID only without a password could leave a vault nothing opens
        // after a Face ID reset; fall back to the default lock instead.
        if lockMode.needsAppPassword && !hasAppPassword { lockMode = .biometric }
        let wanted = lockMode.requiresBiometricACL || !hasAppPassword
        if wanted {
            guard let key = masterKey else { return }
            let bytes = key.withUnsafeBytes { Data($0) }
            if lockMode == .biometricOnly {
                try KeychainStore.storeBiometryOnlyMasterKey(bytes)
            } else {
                try KeychainStore.storeMasterKey(bytes, biometric: lockMode.requiresBiometricACL)
            }
        } else if hasAppPassword {
            try KeychainStore.deleteMasterKey()
        }
    }

    /// Milliseconds until the lock screen accepts another password attempt (M-1).
    public func lockoutRemainingMillis() -> UInt64 { attempts.remainingLockoutMillis() }

    /// What a password attempt at the lock screen came to.
    public enum PasswordUnlockResult: Equatable {
        /// The vault is open (the real secret, or the decoy after its wipe).
        case unlocked
        /// Erase-after-failures fired: the vault is gone and onboarding follows.
        case erased
    }

    /// Unlock with the app password/PIN. On the decoy it performs the duress wipe
    /// and returns `.unlocked` with an empty vault; on a wrong secret it throws
    /// `.wrongPassword(attempts)` or `.lockedOut`, or erases the vault when that
    /// setting is on and the limit is reached.
    ///
    /// Every attempt is counted before it is checked, so killing the app
    /// mid-attempt can't make a guess free; real and decoy both clear the count,
    /// so the counter can't tell them apart. The scrypt work runs off the main
    /// thread; `PasswordKeyBlob.tryUnlock` keeps it the same shape for every
    /// outcome.
    public func unlockWithPassword(_ secret: String) async throws -> PasswordUnlockResult {
        guard hasAppPassword, let realBlob = readBlob(Self.passwordBlobURL()) else { throw VaultError.noAppPassword }
        let wait = attempts.remainingLockoutMillis()
        if wait > 0 { throw VaultError.lockedOut(wait) }
        let duressBlob = readBlob(Self.duressBlobURL())
        let count = attempts.recordAttempt()
        let binding = try deviceBinding()
        let outcome = try await Task.detached(priority: .userInitiated) {
            try PasswordKeyBlob.tryUnlock(secret: secret, realBlob: realBlob, duressBlob: duressBlob, binding: binding)
        }.value

        switch outcome {
        case .real(let vkData, let needsRewrap):
            let key = SymmetricKey(data: vkData)
            let payload = try loadEncryptedVault()
            let snapshot = try decryptVault(payload: payload, key: key)
            self.masterKey = key
            self.identities = snapshot.identities
            self.recipients = snapshot.recipients
            self.notes = snapshot.notes
            self.signers = snapshot.signers ?? []
            self.trashedIdentities = snapshot.trashedIdentities ?? []
            self.trashedRecipients = snapshot.trashedRecipients ?? []
            self.isUnlocked = true
            attempts.reset()
            purgeExpiredTrash()
            await afterPasswordUnlock(secret: secret, vaultKey: vkData, needsRewrap: needsRewrap)
            return .unlocked
        case .duress(let material):
            try performDuressWipe(material)
            return .unlocked
        case .wrong:
            if eraseAfterFailedAttempts && count >= UnlockAttempts.eraseAfter {
                silentWipe()
                return .erased
            }
            throw VaultError.wrongPassword(failures: count)
        }
    }

    /// Housekeeping after a real password unlock. The password has just opened
    /// its blob, so this is the moment to upgrade a v1 blob to the device-bound
    /// v2 while the secret is in hand, and to drop Keychain copies the lock rules
    /// say must not exist (this migrates a 4.x vault that had duress next to
    /// Face ID). The new blob is opened once before it replaces the old one.
    /// Failures here never undo the unlock.
    private func afterPasswordUnlock(secret: String, vaultKey: Data, needsRewrap: Bool) async {
        if needsRewrap {
            guard let binding = try? deviceBinding() else { return }
            let checked = try? await Task.detached(priority: .utility) { () throws -> Data? in
                let blob = try PasswordKeyBlob.wrapVaultKey(secret: secret, vaultKey: vaultKey, binding: binding)
                if case .real(let back, _) = try PasswordKeyBlob.tryUnlock(secret: secret, realBlob: blob, duressBlob: nil, binding: binding),
                   back == vaultKey {
                    return blob
                }
                return nil
            }.value
            guard let blob = checked ?? nil else { return }
            do { try writeBlob(blob, to: Self.passwordBlobURL()) } catch { return }
        }
        try? enforceKeychainPolicy()
    }

    /// Check the app password for an in-app re-auth (L-15), with the same
    /// counter and backoff as the lock screen. The decoy never matches here.
    public func verifyAppPassword(_ secret: String) async throws -> Bool {
        guard let realBlob = readBlob(Self.passwordBlobURL()) else { throw VaultError.noAppPassword }
        let wait = attempts.remainingLockoutMillis()
        if wait > 0 { throw VaultError.lockedOut(wait) }
        attempts.recordAttempt()
        let binding = try deviceBinding()
        let outcome = try await Task.detached(priority: .userInitiated) {
            try PasswordKeyBlob.tryUnlock(secret: secret, realBlob: realBlob, duressBlob: nil, binding: binding)
        }.value
        if case .real = outcome {
            attempts.reset()
            return true
        }
        return false
    }

    /// Wipe everything and silently re-bootstrap an empty vault whose real
    /// password IS the decoy just entered (the settled 4.0.0 duress behavior).
    /// The coercer sees a working, empty, password-only app that the decoy keeps
    /// unlocking; any other secret fails normally. No tell, retry-stable. The
    /// decoy's own scrypt output seals the new key, so the wipe costs no extra
    /// derivation (M-8).
    private func performDuressWipe(_ material: PasswordKeyBlob.DuressMaterial) throws {
        let kind = unlockSecretKind
        silentWipe()
        unlockSecretKind = kind
        lockMode = .none

        let key = SymmetricKey(size: .bits256)
        let vk = key.withUnsafeBytes { Data($0) }
        self.masterKey = key
        try persist() // writes an empty encrypted vault.dat
        self.isUnlocked = true

        // The decoy becomes the new real (and only) password, under a new device secret.
        let realBlob = try material.wrapNewVaultKey(vk, binding: try deviceBinding())
        try writeBlob(realBlob, to: Self.passwordBlobURL())
    }

    private func writeBlob(_ blob: Data, to url: URL) throws {
        try ensureVaultDirectoryExists()
        try blob.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
    }

    // MARK: - Persistence

    private func persist() throws {
        guard let key = masterKey else { throw VaultError.notUnlocked }
        let snapshot = VaultSnapshot(identities: identities, recipients: recipients, notes: notes, signers: signers, trashedIdentities: trashedIdentities, trashedRecipients: trashedRecipients)
        let plaintext = try JSONEncoder().encode(snapshot)
        let sealed = try ChaChaPoly.seal(plaintext, using: key)
        // Combine: nonce(12) || ciphertext || tag(16)
        let combined = sealed.combined
        try ensureVaultDirectoryExists()
        try combined.write(to: Self.vaultFileURL(), options: [.atomic, .completeFileProtectionUnlessOpen])
    }

    private func loadEncryptedVault() throws -> Data {
        let url = Self.vaultFileURL()
        if !FileManager.default.fileExists(atPath: url.path) {
            // Empty vault — return a sentinel that decrypts to an empty snapshot.
            // We do this by sealing an empty snapshot lazily; cleaner to just
            // call this path "fresh" and seed with empty arrays.
            throw VaultError.vaultFileMissing
        }
        return try Data(contentsOf: url)
    }

    private func decryptVault(payload: Data, key: SymmetricKey) throws -> VaultSnapshot {
        let sealedBox: ChaChaPoly.SealedBox
        do {
            sealedBox = try ChaChaPoly.SealedBox(combined: payload)
        } catch {
            throw VaultError.malformedVaultFile
        }
        let plaintext: Data
        do {
            plaintext = try ChaChaPoly.open(sealedBox, using: key)
        } catch {
            throw VaultError.decryptionFailed
        }
        return try JSONDecoder().decode(VaultSnapshot.self, from: plaintext)
    }

    private func ensureVaultDirectoryExists() throws {
        let dir = Self.vaultFileURL().deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
    }

    static func vaultDirectoryURL() -> URL {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return support.appendingPathComponent("AgePony", isDirectory: true)
    }

    private static func vaultFileURL() -> URL {
        vaultDirectoryURL().appendingPathComponent("vault.dat")
    }

    /// The real app-password key blob (present iff an app password is set).
    private static func passwordBlobURL() -> URL {
        vaultDirectoryURL().appendingPathComponent("vault.key.pw")
    }

    /// The duress key blob (present iff a duress password is set).
    private static func duressBlobURL() -> URL {
        vaultDirectoryURL().appendingPathComponent("vault.key.duress")
    }

    // MARK: - Snapshot

    private struct VaultSnapshot: Codable {
        let identities: [StoredIdentity]
        let recipients: [StoredRecipient]
        let notes: [StoredNote]
        /// Optional for backward compatibility: pre-2.0 vault files have no
        /// signers key and decode this as nil (treated as empty).
        let signers: [StoredSigner]?
        /// Optional for backward compatibility: pre-4.0.0 vaults have no recycle
        /// bin and decode these as nil (treated as empty).
        let trashedIdentities: [TrashedIdentity]?
        let trashedRecipients: [TrashedRecipient]?
    }

    // MARK: - Keys

    private enum SettingsKey {
        static let biometricEnabled       = "com.agepony.app.settings.biometricEnabled"
        static let encryptToSelfDefault   = "com.agepony.app.settings.encryptToSelfDefault"
        static let scryptWorkFactor       = "com.agepony.app.settings.scryptWorkFactor"
        static let activeIdentityID       = "com.agepony.app.settings.activeIdentityID"
        static let hasCompletedOnboarding = "com.agepony.app.settings.hasCompletedOnboarding"
        static let hasSeenWalkthrough     = "com.agepony.app.settings.hasSeenWalkthrough"
        static let lockMode               = "com.agepony.app.settings.lockMode"
        static let unlockSecretKind       = "com.agepony.app.settings.unlockSecretKind"
        static let autoLockGraceSeconds   = "com.agepony.app.settings.autoLockGraceSeconds"
        static let proxyMode              = "com.agepony.app.settings.proxyMode"
        static let proxyHost              = "com.agepony.app.settings.proxyHost"
        static let proxyPort              = "com.agepony.app.settings.proxyPort"
        static let proxyUsername          = "com.agepony.app.settings.proxyUsername"
        static let proxyPassword          = "com.agepony.app.settings.proxyPassword"
        static let eraseAfterFailedAttempts = "com.agepony.app.settings.eraseAfterFailedAttempts"
        static let backupRecipientID      = "com.agepony.app.settings.backupRecipientID"
    }
}

public enum VaultError: Error, Equatable {
    case notUnlocked
    case vaultFileMissing
    case malformedVaultFile
    case decryptionFailed
    /// A wrong app password; `failures` is the count so far.
    case wrongPassword(failures: Int)
    /// The backoff is running; milliseconds left.
    case lockedOut(UInt64)
    case noAppPassword
    case duressEqualsReal
    case realEqualsDuress
    case weakSecret(String)
    case kindLockedByDuress
    case lockModeLockedByDuress
    case passwordIsOnlyUnlock
}
