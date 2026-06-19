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
//  Migration note (2.0): `signers` was added to the persisted snapshot as an
//  optional field, so vault files written before 2.0 (which have no signers
//  key) still decode — a missing key reads back as nil and is treated as an
//  empty list. Newly written vaults always include the key.
//

import Foundation
import CryptoKit
import Observation
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

    // MARK: - Settings (persisted in UserDefaults, surfaced here for binding)

    public var biometricEnabled: Bool {
        get { UserDefaults.standard.object(forKey: SettingsKey.biometricEnabled) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKey.biometricEnabled) }
    }

    public var encryptToSelfDefault: Bool {
        get { UserDefaults.standard.object(forKey: SettingsKey.encryptToSelfDefault) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKey.encryptToSelfDefault) }
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

    public init() {}

    // MARK: - Lifecycle

    /// True if a vault has been initialized on this device. Use to gate
    /// "first launch" UI vs. "biometric unlock" UI.
    public static func isProvisioned() -> Bool {
        KeychainStore.masterKeyExists()
    }

    /// Bootstrap a fresh vault. Generates a master key, stores it under the
    /// biometric ACL, and writes an empty encrypted vault file. Triggers the
    /// system's biometric/passcode prompt (because the ACL fires on first
    /// write too on some iOS versions).
    public func bootstrap() async throws {
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        try KeychainStore.storeMasterKey(keyData)
        self.masterKey = key
        self.identities = []
        self.recipients = []
        self.notes = []
        self.signers = []
        try persist()
        self.isUnlocked = true
    }

    /// Unlock an existing vault. Triggers a biometric prompt via the OS.
    public func unlock(prompt: String = "Unlock AgePony") async throws {
        let keyBytes = try KeychainStore.loadMasterKey(prompt: prompt)
        let key = SymmetricKey(data: keyBytes)
        let payload = try loadEncryptedVault()
        let snapshot = try decryptVault(payload: payload, key: key)
        self.masterKey = key
        self.identities = snapshot.identities
        self.recipients = snapshot.recipients
        self.notes = snapshot.notes
        self.signers = snapshot.signers ?? []
        self.isUnlocked = true
    }

    /// Drop the master key from memory. Called when the app enters background.
    public func lock() {
        masterKey = nil
        identities = []
        recipients = []
        notes = []
        signers = []
        isUnlocked = false
    }

    // MARK: - Identity CRUD

    @discardableResult
    public func addIdentity(_ identity: StoredIdentity) throws -> StoredIdentity {
        identities.append(identity)
        // First identity becomes the active one for encrypt-to-self.
        if activeIdentityID == nil {
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

    public func deleteIdentity(id: UUID) throws {
        identities.removeAll { $0.id == id }
        if activeIdentityID == id {
            activeIdentityID = identities.first?.id
        }
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

    public func deleteRecipient(id: UUID) throws {
        recipients.removeAll { $0.id == id }
        try persist()
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

    /// Destroy the vault. Deletes both the Keychain master key and the
    /// encrypted vault file. Used by the Settings "Reset App" affordance
    /// (added in 1h; surfaced as a guarded button).
    public func reset() throws {
        try KeychainStore.deleteMasterKey()
        try? FileManager.default.removeItem(at: Self.vaultFileURL())
        lock()
        UserDefaults.standard.removeObject(forKey: SettingsKey.hasCompletedOnboarding)
        UserDefaults.standard.removeObject(forKey: SettingsKey.hasSeenWalkthrough)
        UserDefaults.standard.removeObject(forKey: SettingsKey.activeIdentityID)
        // Forget how many successful ops we'd counted toward a review prompt
        // so a re-onboarded user starts the rating journey from scratch.
        ReviewPrompter.resetState()
    }

    // MARK: - Persistence

    private func persist() throws {
        guard let key = masterKey else { throw VaultError.notUnlocked }
        let snapshot = VaultSnapshot(identities: identities, recipients: recipients, notes: notes, signers: signers)
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

    private static func vaultFileURL() -> URL {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return support.appendingPathComponent("AgePony", isDirectory: true).appendingPathComponent("vault.dat")
    }

    // MARK: - Snapshot

    private struct VaultSnapshot: Codable {
        let identities: [StoredIdentity]
        let recipients: [StoredRecipient]
        let notes: [StoredNote]
        /// Optional for backward compatibility: pre-2.0 vault files have no
        /// signers key and decode this as nil (treated as empty).
        let signers: [StoredSigner]?
    }

    // MARK: - Keys

    private enum SettingsKey {
        static let biometricEnabled       = "com.agepony.app.settings.biometricEnabled"
        static let encryptToSelfDefault   = "com.agepony.app.settings.encryptToSelfDefault"
        static let activeIdentityID       = "com.agepony.app.settings.activeIdentityID"
        static let hasCompletedOnboarding = "com.agepony.app.settings.hasCompletedOnboarding"
        static let hasSeenWalkthrough     = "com.agepony.app.settings.hasSeenWalkthrough"
    }
}

public enum VaultError: Error, Equatable {
    case notUnlocked
    case vaultFileMissing
    case malformedVaultFile
    case decryptionFailed
}
