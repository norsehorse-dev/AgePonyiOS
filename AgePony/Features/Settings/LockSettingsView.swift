//
//  LockSettingsView.swift
//  AgePony
//
//  Security settings for the vault gate (4.0.0, hardened in 5.0.1): the OS lock
//  mode, the auto-lock grace period, the app-owned password/PIN, the duress
//  password, and erase-after-failed-attempts. Reached from Settings → Security
//  → "Lock & password".
//
//  5.0.1 (security audit):
//    - L-15: anything that weakens the lock asks for proof it's the owner
//      first: the current app password, or Face ID / the device passcode when
//      there is none. That covers No lock, a longer grace period, changing or
//      removing the password, setting, changing or removing the duress
//      password, and turning erase-after-failures off.
//    - H-1: a duress password makes the vault password-only, so the lock mode
//      can't be changed while one is set.
//    - L-16: the password can't be removed while it is the only way in.
//    - M-1: new secrets need at least 6 digits or 8 characters.
//

import SwiftUI
import AgePonyCore

struct LockSettingsView: View {

    let vault: Vault

    @State private var lockMode: LockMode
    @State private var autoLockGrace: Int
    @State private var hasPassword: Bool
    @State private var hasDuress: Bool
    @State private var secretKind: UnlockSecretKind?
    @State private var eraseAfterFailures: Bool

    @State private var showSetPassword = false
    @State private var showSetDuress = false
    @State private var confirmRemovePassword = false
    @State private var reauthAction: ReauthAction?
    /// Runs once the re-auth sheet has gone, so a sheet it opens can present.
    @State private var afterReauth: (() -> Void)?
    @State private var busy = false
    @State private var errorMessage: String?

    /// Something that waits for the owner to prove it's them (L-15).
    struct ReauthAction: Identifiable {
        let id = UUID()
        let run: () -> Void
    }

    init(vault: Vault) {
        self.vault = vault
        _lockMode   = State(initialValue: vault.lockMode)
        _autoLockGrace = State(initialValue: vault.autoLockGraceSeconds)
        _hasPassword = State(initialValue: vault.hasAppPassword)
        _hasDuress  = State(initialValue: vault.hasDuressPassword)
        _secretKind = State(initialValue: vault.unlockSecretKind)
        _eraseAfterFailures = State(initialValue: vault.eraseAfterFailedAttempts)
    }

    var body: some View {
        Form {
            lockModeSection
            autoLockSection
            passwordSection
            if hasPassword {
                duressSection
                eraseSection
            }
        }
        .navigationTitle("Lock & password")
        .navigationBarTitleDisplayMode(.inline)
        .disabled(busy)
        .sheet(isPresented: $showSetPassword) {
            SecretEntrySheet(
                title: hasPassword ? "Change \(secretNoun)" : "Set a password or PIN",
                kind: secretKind ?? .password,
                allowKindChange: !hasDuress
            ) { secret, kind in
                run {
                    try await vault.setAppPassword(secret, kind: kind)
                    secretKind = kind
                }
            }
        }
        .sheet(isPresented: $showSetDuress) {
            SecretEntrySheet(
                title: duressSheetTitle,
                kind: secretKind ?? .password,
                allowKindChange: false
            ) { secret, _ in
                run { try await vault.setDuressPassword(secret) }
            }
        }
        .sheet(item: $reauthAction, onDismiss: {
            let next = afterReauth
            afterReauth = nil
            next?()
        }) { action in
            ReauthSheet(vault: vault, noun: secretNoun) {
                afterReauth = action.run
                reauthAction = nil
            }
        }
        .confirmationDialog(
            "Remove the app \(secretNoun)?",
            isPresented: $confirmRemovePassword,
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                requireOwner { run { try vault.removeAppPassword() } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(hasDuress
                 ? "This also removes the duress \(secretNoun). The vault will open with \(lockModeWord) only."
                 : "The vault will open with \(lockModeWord) only.")
        }
        .alert(
            "Couldn't save",
            isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
    }

    // MARK: - Lock mode

    private var lockModeSection: some View {
        Section {
            Picker("Lock", selection: Binding(get: { lockMode }, set: changeLockMode)) {
                Text(biometricWord).tag(LockMode.biometric)
                Text("No lock").tag(LockMode.none)
            }
            .disabled(hasDuress)
        } header: {
            Text("How the vault is locked")
        } footer: {
            Text(lockModeFooter)
        }
    }

    private var lockModeFooter: String {
        if hasDuress {
            return "While a duress \(secretNoun) is set, only the app \(secretNoun) opens the vault, so a forced unlock always goes through the field where the duress \(secretNoun) works. Remove the duress \(secretNoun) to use \(biometricWord) again."
        }
        switch (lockMode, hasPassword) {
        case (.biometric, _):
            return "\(biometricWord), or your device passcode, unlocks the vault. Any app \(secretNoun) you set below also works."
        case (.none, true):
            return "Only the app \(secretNoun) opens the vault."
        case (.none, false):
            return "The vault opens with no prompt. Set an app password below, or choose \(biometricWord), to protect it."
        }
    }

    private func changeLockMode(_ new: LockMode) {
        guard new != lockMode else { return }
        // Without a device passcode iOS refuses the biometric Keychain lock (plan 2.8).
        if new == .biometric && !BiometricGate.devicePasscodeIsSet() {
            errorMessage = "This iPhone has no passcode, and iOS only lets Face ID, Touch ID or the passcode protect a key when there is one. Set a passcode in Settings › Face ID & Passcode first."
            return
        }
        let apply = {
            run {
                try vault.setLockMode(new)
                lockMode = new
            }
        }
        // Dropping biometric weakens the lock unless a password takes over.
        if new == .none { requireOwner(apply) } else { apply() }
    }

    // MARK: - Auto-lock

    private var autoLockSection: some View {
        Section {
            Picker("Lock after leaving", selection: Binding(get: { autoLockGrace }, set: changeGrace)) {
                Text("Immediately").tag(0)
                Text("15 seconds").tag(15)
                Text("30 seconds").tag(30)
                Text("1 minute").tag(60)
                Text("5 minutes").tag(300)
            }
        } header: {
            Text("Auto-lock")
        } footer: {
            Text("How long AgePony waits after you switch away before locking. Shorter is safer; longer keeps your place during a quick app switch. Restarting the phone always locks.")
        }
    }

    private func changeGrace(_ new: Int) {
        let apply = {
            vault.autoLockGraceSeconds = new
            autoLockGrace = new
        }
        if new > autoLockGrace { requireOwner(apply) } else { apply() }
    }

    // MARK: - App password

    private var passwordSection: some View {
        Section {
            if !hasPassword {
                Button("Set a password or PIN…") { showSetPassword = true }
            } else {
                Text("Unlock \(secretNoun) is set.")
                    .foregroundStyle(.secondary)
                Button("Change…") { requireOwner { showSetPassword = true } }
                Button("Remove", role: .destructive) {
                    if vault.passwordIsOnlyUnlock {
                        errorMessage = hasDuress
                            ? "Your \(secretNoun) is the only way into the vault. Remove the duress \(secretNoun), then choose \(biometricWord) above before removing it."
                            : "Your \(secretNoun) is the only way into the vault. Choose \(biometricWord) above before removing it."
                    } else {
                        confirmRemovePassword = true
                    }
                }
            }
        } header: {
            Text("App password")
        } footer: {
            Text("A password (at least \(PasswordKeyBlob.minPasswordLength) characters) or PIN (at least \(PasswordKeyBlob.minPINLength) digits), checked by AgePony itself and tied to this iPhone. After 5 wrong tries each further try has to wait, starting at 30 seconds. It is the basis for a duress password.")
        }
    }

    // MARK: - Duress

    private var duressSection: some View {
        Section {
            if !hasDuress {
                Button("Set a duress \(secretNoun)…") { requireOwner { showSetDuress = true } }
            } else {
                Text("Duress \(secretNoun) is set. Entering it wipes the vault.")
                    .foregroundStyle(.secondary)
                Button("Change…") { requireOwner { showSetDuress = true } }
                Button("Remove", role: .destructive) {
                    requireOwner { run { try vault.removeDuressPassword() } }
                }
            }
        } header: {
            Text("Duress password")
        } footer: {
            Text("A second \(secretNoun) that, when entered at unlock, silently wipes everything and opens an empty vault. It looks exactly like a normal unlock, with no warning and no confirmation. Setting one turns off \(biometricWord) for the vault, so a forced unlock has to go through the \(secretNoun) field.")
        }
    }

    // MARK: - Erase after failed attempts

    private var eraseSection: some View {
        Section {
            Toggle("Erase after \(UnlockAttempts.eraseAfter) wrong tries", isOn: Binding(
                get: { eraseAfterFailures },
                set: { new in
                    let apply = {
                        vault.eraseAfterFailedAttempts = new
                        eraseAfterFailures = new
                    }
                    if new { apply() } else { requireOwner(apply) }
                }
            ))
        } footer: {
            Text("When on, entering the app \(secretNoun) wrong \(UnlockAttempts.eraseAfter) times in a row erases the vault, the same way the duress \(secretNoun) does but without opening an empty vault afterwards. Keep a backup of your keys if you turn this on.")
        }
    }

    // MARK: - Helpers

    private var secretNoun: String { (secretKind ?? .password).displayNoun }

    private var lockModeWord: String { lockMode == .biometric ? biometricWord : "no lock" }

    private var biometricWord: String {
        switch BiometricGate.availableBiometric() {
        case .faceID:  return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        case .none:    return "Passcode"
        }
    }

    private var duressSheetTitle: String {
        hasDuress ? "Change duress \(secretNoun)" : "Set a duress \(secretNoun)"
    }

    /// Run `action` once the owner has proved it's them (L-15): the app
    /// password when there is one, otherwise Face ID or the device passcode.
    /// A phone with neither has nothing to check.
    private func requireOwner(_ action: @escaping () -> Void) {
        if vault.hasAppPassword {
            reauthAction = ReauthAction(run: action)
            return
        }
        Task {
            do {
                try await BiometricGate.authenticate(reason: "Confirm it's you to change how AgePony locks")
                action()
            } catch BiometricGateError.unavailable {
                action()
            } catch BiometricGateError.userCancelled {
                // Leave everything as it was.
            } catch {
                errorMessage = readable(error)
            }
        }
    }

    /// Run a vault change, then re-read the state it may have changed.
    private func run(_ work: @escaping () async throws -> Void) {
        busy = true
        Task {
            defer {
                busy = false
                refresh()
            }
            do { try await work() } catch { errorMessage = readable(error) }
        }
    }

    private func refresh() {
        lockMode = vault.lockMode
        hasPassword = vault.hasAppPassword
        hasDuress = vault.hasDuressPassword
        secretKind = vault.unlockSecretKind
        eraseAfterFailures = vault.eraseAfterFailedAttempts
    }

    private func readable(_ error: Error) -> String {
        if let e = error as? VaultError {
            switch e {
            case .duressEqualsReal:       return "The duress \(secretNoun) must be different from your real one."
            case .realEqualsDuress:       return "Your \(secretNoun) must be different from the duress \(secretNoun)."
            case .weakSecret(let why):    return why
            case .kindLockedByDuress:     return "Remove the duress \(secretNoun) first to switch between a password and a PIN."
            case .lockModeLockedByDuress: return "Remove the duress \(secretNoun) to use \(biometricWord)."
            case .passwordIsOnlyUnlock:   return "Your \(secretNoun) is the only way into the vault. Choose \(biometricWord) above before removing it."
            case .noAppPassword:          return "Set an app password first."
            case .notUnlocked:            return "Unlock the vault first."
            case .lockedOut(let millis):  return UnlockAttempts.lockoutMessage(millis: millis)
            default:                      return "Something went wrong. Try again."
            }
        }
        if let e = error as? BiometricGateError, case .failed(let msg) = e { return msg }
        return error.localizedDescription
    }
}

// MARK: - Re-auth sheet

/// Asks for the current app password before a change that weakens the lock
/// (L-15). Uses the lock screen's attempt counter and backoff.
private struct ReauthSheet: View {
    let vault: Vault
    let noun: String
    let onSuccess: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var secret = ""
    @State private var checking = false
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Current \(noun)", text: $secret)
                        .textContentType(.password)
                        .keyboardType(vault.unlockSecretKind == .pin ? .numberPad : .default)
                        .onSubmit(check)
                } footer: {
                    if let message { Text(message).foregroundStyle(.red) }
                    else { Text("Confirm it's you before changing how AgePony locks.") }
                }
            }
            .navigationTitle("Enter your \(noun)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue", action: check)
                        .disabled(secret.isEmpty || checking)
                }
            }
        }
    }

    private func check() {
        guard !secret.isEmpty, !checking else { return }
        let entered = secret
        secret = ""
        checking = true
        Task {
            defer { checking = false }
            do {
                if try await vault.verifyAppPassword(entered) {
                    onSuccess()
                } else {
                    message = "Wrong \(noun)."
                }
            } catch VaultError.lockedOut(let millis) {
                message = UnlockAttempts.lockoutMessage(millis: millis)
            } catch {
                message = "Couldn't check the \(noun)."
            }
        }
    }
}

// MARK: - Secret entry sheet

/// Entry form for a new password/PIN or duress password. Requires a confirmation
/// match and the 5.0.1 minimum length (M-1); for the app password it also
/// offers the password/PIN kind choice.
struct SecretEntrySheet: View {

    let title: String
    let allowKindChange: Bool
    let onSave: (_ secret: String, _ kind: UnlockSecretKind) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var kind: UnlockSecretKind
    @State private var secret = ""
    @State private var confirm = ""

    init(title: String, kind: UnlockSecretKind, allowKindChange: Bool,
         onSave: @escaping (_ secret: String, _ kind: UnlockSecretKind) -> Void) {
        self.title = title
        self.allowKindChange = allowKindChange
        self.onSave = onSave
        _kind = State(initialValue: kind)
    }

    private var isPIN: Bool { kind == .pin }

    private var validationError: String? {
        if let problem = PasswordKeyBlob.policyError(secret: secret, isPIN: isPIN) { return problem }
        if secret != confirm { return "The two entries don't match." }
        return nil
    }

    var body: some View {
        NavigationStack {
            Form {
                if allowKindChange {
                    Picker("Type", selection: $kind) {
                        Text("Password").tag(UnlockSecretKind.password)
                        Text("PIN").tag(UnlockSecretKind.pin)
                    }
                    .pickerStyle(.segmented)
                }

                Section {
                    SecureField(isPIN ? "PIN" : "Password", text: $secret)
                        .textContentType(.newPassword)
                        .keyboardType(isPIN ? .numberPad : .default)
                    SecureField(isPIN ? "Confirm PIN" : "Confirm password", text: $confirm)
                        .textContentType(.newPassword)
                        .keyboardType(isPIN ? .numberPad : .default)
                } footer: {
                    if let err = validationError, !secret.isEmpty || !confirm.isEmpty {
                        Text(err).foregroundStyle(.red)
                    } else {
                        Text(isPIN ? "At least \(PasswordKeyBlob.minPINLength) digits." : "At least \(PasswordKeyBlob.minPasswordLength) characters.")
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(secret, kind)
                        dismiss()
                    }
                    .disabled(validationError != nil)
                }
            }
        }
    }
}
