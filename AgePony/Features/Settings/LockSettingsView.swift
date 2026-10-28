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
//  5.1.0 (E6): Face ID only ("Touch ID only", "Optic ID only"). It needs the app
//  password, so choosing it without one sets one up first. Choosing it is not
//  a weakening; leaving it is, so that asks for the password (L-15). It isn't
//  offered while a duress password is set (H-1).
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
    /// The password sheet was opened on the way to Face ID only (E6).
    @State private var biometricOnlyAfterPassword = false
    @State private var confirmBiometricOnly = false
    @State private var showSetDuress = false
    @State private var confirmRemovePassword = false
    @State private var reauthAction: ReauthAction?
    /// Runs once the re-auth sheet has gone, so a sheet it opens can present.
    @State private var afterReauth: (() -> Void)?
    @State private var busy = false
    @State private var errorMessage: String?
    /// A change that can't be made as things stand (not a failed save).
    @State private var refusal: String?

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
        .textCase(nil)
        .navigationTitle("Lock & password")
        .navigationBarTitleDisplayMode(.inline)
        .disabled(busy)
        .sheet(isPresented: $showSetPassword, onDismiss: { biometricOnlyAfterPassword = false }) {
            SecretEntrySheet(
                title: passwordSheetTitle,
                kind: secretKind ?? .password,
                allowKindChange: !hasDuress
            ) { secret, kind in
                let thenBiometricOnly = biometricOnlyAfterPassword
                biometricOnlyAfterPassword = false
                run {
                    try await vault.setAppPassword(secret, kind: kind)
                    secretKind = kind
                    if thenBiometricOnly { try vault.setLockMode(.biometricOnly) }
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
            "Use \(biometricOnlyLabel)?",
            isPresented: $confirmBiometricOnly,
            titleVisibility: .visible
        ) {
            if hasPassword {
                Button("Use \(biometricOnlyLabel)") {
                    run { try vault.setLockMode(.biometricOnly) }
                }
            } else {
                Button("Set a password or PIN") {
                    biometricOnlyAfterPassword = true
                    showSetPassword = true
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(biometricOnlyConfirmMessage)
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
            if hasDuress {
                Text("This also removes the duress \(secretNoun). The vault will open with \(lockModeWord) only.")
            } else {
                Text("The vault will open with \(lockModeWord) only.")
            }
        }
        .alert(
            "Can't change the lock",
            isPresented: Binding(get: { refusal != nil }, set: { if !$0 { refusal = nil } })
        ) {
            Button("OK", role: .cancel) { refusal = nil }
        } message: {
            Text(refusal ?? "")
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
                if offersBiometricOnly {
                    Text(biometricOnlyLabel).tag(LockMode.biometricOnly)
                }
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
            return String(localized: "While a duress \(secretNoun) is set, only the app \(secretNoun) opens the vault, so a forced unlock always goes through the field where the duress \(secretNoun) works. Remove the duress \(secretNoun) to use \(biometricWord) again.")
        }
        switch (lockMode, hasPassword) {
        case (.biometric, _):
            var text = String(localized: "\(biometricWord), or your device passcode, unlocks the vault. Any app \(secretNoun) you set below also works.")
            if offersBiometricOnly {
                text += " " + String(localized: "\(biometricOnlyLabel) leaves the passcode out and uses an app password or PIN as the way back in.")
            }
            return text
        case (.biometricOnly, _):
            var text = String(localized: "Only \(biometryName) or your app \(secretNoun) opens the vault. The device passcode doesn't. If \(biometryName) is reset or changed in the Settings app, enter your \(secretNoun) once and \(biometryName) works again.")
            if hasEnclaveKeys {
                text += " " + String(localized: "Secure Enclave keys made before you chose \(biometricOnlyLabel) keep the protection they were made with: one that asks on each use still accepts the device passcode.")
            }
            return text
        case (.none, true):
            return String(localized: "Only the app \(secretNoun) opens the vault.")
        case (.none, false):
            return String(localized: "The vault opens with no prompt. Set an app password below, or choose \(biometricWord), to protect it.")
        }
    }

    private func changeLockMode(_ new: LockMode) {
        guard new != lockMode else { return }
        // No lock with a password is password-only; any OS lock adds a way in,
        // so it needs the owner too (L-15, E6 review).
        let addsWayIn = lockMode == .none && hasPassword
        if new == .biometricOnly {
            // It needs Face ID set up and an app password; the dialog explains
            // and sets one up if needed.
            guard new.isAvailable(duressSet: hasDuress, biometryEnrolled: BiometricGate.availableBiometric() != .none) else {
                refusal = biometricOnlyRefusal
                return
            }
            if addsWayIn {
                requireOwner { confirmBiometricOnly = true }
            } else {
                confirmBiometricOnly = true
            }
            return
        }
        // Without a device passcode iOS refuses the biometric Keychain lock (plan 2.8).
        if new == .biometric && !BiometricGate.devicePasscodeIsSet() {
            refusal = String(localized: "This iPhone has no passcode, and iOS only lets Face ID, Touch ID or the passcode protect a key when there is one. Set a passcode first, under Face ID & Passcode in the Settings app.")
            return
        }
        let apply = {
            run {
                try vault.setLockMode(new)
                lockMode = new
            }
        }
        // Dropping biometric weakens the lock unless a password takes over,
        // leaving Face ID only lets the passcode back in (E6), and leaving
        // password-only No lock adds Face ID and the passcode.
        if new == .none || lockMode == .biometricOnly || addsWayIn { requireOwner(apply) } else { apply() }
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
                    if lockMode == .biometricOnly {
                        refusal = String(localized: "\(biometricOnlyLabel) needs your \(secretNoun) as the way back in if \(biometryName) is reset. Choose another lock above before removing it.")
                    } else if vault.passwordIsOnlyUnlock {
                        if hasDuress {
                            refusal = String(localized: "Your \(secretNoun) is the only way into the vault. Remove the duress \(secretNoun), then choose \(biometricWord) above before removing it.")
                        } else {
                            refusal = String(localized: "Your \(secretNoun) is the only way into the vault. Choose \(biometricWord) above before removing it.")
                        }
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

    private var lockModeWord: String {
        switch lockMode {
        case .biometric:     return biometricWord
        case .biometricOnly: return biometricOnlyLabel
        case .none:          return String(localized: "no lock")
        }
    }

    /// The device's biometric by name, even while nothing is enrolled (E6).
    private var biometryName: String { BiometricGate.biometryName() }

    /// "Face ID only", "Touch ID only" or "Optic ID only".
    private var biometricOnlyLabel: String { String(localized: "\(biometryName) only") }

    /// Face ID only is listed when the iPhone has Face ID or Touch ID and no
    /// duress password is set, and always while it is the current mode so the
    /// picker shows it. A lockout or nothing enrolled still lists it; choosing
    /// it then says what to do.
    private var offersBiometricOnly: Bool {
        lockMode == .biometricOnly || (!hasDuress && BiometricGate.biometryState() != .unavailable)
    }

    /// Why Face ID only can't be chosen right now: duress, a lockout, or
    /// nothing enrolled (E6 review).
    private var biometricOnlyRefusal: String {
        if hasDuress {
            return String(localized: "Remove the duress \(secretNoun) to use \(biometricOnlyLabel).")
        }
        switch BiometricGate.biometryState() {
        case .lockedOut:
            return String(localized: "\(biometryName) is locked after too many tries. Lock your iPhone and unlock it with the passcode to turn \(biometryName) back on, then choose \(biometricOnlyLabel) again.")
        case .notEnrolled:
            return String(localized: "\(biometricOnlyLabel) needs \(biometryName) set up on this iPhone, under \(biometryName) & Passcode in the Settings app.")
        case .available, .unavailable:
            return String(localized: "AgePony can't use \(biometryName) right now. Check that AgePony is allowed to use \(biometryName) in the Settings app.")
        }
    }

    private var hasEnclaveKeys: Bool {
        vault.identities.contains { $0.type == .secureEnclaveTag || $0.type == .secureEnclaveTagPQ }
    }

    private var biometricOnlyConfirmMessage: String {
        let what = String(localized: "Only \(biometryName) or your app password or PIN will open the vault. The device passcode won't. If \(biometryName) is reset or changed in the Settings app, \(biometryName) stops opening the vault until you enter your password or PIN once.")
        if hasPassword { return what }
        return what + " " + String(localized: "Set a password or PIN first. It's the way back in.")
    }

    private var biometricWord: String {
        switch BiometricGate.availableBiometric() {
        case .faceID:  return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        case .none:    return String(localized: "Passcode")
        }
    }

    private var duressSheetTitle: LocalizedStringKey {
        if hasDuress {
            return "Change duress \(secretNoun)"
        }
        return "Set a duress \(secretNoun)"
    }

    private var passwordSheetTitle: LocalizedStringKey {
        if hasPassword {
            return "Change \(secretNoun)"
        }
        return "Set a password or PIN"
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
                try await BiometricGate.authenticate(reason: String(localized: "Confirm it's you to change how AgePony locks"))
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
            case .duressEqualsReal:       return String(localized: "The duress \(secretNoun) must be different from your real one.")
            case .realEqualsDuress:       return String(localized: "Your \(secretNoun) must be different from the duress \(secretNoun).")
            case .weakSecret:             return UserMessage.text(for: e, fallback: String(localized: "That \(secretNoun) is too short."))
            case .kindLockedByDuress:     return String(localized: "Remove the duress \(secretNoun) first to switch between a password and a PIN.")
            case .lockModeLockedByDuress: return String(localized: "Remove the duress \(secretNoun) to use \(biometricWord).")
            case .passwordIsOnlyUnlock:   return String(localized: "Your \(secretNoun) is the only way into the vault. Choose \(biometricWord) above before removing it.")
            case .noAppPassword:          return String(localized: "Set an app password first.")
            case .notUnlocked:            return String(localized: "Unlock the vault first.")
            case .lockedOut(let millis):  return UserMessage.lockout(millis: millis)
            case .wrongPassword:          return String(localized: "Wrong \(secretNoun).")
            case .vaultFileMissing, .malformedVaultFile, .decryptionFailed:
                return UserMessage.text(for: e, fallback: String(localized: "Couldn't change the lock settings."))
            }
        }
        return UserMessage.text(for: error, fallback: String(localized: "Couldn't change the lock settings."))
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
                    if let message { StatusText(message) }
                    else { Text("Confirm it's you before changing how AgePony locks.") }
                }
            }
            .textCase(nil)
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
                    message = String(localized: "Wrong \(noun).")
                }
            } catch VaultError.lockedOut(let millis) {
                message = UserMessage.lockout(millis: millis)
            } catch {
                message = UserMessage.text(for: error, fallback: String(localized: "Couldn't check the \(noun)."))
            }
        }
    }
}

// MARK: - Secret entry sheet

/// Entry form for a new password/PIN or duress password. Requires a confirmation
/// match and the 5.0.1 minimum length (M-1); for the app password it also
/// offers the password/PIN kind choice.
struct SecretEntrySheet: View {

    let title: LocalizedStringKey
    let allowKindChange: Bool
    let onSave: (_ secret: String, _ kind: UnlockSecretKind) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var kind: UnlockSecretKind
    @State private var secret = ""
    @State private var confirm = ""

    init(title: LocalizedStringKey, kind: UnlockSecretKind, allowKindChange: Bool,
         onSave: @escaping (_ secret: String, _ kind: UnlockSecretKind) -> Void) {
        self.title = title
        self.allowKindChange = allowKindChange
        self.onSave = onSave
        _kind = State(initialValue: kind)
    }

    private var isPIN: Bool { kind == .pin }

    private var validationError: String? {
        if let problem = UserMessage.secretPolicyProblem(secret: secret, isPIN: isPIN) { return problem }
        if secret != confirm { return String(localized: "The two entries don't match.") }
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
                    if isPIN {
                        SecureField("PIN", text: $secret)
                            .textContentType(.newPassword)
                            .keyboardType(.numberPad)
                        SecureField("Confirm PIN", text: $confirm)
                            .textContentType(.newPassword)
                            .keyboardType(.numberPad)
                    } else {
                        SecureField("Password", text: $secret)
                            .textContentType(.newPassword)
                        SecureField("Confirm password", text: $confirm)
                            .textContentType(.newPassword)
                    }
                } footer: {
                    if let err = validationError, !secret.isEmpty || !confirm.isEmpty {
                        StatusText(err)
                    } else if isPIN {
                        Text("At least \(PasswordKeyBlob.minPINLength) digits.")
                    } else {
                        Text("At least \(PasswordKeyBlob.minPasswordLength) characters.")
                    }
                }
            }
            .textCase(nil)
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
