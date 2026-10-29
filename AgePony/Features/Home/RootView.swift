//
//  RootView.swift
//  AgePony
//
//  Top-level state router. Owns the Vault @Observable and decides what to
//  show based on launch state.
//
//  Recovery: when the vault can't be opened by any means it has left (the
//  vault file is gone after a reinstall while the Keychain key survived, or
//  the Keychain key is gone while the vault file is still there), the lock
//  screen offers "Reset and start over" instead of an Unlock button that can
//  never work. Onboarding is only ever shown when no part of a vault exists,
//  so it can't write a new vault over one that is merely locked (L-25).
//
//  Auto-lock (5.0.1, audit M-4): measured on a monotonic clock that the user
//  can't set, and a restart of the phone while the app was away always locks.
//  With "Immediately" the vault locks the moment the app goes to the
//  background; with a grace period it also locks when the period runs out while
//  the app is still in the background, as long as iOS lets it run that long.
//  Locking the phone locks the vault at once.
//
//  Face ID only (5.1.0, E6): the lock screen starts Face ID by itself and offers
//  the app password second. When Face ID can't open the vault (it was reset or
//  a face was added, or it isn't available), the password field comes up with a
//  sentence saying why; a password unlock writes a fresh Face ID item.
//
//  Shares (5.0.1, M-7): RootView receives the share extension's token even
//  while the vault is locked, claims the payload at once (so nothing stays in
//  the App Group) and holds it. Unlocked, HomeView shows it; locked, the lock
//  screen says it's waiting and passphrase mode can finish a passphrase job
//  without unlocking. If the extension couldn't open the app, a recent staged
//  payload is picked up the next time AgePony comes to the front.
//

import SwiftUI
import UIKit
import AgePonyCore

struct RootView: View {

    @State private var vault = Vault()
    @State private var phase: AppPhase = .resolving
    @State private var lockError: String?
    @State private var recovery: Recovery?
    @State private var busy = false
    @State private var backgroundedAt: (millis: UInt64, boot: Int64)?
    @State private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    @State private var graceTimer: Task<Void, Never>?
    @State private var unlockOnReturn = false
    /// Which tab HomeView is showing.
    ///
    /// Held here rather than in HomeView because HomeView is torn down and
    /// rebuilt every time the vault locks and unlocks; state that lives there
    /// does not survive a re-lock.
    @State private var selectedTab: HomeView.Tab = .files
    @State private var resetError: String?
    @State private var notice: String?
    @State private var pendingShare: ClaimedShare?
    @State private var showPassphraseMode = false
    /// Face ID only: Face ID couldn't open the vault, so the lock screen shows
    /// the password field and stops starting Face ID by itself (E6).
    @State private var passwordFallback = false

    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(AppTheme.storageKey) private var themeRaw: String = AppTheme.system.rawValue

    enum AppPhase {
        case resolving
        case fresh
        case locked
        case unlocked
    }

    /// Why the lock screen shows a reset button.
    enum Recovery: Equatable {
        /// The Keychain key survived a reinstall but the vault file didn't.
        case vaultFileMissing
        /// The vault file is there but nothing left can open it.
        case keyMissing

        var title: String {
            switch self {
            case .vaultFileMissing: return String(localized: "Vault missing")
            case .keyMissing:       return String(localized: "Can't open vault")
            }
        }

        var resetWarning: String {
            switch self {
            case .vaultFileMissing:
                return String(localized: "This deletes the leftover key so you can set up AgePony from scratch. The vault file is already missing, so there's no data to lose. You'll need to re-import any identities or recipients you had before.")
            case .keyMissing:
                return String(localized: "The vault file is still on this phone, but the key that opens it is gone, so its contents can't be recovered here. Resetting deletes it and starts a new, empty vault. Restore your keys from a backup or a transfer afterwards.")
            }
        }
    }

    var body: some View {
        Group {
            switch phase {
            case .resolving:
                ResolvingView()
            case .fresh:
                OnboardingView(vault: vault, onComplete: {
                    vault.hasCompletedOnboarding = true
                    phase = .unlocked
                })
            case .locked:
                LockedView(
                    error: lockError,
                    recovery: recovery,
                    busy: busy,
                    hasAppPassword: vault.hasAppPassword,
                    secretKind: vault.unlockSecretKind,
                    showBiometricButton: showBiometricButton,
                    biometricFirst: biometricFirst,
                    forcePasswordField: passwordFallback,
                    biometricWord: biometricWord,
                    shareWaiting: pendingShare != nil,
                    onUnlock: startUnlock,
                    onPassword: submitPassword,
                    onReset: performReset,
                    onPassphraseMode: { showPassphraseMode = true }
                )
            case .unlocked:
                HomeView(vault: vault, selectedTab: $selectedTab, pendingShare: $pendingShare)
            }
        }
        .environment(vault)
        .preferredColorScheme((AppTheme(rawValue: themeRaw) ?? .system).colorScheme)
        .task {
            // Leftovers from a previous run: plaintext a run that was killed left in
            // tmp (5.1.1, M-2), claimed files, and staged payloads nobody came back for.
            // Not sweepAll: a share claimed as the app opens can already be in tmp.
            TempFileCleanup.sweepSessionFiles()
            TempFileCleanup.sweepKeyFiles()
            SharedContainer.removeClaimed()
            SharedContainer.sweepStale()
            #if DEBUG
            // App Store screenshots: a fresh demo vault, unlocked (DemoSeed).
            if DemoSeed.requested {
                await DemoSeed.seed(into: vault)
                phase = .unlocked
                return
            }
            #endif
            resolveInitialPhase()
            pickUpStagedShare()
        }
        .onReceive(NotificationCenter.default.publisher(for: .agePonyShareIncoming)) { note in
            if let token = note.userInfo?["token"] as? String { claimShare(token: token) }
        }
        .sheet(isPresented: $showPassphraseMode) {
            PassphraseModeView(pendingShare: $pendingShare, workFactor: vault.scryptWorkFactor) {
                showPassphraseMode = false
            }
        }
        .onAppear { PrivacyShield.shared.setSceneActive(scenePhase == .active) }
        .onChange(of: scenePhase) { _, newValue in
            PrivacyShield.shared.setSceneActive(newValue == .active)
            handleScenePhaseChange(newValue)
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)) { _ in
            // The phone is locking: lock the vault too, whatever the grace period.
            if phase == .unlocked { lockNow() }
        }
        .alert(
            "Reset failed",
            isPresented: Binding(get: { resetError != nil }, set: { if !$0 { resetError = nil } })
        ) {
            Button("OK", role: .cancel) { resetError = nil }
        } message: {
            Text(resetError ?? "")
        }
        .alert(
            "Vault erased",
            isPresented: Binding(get: { notice != nil }, set: { if !$0 { notice = nil } })
        ) {
            Button("OK", role: .cancel) { notice = nil }
        } message: {
            Text(notice ?? "")
        }
    }

    /// Face ID is offered only when the vault has a biometric Keychain copy to
    /// open: never while a duress password makes it password-only (H-1).
    private var showBiometricButton: Bool {
        vault.lockMode.requiresBiometricACL && !vault.hasDuressPassword
    }

    /// Face ID only (E6): Face ID is the first way in, the password the second.
    private var biometricFirst: Bool {
        vault.lockMode == .biometricOnly && !vault.hasDuressPassword
    }

    /// Whether to start the system prompt without a tap: always when there is
    /// no app password, and in Face ID only mode until Face ID has failed to
    /// open the vault.
    private var autoStartsUnlock: Bool {
        !vault.hasAppPassword || (biometricFirst && !passwordFallback)
    }

    // MARK: - Phase transitions

    private func resolveInitialPhase() {
        guard Vault.isProvisioned() else {
            phase = .fresh
            return
        }
        phase = .locked
        // With an app password, wait for the user to enter it (or tap
        // biometric); without one, unlock via biometric / silent no-lock.
        // Face ID only starts Face ID first (E6).
        if autoStartsUnlock {
            startUnlock()
        }
    }

    private func submitPassword(_ secret: String) {
        guard !busy else { return }
        busy = true
        let noun = (vault.unlockSecretKind ?? .password).displayNoun
        Task {
            defer { busy = false }
            do {
                switch try await vault.unlockWithPassword(secret) {
                case .unlocked:
                    lockError = nil
                    recovery = nil
                    passwordFallback = false
                    phase = .unlocked
                case .erased:
                    vault = Vault()
                    selectedTab = .files
                    lockError = nil
                    phase = .fresh
                    notice = String(localized: "The \(noun) was entered wrong \(UnlockAttempts.eraseAfter) times, so the vault was erased as set in Settings.")
                }
            } catch {
                if (error as? PasswordKeyBlob.BlobError) == .deviceKeyMissing { recovery = .keyMissing }
                lockError = readableMessage(for: error)
                phase = .locked
            }
        }
    }

    private var biometricWord: String {
        switch BiometricGate.availableBiometric() {
        case .faceID:  return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        case .none:
            // Face ID only never falls back to the passcode, so name the
            // biometric even while nothing is enrolled.
            return vault.lockMode == .biometricOnly ? BiometricGate.biometryName() : String(localized: "Passcode")
        }
    }

    private func startUnlock() {
        Task { await performUnlock() }
    }

    private func performUnlock() async {
        do {
            try await vault.unlock(prompt: String(localized: "Unlock AgePony"))
            lockError = nil
            recovery = nil
            passwordFallback = false
            phase = .unlocked
        } catch BiometricGateError.userCancelled {
            lockError = nil
            phase = .locked
        } catch let e as KeychainError where e == .biometryChanged && vault.hasAppPassword {
            // Face ID only after a Face ID reset or a new face (E6): the
            // password opens the vault and puts a fresh Face ID item back.
            lockError = readableMessage(for: e)
            passwordFallback = true
            phase = .locked
        } catch let e as KeychainError where e == .notFound || e == .biometryChanged {
            if vault.hasAppPassword {
                // Password-only vault: the password field is the way in.
                lockError = nil
                passwordFallback = true
                phase = .locked
            } else if vault.vaultFileExists {
                // The vault is here but nothing left opens it. Never fall to
                // onboarding, which would write a new vault over it (L-25).
                recovery = .keyMissing
                lockError = String(localized: "The key that opens this vault is missing from this iPhone's Keychain.")
                phase = .locked
            } else {
                phase = .fresh
            }
        } catch VaultError.vaultFileMissing {
            // Keychain has a master key, but the vault file isn't there.
            // Happens after delete + reinstall.
            recovery = .vaultFileMissing
            lockError = readableMessage(for: VaultError.vaultFileMissing)
            phase = .locked
        } catch {
            lockError = readableMessage(for: error)
            // Face ID only: any other Face ID failure leaves the password.
            if biometricFirst && vault.hasAppPassword { passwordFallback = true }
            phase = .locked
        }
    }

    /// Clears the vault and every key for it, then transitions to .fresh so
    /// the user re-onboards.
    private func performReset() {
        do {
            try vault.reset()
            // Re-create the @State vault so the in-memory model is a clean
            // slate (the existing `vault` is still bound to the old state).
            vault = Vault()
            selectedTab = .files
            recovery = nil
            lockError = nil
            phase = .fresh
        } catch {
            resetError = UserMessage.text(for: error, fallback: String(localized: "Couldn't reset the vault. Try again, or delete and reinstall AgePony."))
        }
    }

    // MARK: - Shares (M-7)

    private func claimShare(token: String) {
        guard let share = try? SharedContainer.claim(token: token) else { return }
        if let old = pendingShare, old.id != share.id { old.discard() }
        pendingShare = share
    }

    /// The extension stages first and then asks iOS to open AgePony. When that
    /// second step doesn't happen, the payload is still waiting: take the
    /// newest one from the last ten minutes.
    private func pickUpStagedShare() {
        guard pendingShare == nil,
              let token = SharedContainer.pendingTokens(maxAge: 600).first else { return }
        claimShare(token: token)
    }

    // MARK: - Auto-lock (M-4)

    private func handleScenePhaseChange(_ newPhase: ScenePhase) {
        switch newPhase {
        case .background:
            guard phase == .unlocked, backgroundedAt == nil else { return }
            backgroundedAt = (MonotonicClock.millis(), MonotonicClock.bootTime())
            let grace = vault.autoLockGraceSeconds
            if grace <= 0 {
                lockNow()
            } else {
                scheduleBackgroundLock(after: grace)
            }
        case .inactive:
            break
        case .active:
            cancelBackgroundLock()
            pickUpStagedShare()
            if phase == .unlocked, let stamp = backgroundedAt, shouldLock(since: stamp) {
                lockNow()
            }
            backgroundedAt = nil
            if phase == .locked && unlockOnReturn {
                unlockOnReturn = false
                if autoStartsUnlock && recovery == nil { startUnlock() }
            }
        @unknown default:
            break
        }
    }

    /// Whether the grace period has run out since `stamp`. A clock that went
    /// backwards or a moved boot time means the phone restarted: lock.
    private func shouldLock(since stamp: (millis: UInt64, boot: Int64)) -> Bool {
        let now = MonotonicClock.millis()
        let boot = MonotonicClock.bootTime()
        if now < stamp.millis { return true }
        if stamp.boot >= 0, boot >= 0, abs(stamp.boot - boot) > 120 { return true }
        return now - stamp.millis >= UInt64(max(vault.autoLockGraceSeconds, 0)) * 1000
    }

    private func lockNow() {
        vault.lock()
        phase = .locked
        unlockOnReturn = true
        // Nothing shared outlives the session it was opened in (M-7).
        pendingShare?.discard()
        pendingShare = nil
        showPassphraseMode = false
        SharedContainer.removeClaimed()
        SharedContainer.removeAll()
        // Decrypted output goes with the screens that showed it (5.1.1, M-2).
        TempFileCleanup.sweepSessionFiles(includingIntents: false)
    }

    /// Keep the app running for the grace period after it leaves the screen and
    /// lock when it ends. iOS gives a background task limited time; if it ends
    /// first, the check on return still locks.
    private func scheduleBackgroundLock(after seconds: Int) {
        cancelBackgroundLock()
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "AgePony auto-lock") {
            Task { @MainActor in cancelBackgroundLock() }
        }
        graceTimer = Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            guard !Task.isCancelled else { return }
            if phase == .unlocked, scenePhase != .active { lockNow() }
            cancelBackgroundLock()
        }
    }

    private func cancelBackgroundLock() {
        graceTimer?.cancel()
        graceTimer = nil
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    // MARK: - Messages

    private func readableMessage(for error: Error) -> String {
        let noun = (vault.unlockSecretKind ?? .password).displayNoun
        if let e = error as? KeychainError, e == .biometryChanged {
            // The password unlock binds whatever is enrolled now, so say to
            // check for an enrolment the owner didn't make (E6 review).
            let changed = String(localized: "\(biometricWord) changed on this iPhone, so it can't open the vault until you enter your \(noun) once. After that, \(biometricWord) works again.")
            let check = BiometricGate.availableBiometric() == .touchID
                ? String(localized: "If you didn't change \(biometricWord) yourself, check Settings > \(biometricWord) & Passcode for a fingerprint you didn't add before you enter your \(noun).")
                : String(localized: "If you didn't change \(biometricWord) yourself, check Settings > \(biometricWord) & Passcode for an appearance you didn't add before you enter your \(noun).")
            return changed + " " + check
        }
        if let e = error as? BiometricGateError, e == .unavailable, biometricFirst {
            if BiometricGate.biometryState() == .lockedOut {
                return String(localized: "\(biometricWord) is locked after too many tries. Enter your \(noun) to open the vault. Unlocking the iPhone with its passcode turns \(biometricWord) back on, but the passcode doesn't open AgePony.")
            }
            return String(localized: "\(biometricWord) isn't available right now. Enter your \(noun) to open the vault. The device passcode doesn't open it.")
        }
        if let e = error as? BiometricGateError {
            switch e {
            case .unavailable:        return UserMessage.text(for: e, fallback: String(localized: "Couldn't unlock the vault."))
            case .userCancelled:      return ""
            case .failed(let msg):    return msg
            }
        }
        if let e = error as? PasswordKeyBlob.BlobError, e == .deviceKeyMissing {
            return String(localized: "This iPhone's key for the app \(noun) is missing, so the \(noun) can't open the vault.")
        }
        if let e = error as? VaultError {
            switch e {
            case .notUnlocked:        return String(localized: "The vault didn't finish opening. Try unlocking again.")
            case .vaultFileMissing:   return String(localized: "The vault file is missing. This usually means AgePony was reinstalled. Tap Reset and start over to set up a new vault.")
            case .malformedVaultFile: return String(localized: "The vault file is damaged and can't be read.")
            case .decryptionFailed:   return String(localized: "The vault couldn't be decrypted. Its key in the Keychain may have been reset.")
            case .wrongPassword(let failures):
                return wrongSecretMessage(noun: noun, failures: failures)
            case .lockedOut(let millis):
                return UserMessage.lockout(millis: millis)
            case .noAppPassword:      return String(localized: "No app password is set for this vault.")
            case .duressEqualsReal, .realEqualsDuress, .weakSecret, .kindLockedByDuress,
                 .lockModeLockedByDuress, .passwordIsOnlyUnlock, .ownerCheckNeeded:
                // Settings errors; they can't come from an unlock, but say what they are.
                return UserMessage.text(for: e, fallback: String(localized: "Couldn't unlock the vault."))
            }
        }
        return UserMessage.text(for: error, fallback: String(localized: "Couldn't unlock the vault."))
    }

    private func wrongSecretMessage(noun: String, failures: Int) -> String {
        var sentences = [String(localized: "Wrong \(noun).")]
        if vault.eraseAfterFailedAttempts {
            let left = UnlockAttempts.eraseAfter - failures
            if (1...3).contains(left) {
                sentences.append(String(AttributedString(localized: "^[\(left) more wrong try](inflect: true) will erase the vault.").characters))
            }
        }
        let wait = vault.lockoutRemainingMillis()
        if wait > 0 {
            sentences.append(String(localized: "Try again in \(UserMessage.waitDescription(millis: wait))."))
        }
        return sentences.joined(separator: " ")
    }
}

// MARK: - Sub-views

private struct ResolvingView: View {
    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            ProgressView()
                .controlSize(.large)
        }
    }
}

private struct LockedView: View {
    let error: String?
    let recovery: RootView.Recovery?
    let busy: Bool
    let hasAppPassword: Bool
    let secretKind: UnlockSecretKind?
    let showBiometricButton: Bool
    /// Face ID only (E6): Face ID first, the password behind "Use password".
    let biometricFirst: Bool
    /// Face ID couldn't open the vault: show the password field straight away.
    let forcePasswordField: Bool
    let biometricWord: String
    let shareWaiting: Bool
    let onUnlock: () -> Void
    let onPassword: (String) -> Void
    let onReset: () -> Void
    let onPassphraseMode: () -> Void

    @State private var confirmingReset: Bool = false
    @State private var secret: String = ""
    @State private var passwordRequested = false

    private var showsPasswordField: Bool {
        !biometricFirst || !showBiometricButton || passwordRequested || forcePasswordField
    }

    private var secretNoun: String { (secretKind ?? .password).displayNoun }

    private func submit() {
        guard !secret.isEmpty, !busy else { return }
        let entered = secret
        secret = ""
        onPassword(entered)
    }

    /// A plain screen (5.1.0, U4): the app name as the title, one sentence on
    /// what's locked, then the ways in. No hero icon or wordmark.
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if let recovery {
                        Text(recovery.title)
                            .font(AgePonyTypography.headline)
                        if let msg = error, !msg.isEmpty {
                            Text(msg)
                        }
                    } else {
                        Text("Your identities, recipients and notes are encrypted on this iPhone. Unlock AgePony to use them.")
                    }
                }

                if recovery == nil, let msg = error, !msg.isEmpty {
                    Section {
                        StatusText(msg)
                    }
                }

                if shareWaiting && recovery == nil {
                    Section {
                        Label("Something you shared is waiting. Unlock to use it, or continue without unlocking if it's protected with a passphrase.", systemImage: "square.and.arrow.down")
                    }
                }

                if recovery != nil {
                    Section {
                        Button("Reset and start over", role: .destructive) {
                            confirmingReset = true
                        }
                        .buttonStyle(.agePonyPrimary)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                    }
                    if recovery == .vaultFileMissing {
                        Section {
                            Button("Try unlocking again", action: onUnlock)
                        }
                    }
                } else if hasAppPassword && !showsPasswordField {
                    Section {
                        Button("Use \(biometricWord)", action: onUnlock)
                            .buttonStyle(.agePonyPrimary)
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(Color.clear)
                            .disabled(busy)
                    }
                    Section {
                        Button("Use \(secretNoun)") { passwordRequested = true }
                    } footer: {
                        Text("The device passcode doesn't open AgePony.")
                    }
                } else if hasAppPassword {
                    Section {
                        Group {
                            if secretKind == .pin {
                                SecureField("PIN", text: $secret)
                                    .keyboardType(.numberPad)
                            } else {
                                SecureField("Password", text: $secret)
                            }
                        }
                        .textContentType(.password)
                        .submitLabel(.go)
                        .onSubmit(submit)
                        .disabled(busy)
                    }
                    Section {
                        Button(action: submit) {
                            if busy { ProgressView().tint(AgePonyColors.onAccent) } else { Text("Unlock") }
                        }
                        .buttonStyle(.agePonyPrimary)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                        .disabled(secret.isEmpty || busy)
                    }
                    if showBiometricButton {
                        Section {
                            Button("Use \(biometricWord)", action: onUnlock)
                        }
                    }
                } else {
                    Section {
                        Button("Unlock", action: onUnlock)
                            .buttonStyle(.agePonyPrimary)
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(Color.clear)
                    }
                }

                if recovery == nil {
                    Section {
                        Button("Continue without unlocking", action: onPassphraseMode)
                    } footer: {
                        Text("Encrypt or decrypt with a passphrase while the vault stays locked.")
                    }
                }
            }
            .textCase(nil)
            .navigationTitle("AgePony")
        }
        .confirmationDialog(
            "Reset AgePony?",
            isPresented: $confirmingReset,
            titleVisibility: .visible
        ) {
            Button("Reset", role: .destructive) {
                onReset()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(recovery?.resetWarning ?? "")
        }
    }
}
