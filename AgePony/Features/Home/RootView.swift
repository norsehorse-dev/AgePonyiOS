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
            case .vaultFileMissing: return "Vault missing"
            case .keyMissing:       return "Can't open vault"
            }
        }

        var resetWarning: String {
            switch self {
            case .vaultFileMissing:
                return "This deletes the leftover key so you can set up AgePony from scratch. The vault file is already missing, so there's no data to lose. You'll need to re-import any identities or recipients you had before."
            case .keyMissing:
                return "The vault file is still on this phone, but the key that opens it is gone, so its contents can't be recovered here. Resetting deletes it and starts a new, empty vault. Restore your keys from a backup or a transfer afterwards."
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
            // Leftovers from a previous run: claimed files, and staged payloads
            // nobody came back for.
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
        vault.lockMode == .biometric && !vault.hasDuressPassword
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
        if !vault.hasAppPassword {
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
                    phase = .unlocked
                case .erased:
                    vault = Vault()
                    selectedTab = .files
                    lockError = nil
                    phase = .fresh
                    notice = "The \(noun) was entered wrong \(UnlockAttempts.eraseAfter) times, so the vault was erased as set in Settings."
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
        case .none:    return "Passcode"
        }
    }

    private func startUnlock() {
        Task { await performUnlock() }
    }

    private func performUnlock() async {
        do {
            try await vault.unlock(prompt: "Unlock AgePony")
            lockError = nil
            recovery = nil
            phase = .unlocked
        } catch BiometricGateError.userCancelled {
            lockError = nil
            phase = .locked
        } catch let e as KeychainError where e == .notFound {
            if vault.hasAppPassword {
                // Password-only vault: the password field is the way in.
                lockError = nil
                phase = .locked
            } else if vault.vaultFileExists {
                // The vault is here but nothing left opens it. Never fall to
                // onboarding, which would write a new vault over it (L-25).
                recovery = .keyMissing
                lockError = "The key that opens this vault is missing from this iPhone's Keychain."
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
            resetError = error.localizedDescription
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
                if !vault.hasAppPassword && recovery == nil { startUnlock() }
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
        if let e = error as? BiometricGateError {
            switch e {
            case .unavailable:        return "Biometric authentication is unavailable on this device."
            case .userCancelled:      return ""
            case .failed(let msg):    return msg
            }
        }
        if let e = error as? PasswordKeyBlob.BlobError, e == .deviceKeyMissing {
            return "This iPhone's key for the app \(noun) is missing, so the \(noun) can't open the vault."
        }
        if let e = error as? VaultError {
            switch e {
            case .notUnlocked:        return "Vault state is inconsistent. Try unlocking again."
            case .vaultFileMissing:   return "The vault file is missing. This usually means AgePony was reinstalled. Tap Reset to start over with a fresh vault."
            case .malformedVaultFile: return "The vault file is corrupted."
            case .decryptionFailed:   return "Could not decrypt the vault. The master key may have been invalidated."
            case .wrongPassword(let failures):
                return wrongSecretMessage(noun: noun, failures: failures)
            case .lockedOut(let millis):
                return UnlockAttempts.lockoutMessage(millis: millis)
            case .noAppPassword:      return "No app password is set for this vault."
            default:                  return "Could not unlock the vault."
            }
        }
        return error.localizedDescription
    }

    private func wrongSecretMessage(noun: String, failures: Int) -> String {
        var text = "Wrong \(noun)."
        if vault.eraseAfterFailedAttempts {
            let left = UnlockAttempts.eraseAfter - failures
            if (1...3).contains(left) {
                text += left == 1 ? " One more wrong try will erase the vault." : " \(left) more wrong tries will erase the vault."
            }
        }
        let wait = vault.lockoutRemainingMillis()
        if wait > 0 {
            text += " Try again in \(UnlockAttempts.describeWait(millis: wait))."
        }
        return text
    }
}

// MARK: - Sub-views

private struct ResolvingView: View {
    var body: some View {
        ZStack {
            AgePonyColors.brandGradient.ignoresSafeArea()
            VStack(spacing: 16) {
                ProgressView()
                    .controlSize(.large)
                    .tint(.white)
                Text("AgePony")
                    .font(AgePonyTypography.title)
                    .foregroundStyle(.white)
            }
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
    let biometricWord: String
    let shareWaiting: Bool
    let onUnlock: () -> Void
    let onPassword: (String) -> Void
    let onReset: () -> Void
    let onPassphraseMode: () -> Void

    @State private var confirmingReset: Bool = false
    @State private var secret: String = ""

    private func submit() {
        guard !secret.isEmpty, !busy else { return }
        let entered = secret
        secret = ""
        onPassword(entered)
    }

    var body: some View {
        ZStack {
            AgePonyColors.brandGradient.ignoresSafeArea()
            VStack(spacing: 24) {
                Spacer()
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 64, weight: .light))
                    .foregroundStyle(.white)
                Text("AgePony")
                    .font(AgePonyTypography.largeTitle)
                    .foregroundStyle(.white)
                Text(recovery?.title ?? "Locked")
                    .font(AgePonyTypography.headline)
                    .foregroundStyle(.white.opacity(0.85))
                if let msg = error, !msg.isEmpty {
                    Text(msg)
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.white.opacity(0.9))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                if shareWaiting && recovery == nil {
                    Label("Something you shared is waiting. Unlock to use it, or continue without unlocking if it's protected with a passphrase.", systemImage: "square.and.arrow.down")
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.white)
                        .padding(12)
                        .background(.white.opacity(0.15), in: RoundedRectangle(cornerRadius: 10))
                        .padding(.horizontal, 32)
                }
                Spacer()
                VStack(spacing: 12) {
                    if recovery != nil {
                        Button("Reset and start over") {
                            confirmingReset = true
                        }
                        .buttonStyle(.agePonyPrimary)
                        if recovery == .vaultFileMissing {
                            Button("Try unlock again", action: onUnlock)
                                .font(AgePonyTypography.footnote)
                                .foregroundStyle(.white.opacity(0.85))
                        }
                    } else if hasAppPassword {
                        SecureField(secretKind == .pin ? "PIN" : "Password", text: $secret)
                            .textContentType(.password)
                            .keyboardType(secretKind == .pin ? .numberPad : .default)
                            .submitLabel(.go)
                            .onSubmit(submit)
                            .padding(12)
                            .background(.white, in: RoundedRectangle(cornerRadius: 10))
                            .foregroundStyle(.black)
                            .disabled(busy)
                        Button(action: submit) {
                            if busy { ProgressView().tint(.white) } else { Text("Unlock") }
                        }
                        .buttonStyle(.agePonyPrimary)
                        .disabled(secret.isEmpty || busy)
                        if showBiometricButton {
                            Button("Use \(biometricWord)", action: onUnlock)
                                .font(AgePonyTypography.footnote)
                                .foregroundStyle(.white.opacity(0.85))
                        }
                    } else {
                        Button("Unlock", action: onUnlock)
                            .buttonStyle(.agePonyPrimary)
                    }
                    if recovery == nil {
                        Button("Continue without unlocking", action: onPassphraseMode)
                            .font(AgePonyTypography.footnote)
                            .foregroundStyle(.white.opacity(0.85))
                    }
                }
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
            }
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
