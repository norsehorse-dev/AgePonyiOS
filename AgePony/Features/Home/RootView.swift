//
//  RootView.swift
//  AgePony
//
//  Top-level state router. Owns the Vault @Observable and decides what to
//  show based on launch state.
//
//  Hotfix 3 on 1g: surfaces a "Reset and start over" button when the
//  vault file is missing but a Keychain master key is still present.
//  This state happens after an app delete + reinstall — iOS wipes the
//  app sandbox (vault.dat) but Keychain items persist by default, so we
//  end up with an orphaned master key and no vault to unlock. The
//  previous Locked screen only offered an Unlock button which can't fix
//  this state. The Reset button calls Vault.reset(), which deletes the
//  orphaned Keychain key and returns to onboarding.
//

import SwiftUI

struct RootView: View {

    @State private var vault = Vault()
    @State private var phase: AppPhase = .resolving
    @State private var lockError: String?
    @State private var vaultMissing: Bool = false
    @State private var lastBackgrounded: Date?
    /// Which tab HomeView is showing.
    ///
    /// Held here rather than in HomeView because HomeView is torn down and
    /// rebuilt every time the vault locks and unlocks; state that lives there
    /// does not survive a re-lock.
    @State private var selectedTab: HomeView.Tab = .files
    @State private var resetError: String?

    @Environment(\.scenePhase) private var scenePhase

    private let backgroundGrace: TimeInterval = 30

    enum AppPhase {
        case resolving
        case fresh
        case locked
        case unlocked
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
                    vaultMissing: vaultMissing,
                    onUnlock: startUnlock,
                    onReset: performReset
                )
            case .unlocked:
                HomeView(vault: vault, selectedTab: $selectedTab)
            }
        }
        .environment(vault)
        .task { resolveInitialPhase() }
        .onChange(of: scenePhase) { _, newValue in
            handleScenePhaseChange(newValue)
        }
        .alert(
            "Reset failed",
            isPresented: Binding(get: { resetError != nil }, set: { if !$0 { resetError = nil } })
        ) {
            Button("OK", role: .cancel) { resetError = nil }
        } message: {
            Text(resetError ?? "")
        }
    }

    // MARK: - Phase transitions

    private func resolveInitialPhase() {
        if Vault.isProvisioned() {
            phase = .locked
            startUnlock()
        } else {
            phase = .fresh
        }
    }

    private func startUnlock() {
        Task { await performUnlock() }
    }

    private func performUnlock() async {
        do {
            try await vault.unlock(prompt: "Unlock AgePony")
            lockError = nil
            vaultMissing = false
            phase = .unlocked
        } catch BiometricGateError.userCancelled {
            lockError = nil
            phase = .locked
        } catch let e as KeychainError where e == .notFound {
            // Master key gone — vault was reset behind us, or hasn't been
            // provisioned. Fall to onboarding.
            phase = .fresh
        } catch VaultError.vaultFileMissing {
            // Keychain has a master key, but the vault file isn't there.
            // Happens after delete + reinstall. The Reset button surfaces
            // through `vaultMissing`.
            vaultMissing = true
            lockError = readableMessage(for: VaultError.vaultFileMissing)
            phase = .locked
        } catch {
            lockError = readableMessage(for: error)
            phase = .locked
        }
    }

    /// Clears the orphaned Keychain master key, the (already-missing)
    /// vault file, onboarding state, and active-identity preference. Then
    /// transitions to .fresh so the user re-onboards.
    private func performReset() {
        do {
            try vault.reset()
            // Re-create the @State vault so the in-memory model is a clean
            // slate (the existing `vault` is still bound to the old state).
            vault = Vault()
            selectedTab = .files
            vaultMissing = false
            lockError = nil
            phase = .fresh
        } catch {
            resetError = error.localizedDescription
        }
    }

    private func handleScenePhaseChange(_ newPhase: ScenePhase) {
        switch newPhase {
        case .background, .inactive:
            lastBackgrounded = Date()
        case .active:
            if phase == .unlocked, let stamp = lastBackgrounded {
                let elapsed = Date().timeIntervalSince(stamp)
                if elapsed >= backgroundGrace {
                    vault.lock()
                    phase = .locked
                    startUnlock()
                }
            }
            lastBackgrounded = nil
        @unknown default:
            break
        }
    }

    private func readableMessage(for error: Error) -> String {
        if let e = error as? BiometricGateError {
            switch e {
            case .unavailable:        return "Biometric authentication is unavailable on this device."
            case .userCancelled:      return ""
            case .failed(let msg):    return msg
            }
        }
        if let e = error as? VaultError {
            switch e {
            case .notUnlocked:        return "Vault state is inconsistent. Try unlocking again."
            case .vaultFileMissing:   return "The vault file is missing. This usually means AgePony was reinstalled. Tap Reset to start over with a fresh vault."
            case .malformedVaultFile: return "The vault file is corrupted."
            case .decryptionFailed:   return "Could not decrypt the vault — the master key may have been invalidated."
            }
        }
        return error.localizedDescription
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
    let vaultMissing: Bool
    let onUnlock: () -> Void
    let onReset: () -> Void

    @State private var confirmingReset: Bool = false

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
                Text(vaultMissing ? "Vault missing" : "Locked")
                    .font(AgePonyTypography.headline)
                    .foregroundStyle(.white.opacity(0.85))
                if let msg = error, !msg.isEmpty {
                    Text(msg)
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.white.opacity(0.9))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                Spacer()
                VStack(spacing: 12) {
                    if vaultMissing {
                        Button("Reset and start over") {
                            confirmingReset = true
                        }
                        .buttonStyle(.agePonyPrimary)
                        Button("Try unlock again", action: onUnlock)
                            .font(AgePonyTypography.footnote)
                            .foregroundStyle(.white.opacity(0.85))
                    } else {
                        Button("Unlock", action: onUnlock)
                            .buttonStyle(.agePonyPrimary)
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
            Text("This deletes the master key from Keychain so you can set up AgePony from scratch. The current vault file is already missing — there's no data to lose. You'll need to re-import any identities or recipients you had before.")
        }
    }
}
