//
//  OnboardingView.swift
//  AgePony
//
//  Shown on first launch when no vault exists on the device. Walks the user
//  through bootstrapping the vault and creating their first identity. Once
//  the identity is saved, calls back to RootView so the home screen can
//  take over.
//
//  A phone with no passcode (5.0.1, plan 2.8): iOS refuses a Keychain item
//  behind Face ID / Touch ID / the passcode, which is what the default lock
//  uses, so setup used to stop on a bare "KeychainError error 0". Setup now
//  checks first and says so plainly, and offers an AgePony password or PIN
//  instead: the vault key is then wrapped under that secret only (No lock mode
//  plus a password, M-3).
//

import SwiftUI

struct OnboardingView: View {

    let vault: Vault
    let onComplete: () -> Void

    @State private var stage: Stage = .welcome
    @State private var bootstrapError: String?
    @State private var showSetPassword = false
    @State private var showPasswordOnlySetup = false
    @State private var working = false

    enum Stage {
        case welcome
        case noPasscode
        case lockSetup
        case choice
        case generate
        case importExisting
    }

    var body: some View {
        NavigationStack {
            switch stage {
            case .welcome:
                WelcomeStage(onContinue: bootstrapAndContinue)
            case .noPasscode:
                NoPasscodeStage(
                    working: working,
                    onCheckAgain: bootstrapAndContinue,
                    onUsePassword: { showPasswordOnlySetup = true }
                )
            case .lockSetup:
                LockSetupStage(
                    biometricWord: biometricWord,
                    onBiometric: { stage = .choice },
                    onSetPassword: { showSetPassword = true }
                )
            case .choice:
                ChoiceStage(
                    onGenerate: { stage = .generate },
                    onImport:   { stage = .importExisting }
                )
            case .generate:
                GenerateIdentityView(vault: vault, onDone: onComplete)
            case .importExisting:
                ImportIdentityView(vault: vault, onDone: onComplete)
            }
        }
        .sheet(isPresented: $showSetPassword) {
            SecretEntrySheet(title: "Set a password or PIN", kind: .password, allowKindChange: true) { secret, kind in
                Task {
                    do {
                        try await vault.setAppPassword(secret, kind: kind)
                        stage = .choice
                    } catch {
                        bootstrapError = error.localizedDescription
                    }
                }
            }
        }
        .sheet(isPresented: $showPasswordOnlySetup) {
            SecretEntrySheet(title: "Set a password or PIN", kind: .password, allowKindChange: true) { secret, kind in
                setUpPasswordOnly(secret: secret, kind: kind)
            }
        }
        .alert("Couldn't initialize AgePony", isPresented: Binding(
            get: { bootstrapError != nil },
            set: { if !$0 { bootstrapError = nil } }
        ), actions: {
            Button("OK", role: .cancel) { bootstrapError = nil }
        }, message: {
            Text(bootstrapError ?? "")
        })
    }

    private func bootstrapAndContinue() {
        // Without a passcode the default lock can't be stored at all (plan 2.8).
        guard BiometricGate.devicePasscodeIsSet() else {
            stage = .noPasscode
            return
        }
        Task {
            do {
                try await vault.bootstrap()
                stage = .lockSetup
            } catch {
                bootstrapError = error.localizedDescription
            }
        }
    }

    /// A vault opened only by an AgePony password or PIN, for a phone with no
    /// passcode. The key goes into the Keychain with no ACL just long enough for
    /// the password to wrap it; setting the password removes that copy (M-3).
    /// If anything fails part way, the half-made vault is removed, so there is
    /// never an unprotected one.
    private func setUpPasswordOnly(secret: String, kind: UnlockSecretKind) {
        working = true
        Task {
            defer { working = false }
            do {
                try await vault.bootstrap(lockMode: .none)
                try await vault.setAppPassword(secret, kind: kind)
                stage = .choice
            } catch {
                try? vault.reset()
                bootstrapError = error.localizedDescription
            }
        }
    }

    private var biometricWord: String {
        switch BiometricGate.availableBiometric() {
        case .faceID:  return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        case .none:    return "device passcode"
        }
    }
}

// MARK: - Welcome

private struct WelcomeStage: View {
    let onContinue: () -> Void

    var body: some View {
        ZStack {
            AgePonyColors.brandGradient.ignoresSafeArea()
            VStack(spacing: 24) {
                Spacer()
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 72, weight: .light))
                    .foregroundStyle(.white)
                Text("AgePony")
                    .font(AgePonyTypography.largeTitle)
                    .foregroundStyle(.white)
                Text("Modern file encryption.")
                    .font(AgePonyTypography.headline)
                    .foregroundStyle(.white.opacity(0.9))
                VStack(spacing: 12) {
                    BulletRow(text: "Encrypt files and notes to people you trust.")
                    BulletRow(text: "Identities and keys stored locally, biometrically gated.")
                    BulletRow(text: "Zero accounts. Zero cloud. Zero telemetry.")
                }
                .padding(.horizontal, 24)
                .padding(.top, 16)
                Spacer()
                Button("Get started", action: onContinue)
                    .buttonStyle(.agePonyPrimary)
                    .padding(.horizontal, 32)
                    .padding(.bottom, 40)
            }
        }
    }
}

private struct BulletRow: View {
    let text: String
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "checkmark")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
            Text(text)
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - No passcode (plan 2.8)

private struct NoPasscodeStage: View {
    let working: Bool
    let onCheckAgain: () -> Void
    let onUsePassword: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 12) {
                Image(systemName: "lock.slash")
                    .font(.system(size: 44, weight: .light))
                    .foregroundStyle(AgePonyColors.tealCore)
                Text("This iPhone has no passcode")
                    .font(AgePonyTypography.title)
                    .multilineTextAlignment(.center)
                Text("AgePony normally locks your vault with Face ID, Touch ID or your passcode. iOS only allows that when the iPhone has a passcode, so that lock isn't available here.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Text("Set a passcode in Settings › Face ID & Passcode and come back, or protect AgePony with its own password or PIN.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 24)
            .padding(.top, 24)

            Spacer()

            VStack(spacing: 14) {
                Button("Use an AgePony password or PIN", action: onUsePassword)
                    .buttonStyle(.agePonyPrimary)
                    .disabled(working)

                Button("I've set a passcode, check again", action: onCheckAgain)
                    .buttonStyle(.agePonySecondary)
                    .disabled(working)

                if working {
                    ProgressView()
                }

                Text("Without a passcode, anyone holding the unlocked phone can open its apps. The AgePony password is then the only thing in front of your keys, so make it a strong one.")
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 8)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
        .navigationTitle("Setup")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Lock setup

private struct LockSetupStage: View {
    let biometricWord: String
    let onBiometric: () -> Void
    let onSetPassword: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 8) {
                Text("How AgePony unlocks")
                    .font(AgePonyTypography.title)
                Text("Your vault is protected on this device. Choose how you unlock it — you can change this anytime in Settings, including adding a duress password.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }
            .padding(.top, 24)

            Spacer()

            VStack(spacing: 14) {
                Button("Continue with \(biometricWord)", action: onBiometric)
                    .buttonStyle(.agePonyPrimary)

                Button("Set a password or PIN", action: onSetPassword)
                    .buttonStyle(.agePonySecondary)

                Text("A password works with or without biometrics, and is required before you can set a duress password.")
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 8)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
        .navigationTitle("Setup")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Choice

private struct ChoiceStage: View {
    let onGenerate: () -> Void
    let onImport:   () -> Void

    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 8) {
                Text("Add your first identity")
                    .font(AgePonyTypography.title)
                Text("AgePony needs at least one identity to decrypt files sent to you.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }
            .padding(.top, 24)

            Spacer()

            VStack(spacing: 14) {
                Button("Generate new identity", action: onGenerate)
                    .buttonStyle(.agePonyPrimary)

                Button("Import existing identity", action: onImport)
                    .buttonStyle(.agePonySecondary)

                Text("You can add more identities later in the Identities tab.")
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 8)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
        .navigationTitle("Setup")
        .navigationBarTitleDisplayMode(.inline)
    }
}
