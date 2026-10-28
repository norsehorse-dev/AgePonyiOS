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
//  iOS refusing the lock with a passcode set (5.1.0): some iPhones refuse the
//  Keychain item even with a passcode, with errSecAuthFailed (-25293) and no
//  prompt. KeychainStore now tries weaker system protections first; if iOS
//  refuses all of them, setup lands on the same screen as the no-passcode case,
//  with the codes, instead of an alert with no way forward.
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
        case keychainRefused(String)
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
                    refusedDetail: nil,
                    working: working,
                    onCheckAgain: bootstrapAndContinue,
                    onUsePassword: { showPasswordOnlySetup = true }
                )
            case .keychainRefused(let detail):
                NoPasscodeStage(
                    refusedDetail: detail,
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
                        bootstrapError = UserMessage.text(for: error, fallback: String(localized: "Couldn't set the password or PIN."))
                    }
                }
            }
        }
        .sheet(isPresented: $showPasswordOnlySetup) {
            SecretEntrySheet(title: "Set a password or PIN", kind: .password, allowKindChange: true) { secret, kind in
                setUpPasswordOnly(secret: secret, kind: kind)
            }
        }
        .alert("Couldn't set up AgePony", isPresented: Binding(
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
            } catch let error as KeychainError {
                // Nothing was written (bootstrap stores the key first), so the
                // password route can start clean.
                stage = .keychainRefused(UserMessage.text(for: error, fallback: String(localized: "iOS refused to store the vault key.")))
            } catch {
                bootstrapError = UserMessage.text(for: error, fallback: String(localized: "Couldn't create the vault."))
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
                bootstrapError = UserMessage.text(for: error, fallback: String(localized: "Couldn't create the vault with a password or PIN."))
            }
        }
    }

    private var biometricWord: String {
        switch BiometricGate.availableBiometric() {
        case .faceID:  return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        case .none:    return String(localized: "device passcode")
        }
    }
}

// MARK: - Welcome

/// A plain first screen (5.1.0, U4): the app name as the title, one sentence
/// on what the app does, and Continue. No hero icon, tagline or bullet list.
private struct WelcomeStage: View {
    let onContinue: () -> Void

    var body: some View {
        Form {
            Section {
                Text("AgePony encrypts files, text and notes with age, and your keys stay on this iPhone.")
            }
            Section {
                Button("Continue", action: onContinue)
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            }
        }
        .textCase(nil)
        .navigationTitle("AgePony")
    }
}

// MARK: - No passcode (plan 2.8)

private struct NoPasscodeStage: View {
    /// nil: the iPhone has no passcode. Otherwise iOS refused the lock with a
    /// passcode set, and this is its message with the codes (5.1.0).
    let refusedDetail: String?
    let working: Bool
    let onCheckAgain: () -> Void
    let onUsePassword: () -> Void

    var body: some View {
        Form {
            Section {
                if let refusedDetail {
                    Text("iOS wouldn't lock the vault here")
                        .font(AgePonyTypography.headline)
                    Text("AgePony normally locks your vault with Face ID, Touch ID or your passcode, but iOS refused to store the vault key that way on this iPhone. \(refusedDetail)")
                    Text("You can protect AgePony with its own password or PIN instead, and try the Face ID lock again later in Settings.")
                } else {
                    Text("This iPhone has no passcode")
                        .font(AgePonyTypography.headline)
                    Text("AgePony normally locks your vault with Face ID, Touch ID or your passcode. iOS only allows that when the iPhone has a passcode, so that lock isn't available here.")
                    Text("Set a passcode in the Settings app under Face ID & Passcode and come back, or protect AgePony with its own password or PIN.")
                }
            }

            Section {
                Button("Use an AgePony password or PIN", action: onUsePassword)
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                    .disabled(working)
            } footer: {
                if refusedDetail == nil {
                    Text("Without a passcode, anyone holding the unlocked phone can open its apps. The AgePony password is then the only thing in front of your keys, so make it a strong one.")
                }
            }

            Section {
                HStack {
                    if refusedDetail == nil {
                        Button("I've set a passcode, check again", action: onCheckAgain)
                    } else {
                        Button("Try again", action: onCheckAgain)
                    }
                    if working {
                        Spacer()
                        ProgressView()
                    }
                }
                .disabled(working)
            }
        }
        .textCase(nil)
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
                Text("Your vault is protected on this device. Choose how you unlock it. You can change this anytime in Settings, including adding a duress password.")
                    .font(AgePonyTypography.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }
            .padding(.top, 24)

            Spacer()

            VStack(spacing: 12) {
                Button("Continue with \(biometricWord)", action: onBiometric)
                    .buttonStyle(.agePonyPrimary)

                Button("Set a password or PIN", action: onSetPassword)
                    .buttonStyle(.agePonySecondary)

                Text("A password works with or without biometrics, and is required before you can set a duress password.")
                    .font(AgePonyTypography.footnote)
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
        Form {
            Section {
                Text("AgePony needs at least one identity to decrypt files sent to you.")
            } header: {
                Text("Add your first identity")
                    .font(AgePonyTypography.headline)
            }
            Section {
                Button("Generate a new identity", action: onGenerate)
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            }
            Section {
                Button("Import an existing identity", action: onImport)
            } footer: {
                Text("You can add more identities later in the Identities tab.")
            }
        }
        .textCase(nil)
        .navigationTitle("Setup")
        .navigationBarTitleDisplayMode(.inline)
    }
}
