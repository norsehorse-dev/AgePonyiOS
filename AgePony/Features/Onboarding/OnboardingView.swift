//
//  OnboardingView.swift
//  AgePony
//
//  Shown on first launch when no vault exists on the device. Walks the user
//  through bootstrapping the vault and creating their first identity. Once
//  the identity is saved, calls back to RootView so the home screen can
//  take over.
//

import SwiftUI

struct OnboardingView: View {

    let vault: Vault
    let onComplete: () -> Void

    @State private var stage: Stage = .welcome
    @State private var bootstrapError: String?

    enum Stage {
        case welcome
        case choice
        case generate
        case importExisting
    }

    var body: some View {
        NavigationStack {
            switch stage {
            case .welcome:
                WelcomeStage(onContinue: bootstrapAndContinue)
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
        Task {
            do {
                try await vault.bootstrap()
                stage = .choice
            } catch {
                bootstrapError = error.localizedDescription
            }
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
