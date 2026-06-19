//
//  AddIdentityView.swift
//  AgePony
//
//  Choice screen used when the user taps "+" on the Identities list.
//  Reuses GenerateIdentityView and ImportIdentityView from the onboarding
//  flow — same code paths, just presented as a sheet instead of a
//  full-screen onboarding stage.
//

import SwiftUI

struct AddIdentityView: View {

    let vault: Vault
    let onDone: () -> Void

    @State private var stage: Stage = .choice

    enum Stage {
        case choice
        case generate
        case importExisting
    }

    var body: some View {
        switch stage {
        case .choice:
            VStack(spacing: 24) {
                VStack(spacing: 8) {
                    Text("Add identity")
                        .font(AgePonyTypography.title)
                    Text("Generate a fresh age identity, or import an existing age or SSH key.")
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                .padding(.top, 24)

                Spacer()

                VStack(spacing: 14) {
                    Button("Generate new identity") { stage = .generate }
                        .buttonStyle(.agePonyPrimary)
                    Button("Import existing identity") { stage = .importExisting }
                        .buttonStyle(.agePonySecondary)
                }
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
            }
            .navigationTitle("Add identity")
            .navigationBarTitleDisplayMode(.inline)

        case .generate:
            GenerateIdentityView(vault: vault, onDone: onDone)

        case .importExisting:
            ImportIdentityView(vault: vault, onDone: onDone)
        }
    }
}
