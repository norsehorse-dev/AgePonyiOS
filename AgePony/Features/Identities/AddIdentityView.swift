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
            Form {
                Section {
                    Button { stage = .generate } label: {
                        Label("Generate a new identity", systemImage: "key")
                    }
                    .foregroundStyle(.primary)
                    Button { stage = .importExisting } label: {
                        Label("Import an existing identity", systemImage: "square.and.arrow.down")
                    }
                    .foregroundStyle(.primary)
                } footer: {
                    Text("Generate a new age identity, or import an age key, an SSH key or a YubiKey identity you already use.")
                }
            }
            .textCase(nil)
            .navigationTitle("Add identity")
            .navigationBarTitleDisplayMode(.inline)

        case .generate:
            GenerateIdentityView(vault: vault, onDone: onDone)

        case .importExisting:
            ImportIdentityView(vault: vault, onDone: onDone)
        }
    }
}
