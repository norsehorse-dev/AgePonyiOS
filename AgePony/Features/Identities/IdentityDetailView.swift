//
//  IdentityDetailView.swift
//  AgePony
//
//  Detail screen for a single identity. Shows the public key block, a
//  reveal-private-key affordance gated by a biometric prompt, and the
//  ability to rename, set as active, or delete.
//

import SwiftUI

struct IdentityDetailView: View {

    let vault: Vault
    let identityID: UUID

    @State private var renaming: Bool = false
    @State private var renameDraft: String = ""
    @State private var privateRevealed: Bool = false
    @State private var revealError: String?
    @State private var pendingDelete: Bool = false

    @Environment(\.dismiss) private var dismiss

    private var identity: StoredIdentity? {
        vault.identities.first(where: { $0.id == identityID })
    }

    var body: some View {
        Group {
            if let identity {
                Form {
                    Section {
                        HStack {
                            Text("Name")
                            Spacer()
                            Text(identity.name).foregroundStyle(.secondary)
                            Button {
                                renameDraft = identity.name
                                renaming = true
                            } label: {
                                Image(systemName: "pencil")
                            }
                        }
                        HStack {
                            Text("Type")
                            Spacer()
                            Text(typeLabel(identity.type))
                                .foregroundStyle(.secondary)
                        }
                        HStack {
                            Text("Created")
                            Spacer()
                            Text(identity.createdAt, style: .date)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Section {
                        AgePonyKeyBlock(
                            label: "Public",
                            value: identity.publicDisplayString()
                        )
                    } footer: {
                        Text("Safe to share. Anyone with this string can encrypt to you.")
                    }

                    Section {
                        if privateRevealed {
                            AgePonyKeyBlock(
                                label: "Private",
                                value: identity.privateDisplayString(),
                                isSensitive: true
                            )
                            Button("Hide private key") {
                                privateRevealed = false
                            }
                            .foregroundStyle(AgePonyColors.tealCore)
                        } else {
                            Button {
                                revealPrivate()
                            } label: {
                                Label("Reveal private key", systemImage: "eye")
                                    .font(AgePonyTypography.body)
                            }
                            .foregroundStyle(AgePonyColors.tealCore)
                        }
                    } footer: {
                        Text("Revealing the private key requires Face ID, Touch ID, or your device passcode.")
                    }

                    if vault.activeIdentityID != identity.id {
                        Section {
                            Button("Set as active identity") {
                                vault.activeIdentityID = identity.id
                            }
                            .foregroundStyle(AgePonyColors.tealCore)
                        } footer: {
                            Text("The active identity is used as your default \"encrypt-to-self\" recipient.")
                        }
                    }

                    Section {
                        Button(role: .destructive) {
                            pendingDelete = true
                        } label: {
                            Label("Delete identity", systemImage: "trash")
                        }
                    } footer: {
                        Text("Files encrypted to this identity will no longer be decryptable on this device.")
                    }
                }
            } else {
                ContentUnavailableView(
                    "Identity not found",
                    systemImage: "questionmark.diamond"
                )
            }
        }
        .navigationTitle(identity?.name ?? "Identity")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Rename identity", isPresented: $renaming) {
            TextField("Name", text: $renameDraft)
            Button("Cancel", role: .cancel) {}
            Button("Save") {
                let trimmed = renameDraft.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty else { return }
                try? vault.renameIdentity(id: identityID, to: trimmed)
            }
        }
        .alert(
            "Couldn't reveal private key",
            isPresented: Binding(get: { revealError != nil }, set: { if !$0 { revealError = nil } })
        ) {
            Button("OK", role: .cancel) { revealError = nil }
        } message: {
            Text(revealError ?? "")
        }
        .confirmationDialog(
            "Delete \"\(identity?.name ?? "this identity")\"?",
            isPresented: $pendingDelete,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                try? vault.deleteIdentity(id: identityID)
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private func revealPrivate() {
        Task {
            do {
                try await BiometricGate.authenticate(reason: "Reveal the private key for this identity.")
                privateRevealed = true
            } catch BiometricGateError.userCancelled {
                // Silent — user backed out.
            } catch {
                revealError = error.localizedDescription
            }
        }
    }

    private func typeLabel(_ t: StoredIdentityType) -> String {
        switch t {
        case .x25519:    return "age X25519"
        case .sshEd25519: return "SSH Ed25519"
        case .sshRSA:    return "SSH RSA"
        case .secureEnclaveP256: return "Secure Enclave (P-256)"
        case .skEd25519: return "Security Key (Ed25519)"
        case .skEcdsaP256: return "Security Key (P-256)"
        }
    }
}
