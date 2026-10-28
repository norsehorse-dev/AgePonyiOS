//
//  IdentityDetailView.swift
//  AgePony
//
//  Detail screen for a single identity. Shows the public key block, a
//  reveal-private-key affordance gated by a biometric prompt, and the
//  ability to rename, set as active, or delete.
//

import SwiftUI
import AgePonyCore

struct IdentityDetailView: View {

    let vault: Vault
    let identityID: UUID

    @State private var renaming: Bool = false
    @State private var renameDraft: String = ""
    @State private var privateRevealed: Bool = false
    @State private var revealError: String?
    /// The in-app prompt, with the app password when Face ID only can't use Face ID (E6).
    @State private var ownerCheck = OwnerCheck()
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
                        LabeledContent("Name", value: identity.name)
                        LabeledContent("Type", value: typeLabel(identity.type))
                        LabeledContent("Created") {
                            Text(identity.createdAt, style: .date)
                        }
                    }

                    Section {
                        AgePonyKeyBlock(
                            label: "Public",
                            value: identity.publicDisplayString(),
                            showsQR: true
                        )
                    } footer: {
                        Text("Safe to share. Anyone with this string can encrypt to you.")
                    }

                    if identity.type == .yubikey {
                        Section {
                            AgePonyKeyBlock(
                                label: "age-plugin-yubikey identity",
                                value: identity.privateDisplayString()
                            )
                        } footer: {
                            Text("Not a secret: it only points at the key on your YubiKey (serial \(identity.yubiKeyStub.map { String($0.serial) } ?? "?")). Put it in an identity file to use the same key with age and age-plugin-yubikey on a computer. Decrypting here takes a tap of the YubiKey, and its PIN when the key asks for it.")
                        }
                    } else if identity.isHardwareDecryptionKey {
                        Section {
                            if identity.type == .secureEnclaveTagPQ && !identity.mlkemInSecureEnclave {
                                // 5.0.1 layout, or made below iOS 26 (5.1.0 RC3).
                                Label("The P-256 half of this key is inside this iPhone's Secure Enclave and the ML-KEM half is in the encrypted vault. A file needs both. Neither can be shown, exported, transferred or backed up, and the key is gone if this iPhone is erased or replaced.", systemImage: "cpu")
                                    .font(AgePonyTypography.subheadline)
                            } else if identity.type == .secureEnclaveTagPQ {
                                Label("Both halves of this key, P-256 and ML-KEM, are inside this iPhone's Secure Enclave. It can't be shown, exported, transferred or backed up, and it's gone if this iPhone is erased or replaced.", systemImage: "cpu")
                                    .font(AgePonyTypography.subheadline)
                            } else {
                                Label("The private key is inside this iPhone's Secure Enclave. It can't be shown, exported, transferred or backed up, and it's gone if this iPhone is erased or replaced.", systemImage: "cpu")
                                    .font(AgePonyTypography.subheadline)
                            }
                        }
                    } else {
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
                        } else {
                            Button {
                                revealPrivate()
                            } label: {
                                Label("Reveal private key", systemImage: "eye")
                            }
                        }
                        if let revealError {
                            StatusText(revealError)
                        }
                    } footer: {
                        Text("Revealing the private key requires Face ID, Touch ID, or your device passcode.")
                    }
                    }

                    if KeyPortability.isPaperBackable(identity) {
                        Section {
                            NavigationLink {
                                PaperBackupView(vault: vault, identity: identity)
                            } label: {
                                Label("Paper backup", systemImage: "printer")
                            }
                        } footer: {
                            Text("A page with this key as a QR code and text, protected with a passphrase, to keep somewhere safe.")
                        }
                    }

                    if vault.activeIdentityID != identity.id {
                        Section {
                            Button("Set as active identity") {
                                vault.activeIdentityID = identity.id
                            }
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
                .textCase(nil)
            } else {
                ContentUnavailableView(
                    "Identity not found",
                    systemImage: "questionmark.diamond"
                )
            }
        }
        .ownerCheck(ownerCheck, vault: vault)
        .navigationTitle(identity?.name ?? String(localized: "Identity"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            // A text button in the bar, not a pencil inside the row (5.1.0, U4).
            if let identity {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Rename") {
                        renameDraft = identity.name
                        renaming = true
                    }
                }
            }
        }
        .alert("Rename identity", isPresented: $renaming) {
            TextField("Name", text: $renameDraft)
            Button("Cancel", role: .cancel) {}
            Button("Save") {
                let trimmed = renameDraft.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty else { return }
                try? vault.renameIdentity(id: identityID, to: trimmed)
            }
        }
        .confirmationDialog(
            "Delete \"\(identity?.name ?? String(localized: "this identity"))\"?",
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
        revealError = nil
        Task {
            do {
                try await ownerCheck.authenticate(vault, reason: String(localized: "Reveal the private key for this identity."))
                privateRevealed = true
            } catch BiometricGateError.userCancelled {
                // Silent: the user backed out.
            } catch {
                revealError = UserMessage.text(for: error, fallback: String(localized: "Couldn't confirm it's you, so the private key stays hidden."))
            }
        }
    }

    private func typeLabel(_ t: StoredIdentityType) -> String {
        t.sectionTitle
    }
}
