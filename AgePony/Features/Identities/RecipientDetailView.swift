//
//  RecipientDetailView.swift
//  AgePony
//
//  Detail view for a single recipient. Shows the full public key in a
//  KeyBlock, lets the user rename, and offers delete. No private material
//  to hide here (recipients are public keys); no biometric prompt needed.
//

import SwiftUI

struct RecipientDetailView: View {

    let vault: Vault
    let recipientID: UUID

    @State private var renaming: Bool = false
    @State private var renameDraft: String = ""
    @State private var pendingDelete: Bool = false

    @Environment(\.dismiss) private var dismiss

    private var recipient: StoredRecipient? {
        vault.recipients.first(where: { $0.id == recipientID })
    }

    var body: some View {
        Group {
            if let recipient {
                Form {
                    Section {
                        HStack {
                            Text("Name")
                            Spacer()
                            Text(recipient.name).foregroundStyle(.secondary)
                            Button {
                                renameDraft = recipient.name
                                renaming = true
                            } label: {
                                Image(systemName: "pencil")
                            }
                        }
                        HStack {
                            Text("Type")
                            Spacer()
                            Text(typeLabel(recipient.type))
                                .foregroundStyle(.secondary)
                        }
                        HStack {
                            Text("Source")
                            Spacer()
                            Text(sourceLabel(recipient.source))
                                .foregroundStyle(.secondary)
                        }
                        if let meta = recipient.sourceMetadata, !meta.isEmpty {
                            HStack {
                                Text("Origin")
                                Spacer()
                                Text(meta)
                                    .font(AgePonyTypography.monoCaption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                        HStack {
                            Text("Added")
                            Spacer()
                            Text(recipient.createdAt, style: .date)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Section {
                        AgePonyKeyBlock(
                            label: "Public key",
                            value: recipient.publicDisplayString()
                        )
                        if let comment = recipient.sshComment, !comment.isEmpty {
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                Text("Comment")
                                    .font(AgePonyTypography.caption)
                                    .foregroundStyle(.secondary)
                                Text(comment)
                                    .font(AgePonyTypography.monoCaption)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                    } footer: {
                        Text("Anyone with this public key can be sent encrypted files. Only they (with the matching private key) can decrypt.")
                    }

                    Section {
                        Button(role: .destructive) {
                            pendingDelete = true
                        } label: {
                            Label("Delete recipient", systemImage: "trash")
                        }
                    } footer: {
                        Text("Removing the recipient doesn't affect any files you've already encrypted to them — those remain decryptable by anyone holding the matching private key.")
                    }
                }
            } else {
                ContentUnavailableView(
                    "Recipient not found",
                    systemImage: "questionmark.diamond"
                )
            }
        }
        .navigationTitle(recipient?.name ?? "Recipient")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Rename recipient", isPresented: $renaming) {
            TextField("Name", text: $renameDraft)
            Button("Cancel", role: .cancel) {}
            Button("Save") {
                let trimmed = renameDraft.trimmingCharacters(in: .whitespaces)
                guard !trimmed.isEmpty else { return }
                renameRecipient(to: trimmed)
            }
        }
        .confirmationDialog(
            "Delete \"\(recipient?.name ?? "this recipient")\"?",
            isPresented: $pendingDelete,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                try? vault.deleteRecipient(id: recipientID)
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    /// In-place rename. Reads the current recipient, mutates the name,
    /// and writes back through Vault's CRUD. The 1c Vault doesn't have a
    /// dedicated renameRecipient(id:to:); we delete + re-add. Order
    /// matters because StoredRecipient.id is preserved, so the row stays
    /// stable for any view bound to the recipient by id.
    private func renameRecipient(to newName: String) {
        guard let existing = recipient else { return }
        // Build a copy with the new name but the same id / createdAt /
        // everything else. Then replace.
        let renamed = StoredRecipient(
            id: existing.id,
            name: newName,
            type: existing.type,
            publicKeyMaterial: existing.publicKeyMaterial,
            sshComment: existing.sshComment,
            source: existing.source,
            sourceMetadata: existing.sourceMetadata,
            createdAt: existing.createdAt
        )
        try? vault.deleteRecipient(id: existing.id)
        _ = try? vault.addRecipient(renamed)
    }

    private func typeLabel(_ t: StoredRecipientType) -> String {
        switch t {
        case .x25519:    return "age X25519"
        case .sshEd25519: return "SSH Ed25519"
        case .sshRSA:    return "SSH RSA"
        }
    }

    private func sourceLabel(_ s: StoredRecipientSource) -> String {
        switch s {
        case .pasteAge:          return "Pasted age string"
        case .pasteSSH:          return "Pasted SSH key"
        case .qrScan:            return "QR scan"
        case .github:            return "GitHub fetch"
        case .contacts:          return "Contacts"
        case .derivedFromIdentity: return "Derived from your identity"
        }
    }
}
