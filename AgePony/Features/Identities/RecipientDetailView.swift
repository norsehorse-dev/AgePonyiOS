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
                        LabeledContent("Name", value: recipient.name)
                        LabeledContent("Type", value: typeLabel(recipient.type))
                        LabeledContent("Source", value: sourceLabel(recipient.source))
                        if let meta = recipient.sourceMetadata, !meta.isEmpty {
                            LabeledContent("Origin") {
                                Text(meta)
                                    .font(AgePonyTypography.monoSmall)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                        LabeledContent("Added") {
                            Text(recipient.createdAt, style: .date)
                        }
                    }

                    Section {
                        AgePonyKeyBlock(
                            label: "Public key",
                            value: recipient.publicDisplayString(),
                            showsQR: true
                        )
                        if let comment = recipient.sshComment, !comment.isEmpty {
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text("Comment")
                                    .font(AgePonyTypography.footnote)
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
                        Text("Removing the recipient doesn't affect files you've already encrypted to them. Anyone holding the matching private key can still decrypt those.")
                    }
                }
                .textCase(nil)
            } else {
                ContentUnavailableView(
                    "Recipient not found",
                    systemImage: "questionmark.diamond"
                )
            }
        }
        .navigationTitle(recipient?.name ?? String(localized: "Recipient"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            // A text button in the bar, not a pencil inside the row (5.1.0, U4).
            if let recipient {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Rename") {
                        renameDraft = recipient.name
                        renaming = true
                    }
                }
            }
        }
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
            "Delete \"\(recipient?.name ?? String(localized: "this recipient"))\"?",
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
        try? vault.renameRecipient(id: existing.id, to: newName)
    }

    private func typeLabel(_ t: StoredRecipientType) -> String {
        t.sectionTitle
    }

    private func sourceLabel(_ s: StoredRecipientSource) -> String {
        switch s {
        case .pasteAge:          return String(localized: "Pasted age string")
        case .pasteSSH:          return String(localized: "Pasted SSH key")
        case .qrScan:            return String(localized: "QR scan")
        case .github:            return String(localized: "GitHub fetch")
        case .contacts:          return String(localized: "Contacts")
        case .derivedFromIdentity: return String(localized: "Derived from your identity")
        }
    }
}
