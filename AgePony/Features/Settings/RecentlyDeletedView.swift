//
//  RecentlyDeletedView.swift
//  AgePony
//
//  The recycle bin (4.0.0). Lists soft-deleted identities and recipients so an
//  accidental delete can be undone. Deleting an identity destroys a private key,
//  so this window matters: restore brings it back intact, or remove it for good.
//  Entries age out after `Vault.trashRetentionDays`.
//

import SwiftUI

struct RecentlyDeletedView: View {

    let vault: Vault

    @State private var confirmEmpty = false
    @State private var pendingPurge: PurgeTarget?

    struct PurgeTarget: Identifiable {
        let id = UUID()
        let targetID: UUID
        let name: String
        let isIdentity: Bool
    }

    private var isEmpty: Bool {
        vault.trashedIdentities.isEmpty && vault.trashedRecipients.isEmpty
    }

    var body: some View {
        Group {
            if isEmpty {
                ContentUnavailableView(
                    "Nothing recently deleted",
                    systemImage: "trash",
                    description: Text("Deleted identities and recipients wait here for \(Vault.trashRetentionDays) days before they're removed for good.")
                )
            } else {
                List {
                    if !vault.trashedIdentities.isEmpty {
                        Section("Identities") {
                            ForEach(vault.trashedIdentities) { t in
                                TrashRow(
                                    seed: t.identity.publicKeyMaterial.base64EncodedString(),
                                    name: t.identity.name,
                                    deletedAt: t.deletedAt,
                                    onRestore: { try? vault.restoreIdentity(id: t.identity.id) },
                                    onPurge: { pendingPurge = PurgeTarget(targetID: t.identity.id, name: t.identity.name, isIdentity: true) }
                                )
                            }
                        }
                    }
                    if !vault.trashedRecipients.isEmpty {
                        Section("Recipients") {
                            ForEach(vault.trashedRecipients) { t in
                                TrashRow(
                                    seed: t.recipient.publicKeyMaterial.base64EncodedString(),
                                    name: t.recipient.name,
                                    deletedAt: t.deletedAt,
                                    onRestore: { try? vault.restoreRecipient(id: t.recipient.id) },
                                    onPurge: { pendingPurge = PurgeTarget(targetID: t.recipient.id, name: t.recipient.name, isIdentity: false) }
                                )
                            }
                        }
                    }
                    Section {
                        Button("Empty recycle bin", role: .destructive) { confirmEmpty = true }
                    } footer: {
                        Text("Restoring an identity brings its private key back intact. A permanent delete cannot be undone.")
                    }
                }
                .textCase(nil)
            }
        }
        .navigationTitle("Recently deleted")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Empty recycle bin?", isPresented: $confirmEmpty, titleVisibility: .visible) {
            Button("Empty", role: .destructive) { try? vault.emptyTrash() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This permanently removes everything here. Any deleted identity's private key is gone for good.")
        }
        .confirmationDialog(
            pendingPurge.map { String(localized: "Delete \"\($0.name)\" permanently?") } ?? "",
            isPresented: Binding(get: { pendingPurge != nil }, set: { if !$0 { pendingPurge = nil } }),
            titleVisibility: .visible,
            presenting: pendingPurge
        ) { target in
            Button("Delete permanently", role: .destructive) {
                if target.isIdentity {
                    try? vault.purgeIdentity(id: target.targetID)
                } else {
                    try? vault.purgeRecipient(id: target.targetID)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("This cannot be undone.")
        }
    }
}

// MARK: - Row

private struct TrashRow: View {
    let seed: String
    let name: String
    let deletedAt: Date
    let onRestore: () -> Void
    let onPurge: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            KeyAvatarView(seed: seed, name: name, size: 36)
            VStack(alignment: .leading, spacing: 4) {
                Text(name).font(AgePonyTypography.body)
                Text(deletedText)
                    .font(AgePonyTypography.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            // Both actions visible in the row, each a full-height target
            // (5.1.0, U4). Delete used to be swipe-only.
            Button("Restore", action: onRestore)
                .buttonStyle(.borderless)
                .frame(minHeight: 44)
            Button("Delete", role: .destructive, action: onPurge)
                .buttonStyle(.borderless)
                .frame(minHeight: 44)
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive, action: onPurge) {
                Label("Delete", systemImage: "trash")
            }
        }
    }

    private var deletedText: String {
        let days = Int(Date().timeIntervalSince(deletedAt) / 86_400)
        let remaining = max(0, Vault.trashRetentionDays - days)
        if days <= 0 {
            return String(AttributedString(localized: "Deleted today · ^[\(remaining) day](inflect: true) left").characters)
        }
        return String(AttributedString(localized: "Deleted ^[\(days) day](inflect: true) ago · ^[\(remaining) day](inflect: true) left").characters)
    }
}
