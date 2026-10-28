//
//  RecipientListView.swift
//  AgePony
//
//  Sectioned list of stored recipients, grouped by type. Mirrors
//  IdentityListView's layout. Swipe to delete (no confirmation —
//  recipients are just public keys, the user can always re-add).
//

import SwiftUI

struct RecipientListView: View {

    let vault: Vault
    /// Opens Add recipient (the empty state's action).
    var onAdd: () -> Void = {}

    var body: some View {
        if vault.recipients.isEmpty {
            ContentUnavailableView {
                Label("No recipients", systemImage: "person.2")
            } description: {
                Text("A recipient is someone else's public key. Add theirs to encrypt files only they can open. Paste it, scan their QR code or fetch it from GitHub.")
            } actions: {
                Button("Add recipient", action: onAdd)
            }
        } else {
            List {
                ForEach(groupedSections, id: \.title) { section in
                    Section(section.title) {
                        ForEach(section.items) { recipient in
                            NavigationLink(value: recipient) {
                                RecipientRow(recipient: recipient)
                            }
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) {
                                    try? vault.deleteRecipient(id: recipient.id)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                }
            }
            .textCase(nil)
            .listStyle(.insetGrouped)
            .navigationDestination(for: StoredRecipient.self) { r in
                RecipientDetailView(vault: vault, recipientID: r.id)
            }
        }
    }

    /// See `IdentityListView.groupedSections` -- same bug, same fix. A saved
    /// post-quantum recipient was invisible here too.
    private var groupedSections: [(title: String, items: [StoredRecipient])] {
        let groups = Dictionary(grouping: vault.recipients, by: { $0.type })
        return StoredRecipientType.allCases.compactMap { type in
            guard let items = groups[type], !items.isEmpty else { return nil }
            return (type.sectionTitle, items.sorted { $0.createdAt < $1.createdAt })
        }
    }
}

// MARK: - Row

private struct RecipientRow: View {
    let recipient: StoredRecipient

    var body: some View {
        HStack(spacing: 12) {
            KeyAvatarView(seed: recipient.publicKeyMaterial.base64EncodedString(),
                          name: recipient.name, size: 36)

            VStack(alignment: .leading, spacing: 4) {
                Text(recipient.name)
                    .font(AgePonyTypography.body)
                HStack(spacing: 8) {
                    if recipient.type == .postQuantum || recipient.type == .tagPQ {
                        PostQuantumBadge(compact: true)
                    }
                    Text(sourceLabel)
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.secondary)
                    Text(shortPublic)
                        .font(AgePonyTypography.monoCaption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var sourceLabel: String {
        switch recipient.source {
        case .pasteAge:          return String(localized: "Pasted")
        case .pasteSSH:          return String(localized: "Pasted")
        case .qrScan:            return String(localized: "QR code")
        case .github:            return String(localized: "GitHub")
        case .contacts:          return String(localized: "Contacts")
        case .derivedFromIdentity: return String(localized: "Your identity")
        }
    }

    private var shortPublic: String {
        recipient.publicDisplayString()
    }
}
