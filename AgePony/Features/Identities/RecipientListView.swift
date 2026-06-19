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

    var body: some View {
        if vault.recipients.isEmpty {
            VStack(spacing: 14) {
                Spacer()
                Image(systemName: "person.2.crop.square.stack")
                    .font(.system(size: 44, weight: .light))
                    .foregroundStyle(.secondary)
                Text("No recipients yet")
                    .font(AgePonyTypography.headline)
                Text("Tap + to add one.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .frame(maxWidth: .infinity)
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
            .listStyle(.insetGrouped)
            .navigationDestination(for: StoredRecipient.self) { r in
                RecipientDetailView(vault: vault, recipientID: r.id)
            }
        }
    }

    private var groupedSections: [(title: String, items: [StoredRecipient])] {
        let groups = Dictionary(grouping: vault.recipients, by: { $0.type })
        let order: [(StoredRecipientType, String)] = [
            (.x25519,    "age X25519"),
            (.sshEd25519, "SSH Ed25519"),
            (.sshRSA,    "SSH RSA")
        ]
        return order.compactMap { (type, title) in
            guard let items = groups[type], !items.isEmpty else { return nil }
            return (title, items.sorted { $0.createdAt < $1.createdAt })
        }
    }
}

// MARK: - Row

private struct RecipientRow: View {
    let recipient: StoredRecipient

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: iconName)
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(AgePonyColors.tealCore)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(recipient.name)
                    .font(AgePonyTypography.bodyEmph)
                HStack(spacing: 6) {
                    Text(sourceLabel)
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(AgePonyColors.tealCore)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(
                            Capsule().fill(AgePonyColors.tealCore.opacity(0.12))
                        )
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

    private var iconName: String {
        switch recipient.type {
        case .x25519:    return "person.crop.circle.fill"
        case .sshEd25519: return "person.crop.circle.badge.checkmark"
        case .sshRSA:    return "person.crop.circle.badge.checkmark"
        }
    }

    private var sourceLabel: String {
        switch recipient.source {
        case .pasteAge:          return "PASTE"
        case .pasteSSH:          return "PASTE"
        case .qrScan:            return "QR"
        case .github:            return "GITHUB"
        case .contacts:          return "CONTACTS"
        case .derivedFromIdentity: return "SELF"
        }
    }

    private var shortPublic: String {
        recipient.publicDisplayString()
    }
}
