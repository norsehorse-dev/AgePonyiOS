//
//  IdentityListView.swift
//  AgePony
//
//  Sectioned list of the user's identities, grouped by type. Tap to push
//  IdentityDetailView. Swipe to delete (with confirmation, since deleting
//  an identity makes any files encrypted to it un-decryptable on this
//  device).
//

import SwiftUI

struct IdentityListView: View {

    let vault: Vault

    @State private var pendingDelete: StoredIdentity?

    var body: some View {
        if vault.identities.isEmpty {
            VStack(spacing: 14) {
                Spacer()
                Image(systemName: "key.slash")
                    .font(.system(size: 44, weight: .light))
                    .foregroundStyle(.secondary)
                Text("No identities yet")
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
                        ForEach(section.items) { identity in
                            NavigationLink(value: identity) {
                                IdentityRow(identity: identity, isActive: identity.id == vault.activeIdentityID)
                            }
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) {
                                    pendingDelete = identity
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationDestination(for: StoredIdentity.self) { id in
                IdentityDetailView(vault: vault, identityID: id.id)
            }
            .confirmationDialog(
                pendingDelete.map { "Delete \"\($0.name)\"?" } ?? "",
                isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    if let id = pendingDelete?.id {
                        try? vault.deleteIdentity(id: id)
                    }
                    pendingDelete = nil
                }
                Button("Cancel", role: .cancel) { pendingDelete = nil }
            } message: {
                Text("Files encrypted to this identity will no longer be decryptable on this device.")
            }
        }
    }

    private var groupedSections: [(title: String, items: [StoredIdentity])] {
        let groups = Dictionary(grouping: vault.identities, by: { $0.type })
        let order: [(StoredIdentityType, String)] = [
            (.x25519,    "age X25519"),
            (.sshEd25519, "SSH Ed25519"),
            (.sshRSA,    "SSH RSA"),
            (.secureEnclaveP256, "Secure Enclave (P-256)"),
            (.skEd25519, "Security Key (Ed25519)"),
            (.skEcdsaP256, "Security Key (P-256)")
        ]
        return order.compactMap { (type, title) in
            guard let items = groups[type], !items.isEmpty else { return nil }
            return (title, items.sorted { $0.createdAt < $1.createdAt })
        }
    }
}

// MARK: - Row

private struct IdentityRow: View {
    let identity: StoredIdentity
    let isActive: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: iconName)
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(AgePonyColors.tealCore)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(identity.name)
                        .font(AgePonyTypography.bodyEmph)
                    if identity.type == .postQuantum {
                        PostQuantumBadge(compact: true)
                    }
                    if isActive {
                        Text("ACTIVE")
                            .font(.system(size: 9, weight: .semibold, design: .default))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(
                                Capsule().fill(AgePonyColors.tealCore)
                            )
                    }
                }
                Text(shortFingerprint)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(.vertical, 4)
    }

    private var iconName: String {
        switch identity.type {
        case .x25519:    return "key.fill"
        case .sshEd25519: return "lock.shield"
        case .sshRSA:    return "lock.shield"
        case .secureEnclaveP256: return "cpu"
        case .skEd25519, .skEcdsaP256: return "key.radiowaves.forward"
        case .postQuantum: return "atom"
        }
    }

    private var shortFingerprint: String {
        identity.publicDisplayString()
    }
}
