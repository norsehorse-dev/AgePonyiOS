//
//  SignersView.swift
//  AgePony
//
//  Manages the trusted-signers list. Signers can be added by pasting a public
//  key, importing an OpenSSH allowed_signers file, or promoting a saved
//  recipient. The whole list exports back to allowed_signers so it round-trips
//  to the command line (`ssh-keygen -Y verify -f allowed_signers`).
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct SignersView: View {

    let vault: Vault

    @State private var showAddPaste: Bool = false
    @State private var showRecipientPicker: Bool = false
    @State private var showImporter: Bool = false
    @State private var pendingDelete: StoredSigner?
    @State private var importSummary: String?
    @State private var exportURL: URL?

    var body: some View {
        Group {
            if vault.signers.isEmpty {
                emptyState
            } else {
                list
            }
        }
        .navigationTitle("Trusted signers")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button {
                        showAddPaste = true
                    } label: {
                        Label("Paste a public key", systemImage: "doc.on.clipboard")
                    }
                    Button {
                        showImporter = true
                    } label: {
                        Label("Import allowed_signers", systemImage: "square.and.arrow.down")
                    }
                    Button {
                        showRecipientPicker = true
                    } label: {
                        Label("From a recipient", systemImage: "person.crop.circle")
                    }
                    .disabled(eligibleRecipients.isEmpty)
                } label: {
                    Image(systemName: "plus")
                }
            }
        }
        .sheet(isPresented: $showAddPaste) {
            NavigationStack {
                AddSignerView(vault: vault, mode: .paste, source: .pasteKey) {}
            }
        }
        .sheet(isPresented: $showRecipientPicker) {
            NavigationStack {
                recipientPicker
            }
        }
        .fileImporter(
            isPresented: $showImporter,
            allowedContentTypes: [.data, .item, .text, .plainText],
            allowsMultipleSelection: false
        ) { result in
            handleAllowedSignersImport(result)
        }
        .onAppear { regenerateExport() }
        .onChange(of: vault.signers) { _, _ in regenerateExport() }
        .confirmationDialog(
            pendingDelete.map { "Remove \"\($0.name)\"?" } ?? "",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let id = pendingDelete?.id { try? vault.deleteSigner(id: id) }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        } message: {
            Text("Their signatures will show as \"valid, unknown signer\" until you add them again.")
        }
        .alert(
            "Import complete",
            isPresented: Binding(get: { importSummary != nil }, set: { if !$0 { importSummary = nil } })
        ) {
            Button("OK", role: .cancel) { importSummary = nil }
        } message: {
            Text(importSummary ?? "")
        }
    }

    // MARK: - List / empty

    private var list: some View {
        List {
            Section {
                ForEach(vault.signers) { signer in
                    SignerRow(signer: signer)
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                pendingDelete = signer
                            } label: {
                                Label("Remove", systemImage: "trash")
                            }
                        }
                }
            } footer: {
                Text("These keys are trusted to sign. When a file's signature matches one, it verifies as signed by that name.")
            }

            if let exportURL {
                Section {
                    ShareLink(item: exportURL) {
                        Label("Export allowed_signers", systemImage: "square.and.arrow.up")
                    }
                } footer: {
                    Text("Share the list as an OpenSSH allowed_signers file for use with ssh-keygen -Y verify.")
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: "person.badge.shield.checkmark")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.secondary)
            Text("No trusted signers yet")
                .font(AgePonyTypography.headline)
            Text("Add a signer's public key so their signatures verify with a name. Tap + to paste a key, import an allowed_signers file, or promote a recipient.")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Recipient picker

    private var eligibleRecipients: [StoredRecipient] {
        vault.recipients.filter { $0.type == .sshEd25519 || $0.type == .sshRSA }
    }

    private var recipientPicker: some View {
        Group {
            if eligibleRecipients.isEmpty {
                Text("No SSH recipients to promote.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } else {
                List(eligibleRecipients) { recipient in
                    Button {
                        promote(recipient)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(recipient.name)
                                .font(AgePonyTypography.bodyEmph)
                                .foregroundStyle(.primary)
                            Text(recipient.type == .sshEd25519 ? "ssh-ed25519" : "ssh-rsa")
                                .font(AgePonyTypography.monoCaption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .navigationTitle("From a recipient")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { showRecipientPicker = false }
            }
        }
    }

    private func promote(_ recipient: StoredRecipient) {
        let keyType = recipient.type == .sshEd25519 ? "ssh-ed25519" : "ssh-rsa"
        let signer = StoredSigner(
            name: recipient.name,
            keyType: keyType,
            publicKeyWire: recipient.publicKeyMaterial,
            comment: recipient.sshComment,
            source: .fromRecipient
        )
        try? vault.addSigner(signer)
        showRecipientPicker = false
    }

    // MARK: - allowed_signers import / export

    private func handleAllowedSignersImport(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard let url = urls.first else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            guard let text = String(data: data, encoding: .utf8) else {
                importSummary = "That file isn't readable as text."
                return
            }
            let parsed = AllowedSigners.parse(text)
            var added = 0
            for entry in parsed {
                if let signer = StoredSigner.from(allowedSigner: entry, source: .importAllowedSigners) {
                    try? vault.addSigner(signer)
                    added += 1
                }
            }
            importSummary = added == 0
                ? "No signers found in that file."
                : "Imported \(added) signer\(added == 1 ? "" : "s")."
        } catch {
            importSummary = "Couldn't import: \(error.localizedDescription)"
        }
    }

    private func regenerateExport() {
        guard !vault.signers.isEmpty else { exportURL = nil; return }
        let text = AllowedSigners.serialize(vault.signers.map { $0.toAllowedSigner() })
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgePonySigners-\(UUID().uuidString.prefix(8))", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let url = dir.appendingPathComponent("allowed_signers")
            try Data(text.utf8).write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
            exportURL = url
        } catch {
            exportURL = nil
        }
    }
}

// MARK: - Row

private struct SignerRow: View {
    let signer: StoredSigner

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "checkmark.seal")
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(AgePonyColors.tealCore)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(signer.name)
                    .font(AgePonyTypography.bodyEmph)
                Text("\(signer.keyType)  ·  \(signer.fingerprint)")
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(.vertical, 4)
    }
}
