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
    /// Whether `importSummary` reports a failure, for the alert's title.
    @State private var importFailed: Bool = false
    @State private var exportURL: URL?
    @Environment(\.editMode) private var editMode

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
        .onChange(of: vault.signers.isEmpty) {
            // Deleting the last signer in Edit mode leaves nothing to edit.
            if vault.signers.isEmpty { editMode?.wrappedValue = .inactive }
        }
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                // Edit mode is the visible way to remove signers (5.1.0, U4);
                // swipe and the row's context menu do the same.
                if !vault.signers.isEmpty {
                    EditButton()
                }
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
                    Label("Add signer", systemImage: "plus")
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
            pendingDelete.map { String(localized: "Remove \"\($0.name)\"?") } ?? "",
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
            importFailed ? Text("Couldn't import") : Text("Import complete"),
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
                        .contextMenu {
                            Button(role: .destructive) {
                                pendingDelete = signer
                            } label: {
                                Label("Remove", systemImage: "trash")
                            }
                        }
                }
                .onDelete { offsets in
                    // Swipe or Edit mode: ask first, like the context menu.
                    if let index = offsets.first, vault.signers.indices.contains(index) {
                        pendingDelete = vault.signers[index]
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
        .textCase(nil)
        .listStyle(.insetGrouped)
    }

    /// The one empty-state pattern (5.1.0, U4): what a trusted signer is and how to add one.
    private var emptyState: some View {
        ContentUnavailableView {
            Label("No trusted signers", systemImage: "person.badge.shield.checkmark")
        } description: {
            Text("A trusted signer is someone's SSH public key you've chosen to trust. Signatures made with it verify with their name. Paste a key, import an allowed_signers file, or promote a recipient.")
        } actions: {
            Button("Paste a public key") { showAddPaste = true }
            Button("Import allowed_signers") { showImporter = true }
        }
    }

    // MARK: - Recipient picker

    private var eligibleRecipients: [StoredRecipient] {
        vault.recipients.filter { $0.type == .sshEd25519 || $0.type == .sshRSA }
    }

    private var recipientPicker: some View {
        Group {
            if eligibleRecipients.isEmpty {
                ContentUnavailableView {
                    Label("No SSH recipients", systemImage: "person.crop.circle")
                } description: {
                    Text("Only SSH Ed25519 and RSA recipients can sign. Add one under Recipients on the Identities tab first.")
                }
            } else {
                List(eligibleRecipients) { recipient in
                    Button {
                        promote(recipient)
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(recipient.name)
                                .font(AgePonyTypography.body)
                                .foregroundStyle(.primary)
                            Text(recipient.type.sectionTitle)
                                .font(AgePonyTypography.subheadline)
                                .foregroundStyle(.secondary)
                            // The Recipients list's short form, so two keys with one name differ.
                            Text(verbatim: recipient.publicDisplayString())
                                .font(AgePonyTypography.monoCaption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                }
                .textCase(nil)
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
                importFailed = true
                importSummary = String(localized: "That file isn't text. An allowed_signers file is plain text with one key per line.")
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
            if added == 0 {
                importFailed = true
                importSummary = String(localized: "No signers found in that file. Each line should hold a name, a key type and a public key.")
            } else {
                importFailed = false
                importSummary = String(AttributedString(localized: "Imported ^[\(added) signer](inflect: true).").characters)
            }
        } catch {
            importFailed = true
            importSummary = UserMessage.text(for: error, fallback: String(localized: "Couldn't read the allowed_signers file."))
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
                .font(AgePonyTypography.body)
                .foregroundStyle(.secondary)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                Text(signer.name)
                    .font(AgePonyTypography.body)
                Text(verbatim: "\(signer.keyType)  ·  \(signer.fingerprint)")
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(.vertical, 4)
    }
}
