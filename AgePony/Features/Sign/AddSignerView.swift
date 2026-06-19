//
//  AddSignerView.swift
//  AgePony
//
//  Adds a trusted signer. Two modes:
//    • paste     — the user pastes an `ssh-* BASE64 [comment]` public key line.
//    • prefilled — the key is already known (from a verification result or a
//                  saved recipient); the user just names it.
//

import SwiftUI
import AgePonyCore

struct AddSignerView: View {

    enum Mode: Equatable {
        case paste
        case prefilled(keyType: String, wire: Data, suggestedName: String)
    }

    let vault: Vault
    let mode: Mode
    let source: StoredSigner.Source
    let onAdded: () -> Void

    @State private var name: String = ""
    @State private var pastedLine: String = ""
    @State private var errorMessage: String?

    @Environment(\.dismiss) private var dismiss

    init(vault: Vault, mode: Mode, source: StoredSigner.Source, onAdded: @escaping () -> Void) {
        self.vault = vault
        self.mode = mode
        self.source = source
        self.onAdded = onAdded
        if case .prefilled(_, _, let suggested) = mode {
            _name = State(initialValue: suggested)
        }
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $name)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            } header: {
                Text("Name")
            } footer: {
                Text("A label for this signer, like \"alice@example.com\". Shown when their signatures verify.")
            }

            switch mode {
            case .paste:
                Section {
                    TextField("ssh-ed25519 AAAA… comment", text: $pastedLine, axis: .vertical)
                        .lineLimit(3...6)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(AgePonyTypography.monoCaption)
                } header: {
                    Text("Public key")
                } footer: {
                    Text("Paste the signer's SSH public key (the same line as their .pub file).")
                }
            case .prefilled(let keyType, let wire, _):
                Section {
                    HStack {
                        Text("Type")
                        Spacer()
                        Text(keyType)
                            .font(AgePonyTypography.monoCaption)
                            .foregroundStyle(.secondary)
                    }
                    HStack {
                        Text("Fingerprint")
                        Spacer()
                        Text(FileVerifier.sshFingerprint(wireBlob: wire))
                            .font(AgePonyTypography.monoCaption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                } header: {
                    Text("Public key")
                }
            }

            Section {
                Button(action: save) {
                    Text("Add signer")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(!canSave)
            }
        }
        .navigationTitle("Add signer")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
        .alert(
            "Couldn't add signer",
            isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var canSave: Bool {
        if name.trimmingCharacters(in: .whitespaces).isEmpty { return false }
        switch mode {
        case .paste:     return !pastedLine.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .prefilled: return true
        }
    }

    private func save() {
        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        guard !trimmedName.isEmpty else { return }

        let keyType: String
        let wire: Data
        var comment: String?

        switch mode {
        case .prefilled(let kt, let w, _):
            keyType = kt
            wire = w
            comment = nil
        case .paste:
            guard let parsed = parsePublicKeyLine(pastedLine) else {
                errorMessage = "That doesn't look like an SSH public key. Expected a line like \"ssh-ed25519 AAAA… comment\"."
                return
            }
            keyType = parsed.keyType
            wire = parsed.wire
            comment = parsed.comment
        }

        let signer = StoredSigner(
            name: trimmedName,
            keyType: keyType,
            publicKeyWire: wire,
            comment: comment,
            source: source
        )
        do {
            try vault.addSigner(signer)
            onAdded()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Parse `ssh-<type> BASE64 [comment]` and validate the wire blob's type
    /// matches the declared type.
    private func parsePublicKeyLine(_ line: String) -> (keyType: String, wire: Data, comment: String?)? {
        let parts = line
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: " ", omittingEmptySubsequences: true)
            .map(String.init)
        guard parts.count >= 2 else { return nil }
        let keyType = parts[0]
        guard let wire = Data(base64Encoded: parts[1]) else { return nil }
        guard (try? SSHSig.publicKeyType(wire)) == keyType else { return nil }
        let comment = parts.count >= 3 ? parts[2...].joined(separator: " ") : nil
        return (keyType, wire, comment)
    }
}
