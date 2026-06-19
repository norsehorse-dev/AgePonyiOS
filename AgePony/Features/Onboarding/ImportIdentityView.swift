//
//  ImportIdentityView.swift
//  AgePony
//
//  Import path used in both onboarding and the Add Identity flow. Three
//  modes: paste `AGE-SECRET-KEY-1...`, paste an OpenSSH PEM, or pick an
//  OpenSSH key file (id_ed25519 / id_rsa) via UIDocumentPicker. The
//  passphrase prompt is shown inline when the SSH PEM turns out to be
//  encrypted.
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct ImportIdentityView: View {

    let vault: Vault
    let onDone: () -> Void

    @State private var mode: Mode = .age
    @State private var name: String = "Personal"
    @State private var pastedAge: String = ""
    @State private var pastedSSH: String = ""
    @State private var passphrase: String = ""
    @State private var showPassphraseField: Bool = false
    @State private var passphraseError: String?
    @State private var importError: String?
    @State private var saving: Bool = false

    @State private var showFilePicker: Bool = false

    enum Mode: String, CaseIterable, Identifiable {
        case age   = "age"
        case ssh   = "SSH"
        var id: String { rawValue }
    }

    var body: some View {
        Form {
            Section {
                TextField("Identity name", text: $name)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
            } header: {
                Text("Name")
            }

            Section {
                Picker("Source", selection: $mode) {
                    Text("age identity").tag(Mode.age)
                    Text("SSH key").tag(Mode.ssh)
                }
                .pickerStyle(.segmented)
            }

            switch mode {
            case .age:
                ageSection
            case .ssh:
                sshSection
            }

            Section {
                Button(action: save) {
                    if saving {
                        ProgressView().frame(maxWidth: .infinity)
                    } else {
                        Text("Save & continue").frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(saveDisabled)
            }
        }
        .navigationTitle("Import identity")
        .navigationBarTitleDisplayMode(.inline)
        .fileImporter(
            isPresented: $showFilePicker,
            allowedContentTypes: [.data, .text, .plainText, UTType(filenameExtension: "pub") ?? .text],
            allowsMultipleSelection: false
        ) { result in
            handleFilePick(result)
        }
        .alert("Could not import", isPresented: Binding(
            get: { importError != nil },
            set: { if !$0 { importError = nil } }
        ), actions: {
            Button("OK", role: .cancel) { importError = nil }
        }, message: {
            Text(importError ?? "")
        })
    }

    // MARK: - age section

    private var ageSection: some View {
        Section {
            TextField("AGE-SECRET-KEY-1...", text: $pastedAge, axis: .vertical)
                .font(AgePonyTypography.monoSmall)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .lineLimit(3...8)
        } header: {
            Text("Paste age secret key")
        } footer: {
            Text("The full string starts with `AGE-SECRET-KEY-1` and is all uppercase.")
        }
    }

    // MARK: - SSH section

    private var sshSection: some View {
        Group {
            Section {
                TextField("-----BEGIN OPENSSH PRIVATE KEY-----...", text: $pastedSSH, axis: .vertical)
                    .font(AgePonyTypography.monoCaption)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .lineLimit(4...12)
                Button {
                    showFilePicker = true
                } label: {
                    Label("Pick from Files…", systemImage: "doc.badge.plus")
                        .font(AgePonyTypography.footnote)
                }
                .foregroundStyle(AgePonyColors.tealCore)
            } header: {
                Text("Paste or pick OpenSSH private key")
            } footer: {
                Text("Supports ed25519 and RSA keys, encrypted or unencrypted.")
            }

            if showPassphraseField {
                Section {
                    SecureField("Passphrase", text: $passphrase)
                        .textInputAutocapitalization(.never)
                    if let msg = passphraseError {
                        Text(msg)
                            .font(AgePonyTypography.caption)
                            .foregroundStyle(AgePonyColors.destructive)
                    }
                } header: {
                    Text("Key is encrypted")
                } footer: {
                    Text("Enter the passphrase you set when you generated this SSH key.")
                }
            }
        }
    }

    private var saveDisabled: Bool {
        if name.trimmingCharacters(in: .whitespaces).isEmpty { return true }
        if saving { return true }
        switch mode {
        case .age: return pastedAge.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .ssh: return pastedSSH.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }

    // MARK: - Actions

    private func handleFilePick(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard let url = urls.first else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            if let text = String(data: data, encoding: .utf8) {
                pastedSSH = text
            } else {
                importError = "That file isn't a UTF-8 OpenSSH key."
            }
        } catch {
            importError = error.localizedDescription
        }
    }

    private func save() {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        saving = true
        passphraseError = nil
        do {
            let stored: StoredIdentity
            switch mode {
            case .age:
                let raw = pastedAge.trimmingCharacters(in: .whitespacesAndNewlines)
                let id  = try X25519Identity(ageIdentity: raw)
                stored = StoredIdentity(
                    name: trimmed,
                    type: .x25519,
                    publicKeyMaterial: id.publicKey,
                    privateKeyMaterial: id.privateKey,
                    sshComment: nil
                )
            case .ssh:
                let pem = pastedSSH.trimmingCharacters(in: .whitespacesAndNewlines)
                let pphr = showPassphraseField ? passphrase : nil
                do {
                    stored = try SSHIdentityImporter.makeStoredIdentity(
                        fromOpenSSHPEM: pem,
                        passphrase: pphr,
                        name: trimmed
                    )
                } catch SSHImportError.passphraseRequired {
                    showPassphraseField = true
                    saving = false
                    return
                } catch SSHImportError.wrongPassphrase {
                    showPassphraseField = true
                    passphraseError = "Incorrect passphrase. Try again."
                    saving = false
                    return
                }
            }
            _ = try vault.addIdentity(stored)
            onDone()
        } catch {
            importError = readable(error)
        }
        saving = false
    }

    private func readable(_ error: Error) -> String {
        if let e = error as? Bech32Error {
            return "That doesn't look like a valid age identity string. (\(e))"
        }
        if let e = error as? SSHImportError {
            switch e {
            case .passphraseRequired: return "This key is passphrase-protected."
            case .wrongPassphrase:    return "Incorrect passphrase."
            case .unsupportedKeyType: return "Only ed25519 and RSA SSH keys are supported."
            case .malformedPEM:       return "The PEM appears malformed."
            }
        }
        return error.localizedDescription
    }
}
