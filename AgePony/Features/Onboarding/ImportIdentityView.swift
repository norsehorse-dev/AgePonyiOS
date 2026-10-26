//
//  ImportIdentityView.swift
//  AgePony
//
//  Import path used in both onboarding and the Add Identity flow. Three
//  modes: paste an age secret key -- classic `AGE-SECRET-KEY-1...` or
//  post-quantum `AGE-SECRET-KEY-PQ-1...` -- paste an OpenSSH PEM, or pick an
//  OpenSSH key file (id_ed25519 / id_rsa) via UIDocumentPicker. The
//  passphrase prompt is shown inline when the SSH PEM turns out to be
//  encrypted.
//
//  5.0.1 adds YubiKey: paste an age-plugin-yubikey identity (the
//  `AGE-PLUGIN-YUBIKEY-1…` line, or the whole file it prints). When the file
//  carries its `# Recipient:` line the key is known at once; otherwise one NFC
//  tap reads it from the slot the line points at.
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
    @State private var pastedYubiKey: String = ""
    @State private var passphrase: String = ""
    @State private var showPassphraseField: Bool = false
    @State private var passphraseError: String?
    @State private var importError: String?
    @State private var saving: Bool = false

    @State private var showFilePicker: Bool = false

    enum Mode: String, CaseIterable, Identifiable {
        case age   = "age"
        case ssh   = "SSH"
        case yubikey = "YubiKey"
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
                    Text("YubiKey").tag(Mode.yubikey)
                }
                .pickerStyle(.segmented)
            }

            switch mode {
            case .age:
                ageSection
            case .ssh:
                sshSection
            case .yubikey:
                yubiKeySection
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
            TextField("AGE-SECRET-KEY-1... or AGE-SECRET-KEY-PQ-1...", text: $pastedAge, axis: .vertical)
                .font(AgePonyTypography.monoSmall)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .lineLimit(3...8)
        } header: {
            Text("Paste age secret key")
        } footer: {
            Text("Starts with `AGE-SECRET-KEY-1`, or `AGE-SECRET-KEY-PQ-1` for a post-quantum key, and is all uppercase. You can paste a whole identity file; the `#` comment lines are ignored.")
        }
    }

    // MARK: - YubiKey section

    private var yubiKeySection: some View {
        Section {
            TextField("AGE-PLUGIN-YUBIKEY-1...", text: $pastedYubiKey, axis: .vertical)
                .font(AgePonyTypography.monoSmall)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .lineLimit(3...10)
        } header: {
            Text("Paste age-plugin-yubikey identity")
        } footer: {
            Text("From `age-plugin-yubikey --identity` on a computer. Paste the whole output if you can: with its Recipient line no tap is needed now. Otherwise you'll hold the YubiKey to your iPhone once so AgePony can read the key. Decrypting needs a tap each time.")
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
        case .yubikey: return pastedYubiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
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
        if mode == .yubikey {
            Task { await saveYubiKey(trimmed) }
            return
        }
        do {
            let stored: StoredIdentity
            switch mode {
            case .yubikey:
                saving = false
                return
            case .age:
                let raw = firstKeyLine(in: pastedAge)
                // Route on the prefix, as IdentityImport.kt does on Android.
                // A post-quantum key also begins "AGE-SECRET-KEY-", so the more
                // specific test has to come first -- checking the classic prefix
                // first would swallow every PQ key and hand it to a decoder that
                // can only reject it.
                if raw.uppercased().hasPrefix("AGE-SECRET-KEY-PQ-") {
                    let pq = try HybridIdentity(ageIdentity: raw)
                    stored = StoredIdentity(
                        name: trimmed,
                        type: .postQuantum,
                        publicKeyMaterial: pq.publicKey,
                        privateKeyMaterial: pq.seed,
                        sshComment: nil
                    )
                } else {
                    let id = try X25519Identity(ageIdentity: raw)
                    stored = StoredIdentity(
                        name: trimmed,
                        type: .x25519,
                        publicKeyMaterial: id.publicKey,
                        privateKeyMaterial: id.privateKey,
                        sshComment: nil
                    )
                }
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

    /// Store a YubiKey identity: the stub, and the public key from the pasted
    /// file or from one NFC tap.
    @MainActor
    private func saveYubiKey(_ trimmed: String) async {
        defer { saving = false }
        do {
            let (stub, known) = try YubiKeyStub.parseIdentityFile(pastedYubiKey)
            let key: Data
            if let known {
                key = known
            } else {
                key = try await YubiKeyDecrypt.readKey(stub: stub)
            }
            if vault.identities.contains(where: { $0.type == .yubikey && $0.publicKeyMaterial == key }) {
                importError = "This YubiKey key is already in your vault."
                return
            }
            let stored = StoredIdentity(
                name: trimmed,
                type: .yubikey,
                publicKeyMaterial: key,
                privateKeyMaterial: stub.bytes,
                sshComment: nil
            )
            _ = try vault.addIdentity(stored)
            onDone()
        } catch {
            if YubiKeyDecrypt.isCancelled(error) { return }
            importError = YubiKeyDecrypt.message(for: error)
        }
    }

    /// Accept either a bare key string or the contents of a whole identity
    /// file. `age-keygen` and AgePony Desktop both write `# created:` and
    /// `# public key:` lines above the key, and pasting the file wholesale is
    /// the obvious thing to try.
    private func firstKeyLine(in text: String) -> String {
        let payload = text
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .first { !$0.isEmpty && !$0.hasPrefix("#") }
        return payload ?? text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// What a Bech32 human-readable part means, in the user's terms.
    private func describe(hrp: String) -> String {
        switch hrp.lowercased() {
        case "age-secret-key-":
            return "a classic age identity, starting AGE-SECRET-KEY-1"
        case "age-secret-key-pq-":
            return "a post-quantum identity, starting AGE-SECRET-KEY-PQ-1"
        case "age":
            return "an age recipient (age1…), which is a public key rather than an identity"
        case "age1pq":
            return "a post-quantum recipient (age1pq1…), which is a public key rather than an identity"
        default:
            return "a “\(hrp)…” string"
        }
    }

    private func readable(_ error: Error) -> String {
        if let e = error as? Bech32Error {
            switch e {
            case .unexpectedHRP(let expected, let actual):
                return "That's \(describe(hrp: actual)). This field needs \(describe(hrp: expected))."
            case .invalidChecksum:
                return "The checksum doesn't match. The string is probably truncated or has a typo — check you copied all of it."
            case .mixedCase:
                return "An age key is all one case. This string mixes upper and lower case."
            case .invalidCharacter(let c):
                return "“\(c)” can't appear in an age key. Check for a stray character picked up while copying."
            case .invalidPadding:
                return "That decoded cleanly but is the wrong length for its key type."
            case .stringTooShort, .missingSeparator, .emptyHRP:
                return "That doesn't look like an age identity string."
            default:
                return "That doesn't look like a valid age identity string. (\(e))"
            }
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
