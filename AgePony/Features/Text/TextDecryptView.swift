//
//  TextDecryptView.swift
//  AgePony
//
//  Hotfix on 1g: runDecrypt moved off-main via DispatchQueue.global.
//  The biometric prompt still runs as an async/await call before the
//  background work, since BiometricGate.authenticate needs to interact
//  with LAContext on the main thread anyway.
//

import SwiftUI
import AgePonyCore
import UIKit

struct TextDecryptView: View {

    let vault: Vault
    let preloadedText: String

    @State private var inputText: String
    @State private var summary: AgeFileSummary?
    @State private var passphraseInput: String = ""
    @State private var resultPlaintext: String?
    @State private var working: Bool = false
    @State private var errorMessage: String?
    @State private var copied: Bool = false

    @Environment(\.dismiss) private var dismiss

    init(vault: Vault, preloadedText: String = "") {
        self.vault = vault
        self.preloadedText = preloadedText
        _inputText = State(initialValue: preloadedText)
    }

    var body: some View {
        Form {
            inputSection
            if let summary = summary {
                FileInfoSection(summary: summary)
                if summary.onlyScrypt {
                    passphraseSection
                }
                if resultPlaintext == nil {
                    decryptSection
                }
            } else if !inputText.isEmpty {
                inspectSection
            }
            if let plaintext = resultPlaintext {
                resultSection(plaintext: plaintext)
            }
        }
        .navigationTitle("Decrypt text")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") { dismiss() }
            }
        }
        .task {
            if !preloadedText.isEmpty && summary == nil {
                inspect()
            }
        }
        .alert(
            "Decrypt failed",
            isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var inputSection: some View {
        Section {
            TextEditor(text: $inputText)
                .font(AgePonyTypography.monoCaption)
                .frame(minHeight: 160)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .disabled(resultPlaintext != nil)
                .onChange(of: inputText) { _, _ in
                    summary = nil
                    resultPlaintext = nil
                    errorMessage = nil
                }
        } header: {
            Text("Encrypted text")
        } footer: {
            Text("Paste the BEGIN/END armored block, including the markers.")
        }
    }

    private var inspectSection: some View {
        Section {
            Button {
                inspect()
            } label: {
                Text("Inspect").frame(maxWidth: .infinity)
            }
            .buttonStyle(.agePonySecondary)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            .disabled(inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        } footer: {
            Text("Reads the recipient list out of the armored block without decrypting.")
        }
    }

    private var passphraseSection: some View {
        Section {
            SecureField("Passphrase", text: $passphraseInput)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        } header: {
            Text("Passphrase")
        } footer: {
            Text("This text was encrypted with a passphrase. Decryption takes a moment because scrypt is deliberately slow.")
        }
    }

    private var decryptSection: some View {
        Section {
            Button {
                Task { await startDecrypt() }
            } label: {
                if working {
                    HStack {
                        ProgressView()
                        Text("Decrypting…")
                    }
                    .frame(maxWidth: .infinity)
                } else {
                    Text("Decrypt").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.agePonyPrimary)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            .disabled(!canDecrypt || working)
        }
    }

    private func resultSection(plaintext: String) -> some View {
        Group {
            Section {
                ScrollView {
                    Text(plaintext)
                        .font(AgePonyTypography.body)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(.vertical, 8)
                }
                .frame(maxHeight: 280)
            } header: {
                Text("Plaintext")
            }

            Section {
                Button {
                    copyResult()
                } label: {
                    Label(copied ? "Copied" : "Copy to clipboard",
                          systemImage: copied ? "checkmark" : "doc.on.doc")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)

                Button("Decrypt another") {
                    inputText = ""
                    summary = nil
                    passphraseInput = ""
                    resultPlaintext = nil
                    copied = false
                }
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
            }
        }
    }

    private var canDecrypt: Bool {
        guard let summary else { return false }
        if summary.onlyScrypt {
            return !passphraseInput.isEmpty
        }
        return !vault.identities.isEmpty
    }

    private func inspect() {
        errorMessage = nil
        do {
            let bytes = Data(inputText.utf8)
            let s = try AgeFileInspector.inspect(
                fileBytes: bytes,
                knownIdentities: vault.identities
            )
            summary = s
        } catch {
            errorMessage = describeInspectError(error)
        }
    }

    /// Handles the biometric prompt (which must run on MainActor) before
    /// kicking the actual decrypt onto a background queue.
    private func startDecrypt() async {
        guard let summary else { return }
        working = true
        errorMessage = nil

        if !summary.onlyScrypt {
            // Identity path needs biometric to reveal private keys.
            do {
                try await BiometricGate.authenticate(reason: "Decrypt text")
            } catch BiometricGateError.userCancelled {
                working = false
                return
            } catch {
                errorMessage = error.localizedDescription
                working = false
                return
            }
        }

        let passphraseSnapshot = passphraseInput
        let summarySnapshot = summary
        let identitiesSnapshot = vault.identities.compactMap { try? $0.toAgeIdentity() }
        // Text mode always inspects buffered bytes, so the payload is present.
        // The file flow uses the header-only inspector, where it is nil by design.
        let binarySnapshot = summarySnapshot.binaryBytes ?? Data()

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let plaintext: Data
                if summarySnapshot.onlyScrypt {
                    plaintext = try Age.decrypt(
                        ciphertext: binarySnapshot,
                        passphrase: passphraseSnapshot
                    )
                } else {
                    plaintext = try Age.decrypt(
                        ciphertext: binarySnapshot,
                        identities: identitiesSnapshot
                    )
                }
                let resultString = String(data: plaintext, encoding: .utf8) ?? "(non-UTF-8 plaintext, \(plaintext.count) bytes)"
                DispatchQueue.main.async {
                    resultPlaintext = resultString
                    working = false
                }
            } catch {
                let description = describeDecryptError(error)
                DispatchQueue.main.async {
                    errorMessage = description
                    working = false
                }
            }
        }
    }

    private func copyResult() {
        guard let result = resultPlaintext else { return }
        let pasteboard = UIPasteboard.general
        let expiry = Date().addingTimeInterval(60)
        pasteboard.setItems(
            [[UIPasteboard.typeAutomatic: result]],
            options: [
                .expirationDate: expiry,
                .localOnly: true
            ]
        )
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { copied = false }
    }

    private func describeInspectError(_ error: Error) -> String {
        if let e = error as? AgeFileInspectorError {
            switch e {
            case .notAnAgeFile:          return "This doesn't look like an armored age block."
            case .malformedArmor:        return "The armored block is malformed."
            case .headerParseFailed(let m): return "Couldn't parse the age header: \(m)"
            // Text mode inspects bytes already in hand, so this cannot arise here.
            case .cannotOpenFile(let name): return "Couldn't open \(name)."
            }
        }
        return error.localizedDescription
    }

    private func describeDecryptError(_ error: Error) -> String {
        let s = String(describing: error)
        if s.contains("wrongPassphrase") { return "Wrong passphrase." }
        if s.contains("noMatchingIdentity") { return "No identity in this vault can decrypt this text." }
        return error.localizedDescription
    }
}

private struct FileInfoSection: View {
    let summary: AgeFileSummary

    var body: some View {
        Section {
            HStack(spacing: 16) {
                meta("Size", ByteCountFormatter.string(fromByteCount: Int64(summary.byteCount), countStyle: .file))
                meta("Format", summary.armored ? "PEM-armored" : "Binary")
                meta("Recipients", "\(summary.stanzas.count)")
                Spacer()
            }

            ForEach(summary.stanzas) { stanza in
                HStack(spacing: 10) {
                    Image(systemName: icon(for: stanza.kind))
                        .foregroundStyle(AgePonyColors.tealCore)
                        .frame(width: 18)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(stanza.kind.displayLabel)
                            .font(AgePonyTypography.footnote)
                        if let matched = stanza.matchedIdentityName {
                            Text("matches your identity \"\(matched)\"")
                                .font(AgePonyTypography.caption)
                                .foregroundStyle(AgePonyColors.tealCore)
                        }
                    }
                    Spacer()
                }
            }
        } header: {
            Text("This text contains")
        }
    }

    private func meta(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(AgePonyTypography.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(AgePonyTypography.footnote)
        }
    }

    private func icon(for kind: StanzaSummary.Kind) -> String {
        switch kind {
        case .x25519:      return "key.fill"
        case .sshEd25519:  return "lock.shield"
        case .sshRSA:      return "lock.shield"
        case .scrypt:      return "lock.rectangle"
        case .postQuantum: return "atom"
        case .unknown:     return "questionmark.circle"
        }
    }
}
