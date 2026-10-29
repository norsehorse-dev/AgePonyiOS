//
//  TextDecryptView.swift
//  AgePony
//
//  Hotfix on 1g: runDecrypt moved off-main via DispatchQueue.global.
//  The biometric prompt still runs as an async/await call before the
//  background work, since BiometricGate.authenticate needs to interact
//  with LAContext on the main thread anyway.
//
//  5.1.1: a signature in the text (a header stanza or a signed bundle) is
//  verified as the file flow does it, and shown under the plaintext (L-1). The
//  plaintext can't be selected, so it only leaves through the Copy button,
//  which is local-only and expires (L-14).
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
    /// The verdict on the text's signature, when it carried one (5.1.1, L-1).
    @State private var signature: FileVerificationResult?
    @State private var working: Bool = false
    @State private var errorMessage: String?
    /// The YubiKey PIN prompt's answer, for the next `prepare` call only (5.1.0:
    /// asked before the tap). Dropped as soon as `prepare` returns.
    @State private var yubiKeyPIN: YubiKeyPINEntry?
    /// The in-app prompt, with the app password when Face ID only can't use Face ID (E6).
    @State private var ownerCheck = OwnerCheck()
    @State private var showYubiKeyPIN = false
    @State private var yubiKeyPINNote: String?
    @State private var yubiKeyOffersNoPIN = false
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
                FileInfoSection(filename: nil, summary: summary)
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
            if let errorMessage {
                Section {
                    StatusText(errorMessage)
                }
            }
        }
        .textCase(nil)
        .ownerCheck(ownerCheck, vault: vault)
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
        .yubiKeyPINPrompt(isPresented: $showYubiKeyPIN, note: yubiKeyPINNote, offersNoPIN: yubiKeyOffersNoPIN) { pin in
            yubiKeyPIN = pin
            Task { await startDecrypt(afterPIN: true) }
        }
    }

    private var inputSection: some View {
        Section {
            TextEditor(text: $inputText)
                // No keyboard learning from what's typed here (L-23).
                .autocorrectionDisabled()
                .font(AgePonyTypography.monoCaption)
                .frame(minHeight: 160)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .disabled(resultPlaintext != nil)
                .onChange(of: inputText) { _, _ in
                    summary = nil
                    resultPlaintext = nil
                    signature = nil
                    errorMessage = nil
                }
            // The system paste button reads the clipboard only when tapped, so iOS
            // shows no "allow paste" prompt. It replaces whatever is in the field.
            if resultPlaintext == nil {
                PasteButton(payloadType: String.self) { strings in
                    guard let text = strings.first else { return }
                    // The callback isn't promised to run on the main thread.
                    DispatchQueue.main.async { inputText = text }
                }
                .labelStyle(.titleAndIcon)
                .tint(AgePonyColors.accent)
            }
        } header: {
            Text("Encrypted text")
        } footer: {
            Text("Paste the armored block, including the BEGIN and END markers.")
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
                // No system selection: its Copy skips local-only and expiry (5.1.1, L-14).
                ScrollView {
                    Text(plaintext)
                        .font(AgePonyTypography.body)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 8)
                }
                .frame(maxHeight: 280)
            } header: {
                Text("Plaintext")
            }

            // Shown even when it failed: the plaintext is already on screen (5.1.1, L-1).
            if let signature {
                Section {
                    CompactVerifiedBadge(result: signature)
                } header: {
                    Text("Signature")
                }
            }

            Section {
                Button {
                    copyResult()
                } label: {
                    Group {
                        if copied {
                            Label("Copied", systemImage: "checkmark")
                        } else {
                            Label("Copy to clipboard", systemImage: "doc.on.doc")
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }

            // Its own section, as on the other done screens: sharing one with the
            // clear-backed button left a half-rounded row under it.
            Section {
                Button("Decrypt another") {
                    inputText = ""
                    summary = nil
                    passphraseInput = ""
                    resultPlaintext = nil
                    signature = nil
                    copied = false
                }
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
    private func startDecrypt(afterPIN: Bool = false) async {
        // The PIN is used for this one attempt at most; no early return keeps it.
        let pinEntry = yubiKeyPIN
        yubiKeyPIN = nil
        guard let summary else { return }
        working = true
        errorMessage = nil

        if !summary.onlyScrypt && !afterPIN {
            // Identity path needs biometric to reveal private keys.
            do {
                try await ownerCheck.authenticate(vault, reason: String(localized: "Decrypt text"))
            } catch BiometricGateError.userCancelled {
                working = false
                return
            } catch {
                errorMessage = UserMessage.text(for: error, fallback: BiometricGate.didNotConfirmText)
                working = false
                return
            }
        }

        var identitiesSnapshot: [any AgeIdentity] = []
        if !summary.onlyScrypt {
            let prepared = await DecryptIdentities.prepare(vault: vault, stanzas: summary.rawStanzas, yubiKeyPIN: pinEntry)
            switch prepared {
            case .ready(let ids):
                identitiesSnapshot = ids
            case .needsPIN(let note, let offersNoPIN):
                yubiKeyPINNote = note
                yubiKeyOffersNoPIN = offersNoPIN
                showYubiKeyPIN = true
                working = false
                return
            case .cancelled:
                working = false
                return
            case .failed(let message):
                errorMessage = message
                working = false
                return
            }
        }

        let passphraseSnapshot = passphraseInput
        let summarySnapshot = summary
        // Text mode always inspects buffered bytes, so the payload is present.
        // The file flow uses the header-only inspector, where it is nil by design.
        let binarySnapshot = summarySnapshot.binaryBytes ?? Data()
        // For signer attribution, worked out off the main actor (as DecryptFlow does).
        let storedIdentities = vault.identities
        let storedRecipients = vault.recipients
        let storedSigners = vault.signers

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let outcome = try TextDecryptor.decrypt(
                    binary: binarySnapshot,
                    identities: identitiesSnapshot,
                    passphrase: summarySnapshot.onlyScrypt ? passphraseSnapshot : nil,
                    storedIdentities: storedIdentities,
                    recipients: storedRecipients,
                    signers: storedSigners
                )
                DispatchQueue.main.async {
                    resultPlaintext = outcome.text
                    signature = outcome.signature
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
        ClipboardPreferences.copy(result)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { copied = false }
    }

    private func describeInspectError(_ error: Error) -> String {
        if let e = error as? AgeFileInspectorError {
            switch e {
            case .notAnAgeFile:   return String(localized: "This isn't an armored age block. It should start with -----BEGIN AGE ENCRYPTED FILE-----.")
            case .malformedArmor: return String(localized: "The armored block is damaged. Copy it again, including the BEGIN and END lines.")
            case .headerParseFailed, .cannotOpenFile: break
            }
        }
        return UserMessage.text(for: error, fallback: String(localized: "Couldn't read the encrypted text."))
    }

    private func describeDecryptError(_ error: Error) -> String {
        if let e = error as? AgeError, case .noMatchingIdentity = e {
            return String(localized: "None of the identities in this vault can decrypt this text.")
        }
        return UserMessage.text(for: error, fallback: String(localized: "Couldn't decrypt the text."))
    }
}

// MARK: - Decrypt and verify (5.1.1, L-1)

/// Decrypts armored text that has already been de-armored, and checks any
/// signature it carries the way DecryptFlow does for a file: a signed bundle's
/// verdict first, otherwise the header stanza's.
enum TextDecryptor {

    struct Outcome {
        let text: String
        /// Nil when the text carried no signature.
        let signature: FileVerificationResult?
    }

    /// `passphrase` non-nil means a passphrase decrypt, and `identities` is ignored.
    static func decrypt(
        binary: Data,
        identities: [any AgeIdentity],
        passphrase: String?,
        storedIdentities: [StoredIdentity],
        recipients: [StoredRecipient],
        signers: [StoredSigner]
    ) throws -> Outcome {
        try decrypt(binary: binary, identities: identities, passphrase: passphrase,
                    storedIdentities: storedIdentities, recipients: recipients, signers: signers,
                    scryptFits: { ScryptMemory.fits(workFactor: $0) })
    }

    /// `scryptFits` decides whether a work factor fits in memory; tests pass their own.
    static func decrypt(
        binary: Data,
        identities: [any AgeIdentity],
        passphrase: String?,
        storedIdentities: [StoredIdentity],
        recipients: [StoredRecipient],
        signers: [StoredSigner],
        scryptFits: (Int) -> Bool
    ) throws -> Outcome {
        let decrypted: Age.DecryptedWithSignature
        if let passphrase {
            let header = try? Age.parseHeader(ciphertext: binary)
            // Refuse a work factor that won't fit before deriving (5.1.1, L-2).
            if let header {
                try FileEncryptor.checkScryptMemory(stanzas: header.stanzas, fits: scryptFits)
            }
            do {
                decrypted = try Age.decryptAndRecoverSignature(
                    ciphertext: binary,
                    identities: [ScryptIdentity(passphrase: passphrase)]
                )
            } catch AgeError.noMatchingIdentity {
                // As Age.decrypt(ciphertext:passphrase:) reads it.
                if let header, header.stanzas.allSatisfy({ $0.type == "scrypt" }) {
                    throw AgeError.wrongPassphrase
                }
                throw AgeError.noMatchingIdentity
            }
        } else {
            decrypted = try Age.decryptAndRecoverSignature(ciphertext: binary, identities: identities)
        }

        var plaintext = decrypted.plaintext
        let signature: FileVerificationResult?
        if SignedBundle.looksLikeBundle(plaintext) {
            guard let bundle = SignedBundle.parse(plaintext) else {
                throw FileEncryptorError.bundleDamaged(String(localized: "The text decrypted, but the signed bundle inside it is damaged."))
            }
            signature = FileVerifier.verify(
                bundle: bundle,
                identities: storedIdentities,
                recipients: recipients,
                signers: signers
            )
            plaintext = bundle.payload
        } else {
            signature = FileVerifier.verify(
                stanza: decrypted.signature,
                plaintext: plaintext,
                identities: storedIdentities,
                recipients: recipients,
                signers: signers
            )
        }

        let text = String(data: plaintext, encoding: .utf8) ?? String(localized: "(Not UTF-8 text, \(plaintext.count) bytes)")
        return Outcome(text: text, signature: signature)
    }
}
