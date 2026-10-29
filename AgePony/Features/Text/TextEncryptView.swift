//
//  TextEncryptView.swift
//  AgePony
//
//  Hotfix on 1g: runEncrypt no longer async. Same pattern as
//  EncryptFlow — the synchronous Age.encrypt call (especially with
//  scrypt) runs on DispatchQueue.global so the main thread stays
//  responsive.
//

import SwiftUI
import AgePonyCore
import UIKit

struct TextEncryptView: View {

    let vault: Vault
    let preloadedText: String

    @State private var inputText: String
    @State private var recipients: [any AgeRecipient] = []
    @State private var passphrase: String?
    @State private var resultArmored: String?
    @State private var working: Bool = false
    @State private var errorMessage: String?
    @State private var copied: Bool = false

    @State private var showRecipientPicker: Bool = false

    @Environment(\.dismiss) private var dismiss

    init(vault: Vault, preloadedText: String = "") {
        self.vault = vault
        self.preloadedText = preloadedText
        _inputText = State(initialValue: preloadedText)
    }

    private static let resultAnchor = "result"

    var body: some View {
        ScrollViewReader { proxy in
            Form {
                inputSection
                recipientsSection
                if let result = resultArmored {
                    resultSection(armored: result)
                } else {
                    encryptSection
                }
                if let errorMessage {
                    Section {
                        StatusText(errorMessage)
                    }
                }
            }
            // The result replaces the Encrypt button below the recipients, often
            // off screen: bring it into view so Copy and Share are seen.
            .onChange(of: resultArmored) { _, new in
                guard new != nil else { return }
                withAnimation { proxy.scrollTo(Self.resultAnchor, anchor: .top) }
            }
        }
        .textCase(nil)
        .navigationTitle("Encrypt text")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") { dismiss() }
            }
        }
        .sheet(isPresented: $showRecipientPicker) {
            NavigationStack {
                RecipientPickerView(
                    identities: vault.identities,
                    savedRecipients: vault.recipients,
                    initiallySelectedIdentityIDs: defaultSelectedIdentityIDs,
                    initiallySelectedRecipientIDs: vault.backupRecipientSelection,
                    onConfirm: { recipients, passphrase in
                        self.recipients = recipients
                        self.passphrase = passphrase
                        self.resultArmored = nil
                    },
                    onSaveRecipient: { try vault.addRecipient($0) }
                )
            }
        }
    }

    private var inputSection: some View {
        Section {
            TextEditor(text: $inputText)
                // No keyboard learning from what's typed here (L-23).
                .autocorrectionDisabled()
                .frame(minHeight: 180)
                .font(AgePonyTypography.body)
                .disabled(resultArmored != nil)
        } header: {
            Text("Plaintext")
        } footer: {
            Text("Paste or type the text you want to encrypt. UTF-8 only.")
        }
    }

    private var recipientsSection: some View {
        Section {
            Button {
                showRecipientPicker = true
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(recipientSummaryTitle)
                            .font(AgePonyTypography.body)
                            .foregroundStyle(.primary)
                        Text(recipientSummarySubtitle)
                            .font(AgePonyTypography.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: "chevron.right")
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)
            .disabled(resultArmored != nil)
        } header: {
            Text("Recipients")
        }
    }

    private var encryptSection: some View {
        Section {
            Button(action: runEncrypt) {
                if working {
                    HStack {
                        ProgressView()
                        Text("Encrypting…")
                    }
                    .frame(maxWidth: .infinity)
                } else {
                    Text("Encrypt").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.agePonyPrimary)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            .disabled(!canEncrypt || working)
        }
    }

    private func resultSection(armored: String) -> some View {
        Group {
            Section {
                ScrollView {
                    Text(armored)
                        .font(AgePonyTypography.monoCaption)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(.vertical, 8)
                }
                .frame(maxHeight: 280)
            } header: {
                Text("Encrypted")
            } footer: {
                Text("PEM-style armor. Safe to paste anywhere that handles text. The recipient runs Decrypt text with their identity or passphrase.")
            }
            .id(Self.resultAnchor)

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

                ShareLink(item: armored) {
                    Text("Share…")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.agePonySecondary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }

            // Its own section, as on the other done screens.
            Section {
                Button("Encrypt another") {
                    inputText = ""
                    resultArmored = nil
                    copied = false
                }
            }
        }
    }

    private var defaultSelectedIdentityIDs: Set<UUID> {
        guard vault.encryptToSelfDefault, let active = vault.activeIdentity() else {
            return []
        }
        return [active.id]
    }

    private var canEncrypt: Bool {
        let hasText = !inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        let hasTarget = !recipients.isEmpty || passphrase?.isEmpty == false
        return hasText && hasTarget
    }

    private var recipientSummaryTitle: String {
        if passphrase?.isEmpty == false {
            return String(localized: "Passphrase only")
        }
        if recipients.isEmpty {
            return String(localized: "Choose recipients")
        }
        let n = recipients.count
        return String(AttributedString(localized: "^[\(n) recipient](inflect: true)").characters)
    }

    private var recipientSummarySubtitle: String {
        if passphrase?.isEmpty == false {
            return String(localized: "Encrypted with a passphrase (scrypt)")
        }
        if recipients.isEmpty {
            return String(localized: "Tap to add the people who can decrypt")
        }
        return String(localized: "Tap to change")
    }

    private func runEncrypt() {
        working = true
        errorMessage = nil
        let bodyData = Data(inputText.utf8)
        let recipientsSnapshot = recipients
        let passphraseSnapshot = passphrase

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let binary: Data
                if let pphr = passphraseSnapshot, !pphr.isEmpty {
                    binary = try Age.encrypt(plaintext: bodyData, passphrase: pphr, workFactor: 16)
                } else {
                    binary = try Age.encrypt(plaintext: bodyData, to: recipientsSnapshot)
                }
                let armored = AgeArmor.encode(binary)
                DispatchQueue.main.async {
                    resultArmored = armored
                    working = false
                }
            } catch {
                let description = describe(error)
                DispatchQueue.main.async {
                    errorMessage = description
                    working = false
                }
            }
        }
    }

    private func describe(_ error: Error) -> String {
        UserMessage.text(for: error, fallback: String(localized: "Couldn't encrypt the text."))
    }

    private func copyResult() {
        guard let result = resultArmored else { return }
        ClipboardPreferences.copy(result)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { copied = false }
    }
}
