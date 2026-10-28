//
//  MigrateFlow.swift
//  AgePony
//
//  Move a file you already hold onto different recipients. In practice that's
//  onto a post-quantum one.
//
//  Why this exists: encrypting to a post-quantum recipient protects files from
//  today onward, but everything already encrypted stays exactly as breakable as
//  the key it was encrypted to. A file captured today and stored can be opened
//  later by whoever eventually breaks X25519. Migrating is how existing files
//  catch up.
//
//  It is honest about its limits. Re-encrypting your copy does nothing about
//  copies already sent elsewhere, and the operation puts a decrypted copy on
//  disk while it runs. Both are said plainly rather than buried.
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct MigrateFlow: View {

    let vault: Vault

    @State private var stage: Stage = .pickFile
    @State private var sourceURL: URL?
    @State private var sourceName: String = ""
    @State private var summary: AgeFileSummary?
    @State private var passphrase: String = ""
    @State private var recipients: [any AgeRecipient] = []
    @State private var recipientLabel: String = ""
    @State private var armor: Bool = true
    @State private var progressFraction: Double?
    @State private var result: MigrateService.Output?
    @State private var errorMessage: String?
    /// The YubiKey PIN prompt's answer, for the next `prepare` call only (5.1.0:
    /// asked before the tap). Dropped as soon as `prepare` returns.
    @State private var yubiKeyPIN: YubiKeyPINEntry?
    /// The in-app prompt, with the app password when Face ID only can't use Face ID (E6).
    @State private var ownerCheck = OwnerCheck()
    @State private var showYubiKeyPIN = false
    @State private var yubiKeyPINNote: String?
    @State private var yubiKeyOffersNoPIN = false
    @State private var showFilePicker: Bool = false
    @State private var showRecipientPicker: Bool = false

    @Environment(\.dismiss) private var dismiss

    enum Stage {
        case pickFile
        case inspecting
        case configure
        case working
        case done
    }

    var body: some View {
        content
            .ownerCheck(ownerCheck, vault: vault)
            .navigationTitle("Re-encrypt a file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if stage == .done {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { cleanupAndDismiss() }
                    }
                } else {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { cleanupAndDismiss() }
                    }
                }
            }
            .fileImporter(
                isPresented: $showFilePicker,
                allowedContentTypes: ageContentTypes,
                allowsMultipleSelection: false
            ) { handleFilePick($0) }
            .sheet(isPresented: $showRecipientPicker) {
                NavigationStack {
                    RecipientPickerView(
                        identities: vault.identities,
                        savedRecipients: vault.recipients,
                        initiallySelectedIdentityIDs: [],
                        onConfirm: { picked, _ in
                            // A passphrase would defeat the point here: the
                            // whole operation is about moving to a stronger
                            // key, not to a memorised one.
                            recipients = picked
                            recipientLabel = String(AttributedString(localized: "^[\(picked.count) recipient](inflect: true)").characters)
                        },
                        onSaveRecipient: { try vault.addRecipient($0) }
                    )
                }
            }
            .yubiKeyPINPrompt(isPresented: $showYubiKeyPIN, note: yubiKeyPINNote, offersNoPIN: yubiKeyOffersNoPIN) { pin in
                yubiKeyPIN = pin
                Task { await runMigrate(afterPIN: true) }
            }
    }

    @ViewBuilder
    private var content: some View {
        switch stage {
        case .pickFile:   pickFileStage
        case .inspecting: spinner("Reading header…")
        case .configure:  configureStage
        case .working:    workingStage
        case .done:       doneStage
        }
    }

    private var pickFileStage: some View {
        Form {
            Section {
                Button("Choose a .age file…") { showFilePicker = true }
            } footer: {
                Text("Decrypt a file you can already open and encrypt it again to different recipients. Usually that's to move it onto a quantum-safe key, so a file stored today stays private later.")
            }
            errorSection
        }
        .textCase(nil)
    }

    /// The last failure, under the action that caused it.
    @ViewBuilder
    private var errorSection: some View {
        if let errorMessage {
            Section {
                StatusText(errorMessage)
            }
        }
    }

    private var configureStage: some View {
        Form {
            if let summary {
                FileInfoSection(filename: sourceName, summary: summary)
                if summary.isPostQuantum {
                    Section {
                        Label("This file is already encrypted to a quantum-safe recipient.", systemImage: "atom")
                    }
                }

                if summary.onlyScrypt {
                    Section("Passphrase") {
                        SecureField("Passphrase for the current file", text: $passphrase)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                }
            }

            Section {
                Button {
                    showRecipientPicker = true
                } label: {
                    HStack {
                        if recipients.isEmpty {
                            Text("Choose new recipients")
                                .foregroundStyle(AgePonyColors.accent)
                        } else {
                            Text(recipientLabel)
                                .foregroundStyle(.primary)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").foregroundStyle(.secondary)
                    }
                }
                Toggle("ASCII armor", isOn: $armor)
            } header: {
                Text("Re-encrypt to")
            } footer: {
                Text("Only your copy changes. Anything you already sent to someone else stays encrypted to the old key.")
            }

            Section {
                Button {
                    Task { await runMigrate() }
                } label: {
                    Text("Re-encrypt")
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(!canRun)
            } footer: {
                Text("While this runs, a decrypted copy is written to this app's temporary storage and deleted as soon as it finishes.")
            }

            errorSection
        }
        .textCase(nil)
    }

    private var workingStage: some View {
        VStack(spacing: 16) {
            Spacer()
            if let progressFraction {
                ProgressView(value: progressFraction)
                    .progressViewStyle(.linear)
                    .padding(.horizontal, 48)
                Text(progressFraction, format: .percent.precision(.fractionLength(0)))
                    .font(AgePonyTypography.subheadline)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            } else {
                ProgressView().controlSize(.large)
            }
            Group {
                if (progressFraction ?? 0) < 0.5 {
                    Text("Decrypting…")
                } else {
                    Text("Re-encrypting…")
                }
            }
            .font(AgePonyTypography.headline)
            .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var doneStage: some View {
        Form {
            Section {
                StatusText("Re-encrypted", kind: .success, verdict: true)
                    .font(AgePonyTypography.headline)
                if let result {
                    LabeledContent("File") {
                        Text(result.url.lastPathComponent)
                            .font(AgePonyTypography.monoSmall)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    LabeledContent("Size before", value: ByteCountFormatter.string(fromByteCount: result.originalSize, countStyle: .file))
                    LabeledContent("Size now", value: ByteCountFormatter.string(fromByteCount: result.newSize, countStyle: .file))
                    LabeledContent("Recipients", value: recipientLabel)
                }
            } footer: {
                Text("Replace your stored copy with this one. The original file is unchanged.")
            }

            if let result {
                Section {
                    ShareLink(item: result.url) {
                        Text("Share re-encrypted file").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                }
            }
        }
        .textCase(nil)
    }

    private func spinner(_ text: LocalizedStringKey) -> some View {
        VStack(spacing: 16) {
            Spacer()
            ProgressView().controlSize(.large)
            Text(text).font(AgePonyTypography.headline).foregroundStyle(.secondary)
            Spacer()
        }
    }

    // MARK: - Logic

    private var ageContentTypes: [UTType] {
        if let age = UTType("org.age-encryption.age") { return [age, .data] }
        return [.data]
    }

    private var canRun: Bool {
        guard !recipients.isEmpty, let summary else { return false }
        if summary.onlyScrypt { return !passphrase.isEmpty }
        return !vault.identities.isEmpty
    }

    private func handleFilePick(_ result: Result<[URL], Error>) {
        do {
            guard let url = try result.get().first else { return }
            errorMessage = nil
            sourceURL = url
            sourceName = url.lastPathComponent
            stage = .inspecting
            Task { await inspect(url) }
        } catch {
            errorMessage = UserMessage.text(for: error, fallback: String(localized: "Couldn't open the file you picked."))
        }
    }

    private func inspect(_ url: URL) async {
        do {
            summary = try AgeFileInspector.inspect(fileURL: url, knownIdentities: vault.identities)
            stage = .configure
        } catch {
            if let e = error as? AgeFileInspectorError, case .notAnAgeFile = e {
                errorMessage = String(localized: "This file isn't age-encrypted.")
            } else {
                errorMessage = UserMessage.text(for: error, fallback: String(localized: "Couldn't read the file's age header."))
            }
            stage = .pickFile
        }
    }

    private func runMigrate(afterPIN: Bool = false) async {
        // The PIN is used for this one attempt at most; no early return keeps it.
        let pinEntry = yubiKeyPIN
        yubiKeyPIN = nil
        guard let url = sourceURL, let summary else { return }
        errorMessage = nil

        if !summary.onlyScrypt && !afterPIN {
            do {
                try await ownerCheck.authenticate(vault, reason: String(localized: "Re-encrypt \"\(sourceName)\""))
            } catch BiometricGateError.userCancelled {
                return
            } catch {
                errorMessage = UserMessage.text(for: error, fallback: BiometricGate.didNotConfirmText)
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
                return
            case .cancelled:
                return
            case .failed(let message):
                errorMessage = message
                return
            }
        }

        stage = .working
        progressFraction = nil

        let usingPassphrase = summary.onlyScrypt
        let passphraseSnapshot = passphrase
        let recipientsSnapshot = recipients
        let armorSnapshot = armor

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let out = try MigrateService.migrate(
                    inputURL: url,
                    identities: identitiesSnapshot,
                    passphrase: usingPassphrase ? passphraseSnapshot : nil,
                    to: recipientsSnapshot,
                    armor: armorSnapshot,
                    progress: { fraction in
                        DispatchQueue.main.async { progressFraction = fraction }
                    }
                )
                DispatchQueue.main.async {
                    result = out
                    stage = .done
                    progressFraction = nil
                }
            } catch {
                let description: String? = UserMessage.isCancellation(error)
                    ? nil
                    : UserMessage.text(for: error, fallback: String(localized: "Couldn't re-encrypt the file."))
                DispatchQueue.main.async {
                    errorMessage = description
                    stage = .configure
                    progressFraction = nil
                }
            }
        }
    }

    private func cleanupAndDismiss() {
        if let url = result?.url { FileEncryptor.cleanupTempFile(at: url) }
        dismiss()
    }
}
