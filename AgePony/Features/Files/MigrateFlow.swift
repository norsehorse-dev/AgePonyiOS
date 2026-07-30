//
//  MigrateFlow.swift
//  AgePony
//
//  Move a file you already hold onto different recipients — in practice, onto a
//  post-quantum one.
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
            .navigationTitle("Re-encrypt a file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { cleanupAndDismiss() }
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
                            recipientLabel = "\(picked.count) recipient\(picked.count == 1 ? "" : "s")"
                        },
                        onSaveRecipient: { try vault.addRecipient($0) }
                    )
                }
            }
            .alert(
                "Re-encrypt failed",
                isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
            ) {
                Button("OK", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
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
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)
            Text("Re-encrypt a file")
                .font(AgePonyTypography.title)
            Text("Decrypt a file you can already open and encrypt it again to different recipients — usually to move it onto a post-quantum key, so a file stored today stays private later.")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Button("Pick a .age file…") { showFilePicker = true }
                .buttonStyle(.agePonyPrimary)
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
        }
    }

    private var configureStage: some View {
        Form {
            if let summary {
                Section("Current file") {
                    FileInfoCard(filename: sourceName, summary: summary)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                    if summary.isPostQuantum {
                        Text("This file is already encrypted to a post-quantum recipient.")
                            .font(AgePonyTypography.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if summary.onlyScrypt {
                    Section("Passphrase") {
                        SecureField("Passphrase for the current file", text: $passphrase)
                            .textInputAutocapitalization(.never)
                    }
                }
            }

            Section {
                Button {
                    showRecipientPicker = true
                } label: {
                    HStack {
                        Text(recipients.isEmpty ? "Choose new recipients" : recipientLabel)
                            .foregroundStyle(recipients.isEmpty ? AgePonyColors.tealCore : .primary)
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
                    Text("Re-encrypt").frame(maxWidth: .infinity)
                }
                .disabled(!canRun)
            } footer: {
                Text("While this runs, a decrypted copy is written to this app's temporary storage and deleted as soon as it finishes.")
            }
        }
    }

    private var workingStage: some View {
        VStack(spacing: 18) {
            Spacer()
            if let progressFraction {
                ProgressView(value: progressFraction)
                    .progressViewStyle(.linear)
                    .tint(AgePonyColors.tealCore)
                    .padding(.horizontal, 48)
                Text("\(Int(progressFraction * 100))%")
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            } else {
                ProgressView().controlSize(.large).tint(AgePonyColors.tealCore)
            }
            Text(progressFraction ?? 0 < 0.5 ? "Decrypting…" : "Re-encrypting…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var doneStage: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 56, weight: .regular))
                .foregroundStyle(AgePonyColors.tealCore)
            Text("Re-encrypted")
                .font(AgePonyTypography.title)
            if let result {
                Text(result.url.lastPathComponent)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(ByteCountFormatter.string(fromByteCount: result.originalSize, countStyle: .file)
                     + " → "
                     + ByteCountFormatter.string(fromByteCount: result.newSize, countStyle: .file))
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(.secondary)
            }
            Text("Replace your stored copy with this one. The original file is unchanged.")
                .font(AgePonyTypography.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            VStack(spacing: 12) {
                if let result {
                    ShareLink(item: result.url) {
                        Text("Share re-encrypted file").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                }
                Button("Done") { cleanupAndDismiss() }
                    .buttonStyle(.agePonySecondary)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
    }

    private func spinner(_ text: String) -> some View {
        VStack(spacing: 18) {
            Spacer()
            ProgressView().controlSize(.large).tint(AgePonyColors.tealCore)
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
            sourceURL = url
            sourceName = url.lastPathComponent
            stage = .inspecting
            Task { await inspect(url) }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func inspect(_ url: URL) async {
        do {
            summary = try AgeFileInspector.inspect(fileURL: url, knownIdentities: vault.identities)
            stage = .configure
        } catch {
            errorMessage = String(describing: error)
            stage = .pickFile
        }
    }

    private func runMigrate() async {
        guard let url = sourceURL, let summary else { return }

        if !summary.onlyScrypt {
            do {
                try await BiometricGate.authenticate(reason: "Re-encrypt \"\(sourceName)\"")
            } catch BiometricGateError.userCancelled {
                return
            } catch {
                errorMessage = error.localizedDescription
                return
            }
        }

        stage = .working
        progressFraction = nil

        let usingPassphrase = summary.onlyScrypt
        let passphraseSnapshot = passphrase
        let recipientsSnapshot = recipients
        let armorSnapshot = armor
        let identitiesSnapshot: [any AgeIdentity] = usingPassphrase
            ? []
            : vault.identities.compactMap { try? $0.toAgeIdentity() }

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
                let description = String(describing: error)
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
