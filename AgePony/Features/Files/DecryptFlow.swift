//
//  DecryptFlow.swift
//  AgePony
//
//  Orchestrates the decrypt path. Two entry points:
//
//    1. Manual: user picks a .age via the Files tab. Stage starts at
//       .pickFile, document picker opens, we read the bytes and
//       inspect immediately.
//
//    2. External: a .age opens from outside the app (Files.app share,
//       Mail attachment, Messages…). DecryptFlow is presented as a sheet
//       with `preloadedURL` set, skipping the pickFile stage and going
//       straight to inspect.
//
//  After inspection the user sees a FileInfoSection summarising what the
//  file is. They authorize the decrypt with the Decrypt button, which
//  fires a biometric prompt (or asks for a passphrase, if the file is
//  scrypt-only) and then surfaces a ShareLink to the plaintext result.
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct DecryptFlow: View {

    let vault: Vault
    /// When non-nil, skips the picker and starts inspecting this file on
    /// appear. Used for external `.age` opens via `.onOpenURL`.
    let preloadedURL: URL?

    /// Outlives the view, so a decrypt that finishes after the flow is gone can tell (M-7).
    @State private var lifetime = FlowLifetime()
    @State private var stage: Stage = .pickFile
    @State private var sourceURL: URL?
    @State private var sourceName: String = ""
    @State private var summary: AgeFileSummary?
    @State private var passphrase: String = ""
    @State private var working: Bool = false
    /// Fraction of the input consumed, or nil before the first report.
    @State private var progressFraction: Double?
    @State private var errorMessage: String?
    /// The YubiKey PIN prompt's answer, for the next `prepare` call only (5.1.0:
    /// asked before the tap). Dropped as soon as `prepare` returns.
    @State private var yubiKeyPIN: YubiKeyPINEntry?
    /// The in-app prompt, with the app password when Face ID only can't use Face ID (E6).
    @State private var ownerCheck = OwnerCheck()
    @State private var showYubiKeyPIN = false
    @State private var yubiKeyPINNote: String?
    @State private var yubiKeyOffersNoPIN = false
    @State private var resultURL: URL?
    /// The verdict on a signed bundle's signature, when the file carried one.
    @State private var signature: FileVerificationResult?

    @State private var showFilePicker: Bool = false

    @Environment(\.dismiss) private var dismiss

    enum Stage {
        case pickFile
        case inspecting
        case ready          // summary populated, user can decrypt
        case decrypting
        case done
    }

    init(vault: Vault, preloadedURL: URL? = nil) {
        self.vault = vault
        self.preloadedURL = preloadedURL
    }

    var body: some View {
        contentForStage
            .ownerCheck(ownerCheck, vault: vault)
            .navigationTitle("Decrypt a file")
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
            .task {
                if let url = preloadedURL, sourceURL == nil {
                    handlePicked(url: url)
                }
            }
            .fileImporter(
                isPresented: $showFilePicker,
                allowedContentTypes: ageContentTypes,
                allowsMultipleSelection: false
            ) { result in
                handleFilePick(result)
            }
            .yubiKeyPINPrompt(isPresented: $showYubiKeyPIN, note: yubiKeyPINNote, offersNoPIN: yubiKeyOffersNoPIN) { pin in
                yubiKeyPIN = pin
                Task { await runDecrypt(afterPIN: true) }
            }
            .onDisappear {
                // However the flow goes away (swipe, lock, a new share), the
                // plaintext it wrote goes with it (M-7).
                lifetime.gone = true
                if let url = resultURL { FileEncryptor.cleanupTempFile(at: url) }
            }
    }

    // MARK: - Stage routing

    @ViewBuilder
    private var contentForStage: some View {
        switch stage {
        case .pickFile:
            pickFileStage
        case .inspecting:
            inspectingStage
        case .ready:
            readyStage
        case .decrypting:
            decryptingStage
        case .done:
            doneStage
        }
    }

    private var pickFileStage: some View {
        Form {
            Section {
                Button("Choose a .age file…") { showFilePicker = true }
            } footer: {
                Text("Decrypt with one of your identities, or with the passphrase for a file that was encrypted with one.")
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

    private var inspectingStage: some View {
        VStack(spacing: 16) {
            Spacer()
            ProgressView()
                .controlSize(.large)
            Text("Reading file…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var readyStage: some View {
        Form {
            if let summary {
                FileInfoSection(filename: sourceName, summary: summary)
            }

            if summary?.onlyScrypt == true {
                Section {
                    SecureField("Passphrase", text: $passphrase)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } header: {
                    Text("Passphrase")
                } footer: {
                    Text("This file was encrypted with a passphrase.")
                }
            }

            Section {
                Button {
                    Task { await runDecrypt() }
                } label: {
                    Text("Decrypt")
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(!canDecrypt)
            } footer: {
                if summary?.onlyScrypt == false {
                    Text("AgePony asks for Face ID or your passcode before it uses your keys.")
                }
            }

            errorSection
        }
        .textCase(nil)
    }

    private var decryptingStage: some View {
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
                ProgressView()
                    .controlSize(.large)
            }
            Text("Decrypting…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var doneStage: some View {
        Form {
            Section {
                StatusText("Decrypted", kind: .success, verdict: true)
                    .font(AgePonyTypography.headline)
                if let url = resultURL {
                    LabeledContent("File") {
                        Text(url.lastPathComponent)
                            .font(AgePonyTypography.monoSmall)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
            } footer: {
                Text("The decrypted copy is deleted from this iPhone when you close this screen.")
            }

            // The signature is the last thing in a bundle, so its verdict can only
            // be known once the payload has already been written. A failed one has
            // to be shown here: the file exists either way, and a user who sees
            // only "Decrypted" would reasonably assume it was vouched for.
            if let signature {
                Section {
                    CompactVerifiedBadge(result: signature)
                } header: {
                    Text("Signature")
                }
            }

            if let url = resultURL {
                Section {
                    PlaintextShareButton(url: url)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }
            }
        }
        .textCase(nil)
    }

    // MARK: - Logic

    private var ageContentTypes: [UTType] {
        // Prefer the imported UTI we declared in Info.plist, fall back to
        // .data which always exists. Document picker shows both .age and
        // any-data so opening a renamed/anonymous file still works.
        if let age = UTType("org.age-encryption.age") {
            return [age, .data]
        }
        return [.data]
    }

    private var canDecrypt: Bool {
        guard let summary else { return false }
        if summary.onlyScrypt {
            return !passphrase.isEmpty
        }
        return !vault.identities.isEmpty
    }

    private func handleFilePick(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard let url = urls.first else { return }
            handlePicked(url: url)
        } catch {
            errorMessage = UserMessage.text(for: error, fallback: String(localized: "Couldn't open the file you picked."))
        }
    }

    private func handlePicked(url: URL) {
        errorMessage = nil
        sourceURL = url
        sourceName = url.lastPathComponent
        // A verdict belongs to one file. Picking another must not leave the
        // previous file's badge on screen.
        signature = nil
        resultURL = nil
        stage = .inspecting
        Task { await runInspect() }
    }

    private func runInspect() async {
        guard let url = sourceURL else { return }
        do {
            // Header only: instant on a file of any size, and holds nothing but
            // the header. The whole file used to be read here, converted to a
            // String to sniff for armor, decoded, and then kept alive in view
            // state until the screen went away.
            summary = try AgeFileInspector.inspect(
                fileURL: url,
                knownIdentities: vault.identities
            )
            stage = .ready
        } catch {
            errorMessage = describeInspect(error)
            stage = .pickFile
        }
    }

    private func runDecrypt(afterPIN: Bool = false) async {
        // The PIN is used for this one attempt at most; no early return keeps it.
        let pinEntry = yubiKeyPIN
        yubiKeyPIN = nil
        guard let summary, let url = sourceURL else { return }
        errorMessage = nil

        // Authenticate first, on the main actor, before any heavy work begins.
        // The passphrase path needs no biometric: the passphrase is itself the
        // authentication. The identity path prompts before private material is
        // used, even though the master key is already in memory — defence in
        // depth, and a signal to the user that something is being unlocked.
        if !summary.onlyScrypt && !afterPIN {
            do {
                try await ownerCheck.authenticate(vault, reason: String(localized: "Decrypt \"\(sourceName)\""))
            } catch BiometricGateError.userCancelled {
                return
            } catch {
                errorMessage = describeDecrypt(error)
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

        stage = .decrypting
        working = true
        progressFraction = nil

        let usingPassphrase = summary.onlyScrypt
        let passphraseSnapshot = passphrase

        // Snapshot the vault for signer attribution too: if the plaintext turns
        // out to be a signed bundle, the verdict is worked out on the background
        // thread rather than reaching back onto the main actor for it.
        let storedIdentities = vault.identities
        let storedRecipients = vault.recipients
        let storedSigners = vault.signers

        // Off the main thread. Files of any size decrypt now, and a large one
        // run inline would block the UI long enough for the iOS watchdog to
        // terminate the app — the same reason EncryptFlow dispatches.
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let outcome = try FileEncryptor.decrypt(
                    inputURL: url,
                    identities: identitiesSnapshot,
                    passphrase: usingPassphrase ? passphraseSnapshot : nil,
                    progress: { done, total in
                        guard total > 0 else { return }
                        let fraction = Double(done) / Double(total)
                        DispatchQueue.main.async { progressFraction = fraction }
                    }
                )

                // A signed bundle (passphrase files, and every iOS file before
                // 5.0.1), or a signature stanza in the header (key files from
                // 5.0.1 on, both platforms).
                let verdict = outcome.signedBundle.map {
                    FileVerifier.verify(
                        bundle: $0,
                        identities: storedIdentities,
                        recipients: storedRecipients,
                        signers: storedSigners
                    )
                } ?? FileVerifier.verify(
                    stanza: outcome.signatureStanza,
                    plaintextURL: outcome.url,
                    identities: storedIdentities,
                    recipients: storedRecipients,
                    signers: storedSigners
                )

                DispatchQueue.main.async {
                    // The flow went away while this decrypt ran (Cancel, swipe, lock):
                    // nothing will show or clean up this file, so delete it now (M-7).
                    if lifetime.gone {
                        try? FileManager.default.removeItem(at: outcome.url)
                        return
                    }
                    resultURL = outcome.url
                    signature = verdict
                    stage = .done
                    working = false
                    progressFraction = nil
                }
            } catch {
                let description = describeDecrypt(error)
                DispatchQueue.main.async {
                    errorMessage = description
                    stage = .ready
                    working = false
                    progressFraction = nil
                }
            }
        }
    }

    private func cleanupAndDismiss() {
        if let url = resultURL { FileEncryptor.cleanupTempFile(at: url) }
        dismiss()
    }

    private func describeInspect(_ error: Error) -> String {
        if let e = error as? AgeFileInspectorError, case .notAnAgeFile = e {
            return String(localized: "This file isn't age-encrypted.")
        }
        return UserMessage.text(for: error, fallback: String(localized: "Couldn't read the file's age header."))
    }

    /// Nil when the person cancelled, so nothing is shown.
    private func describeDecrypt(_ error: Error) -> String? {
        if UserMessage.isCancellation(error) { return nil }
        return UserMessage.text(for: error, fallback: String(localized: "Couldn't decrypt the file."))
    }
}

/// Set when a flow goes away, read by work that may finish afterwards.
final class FlowLifetime {
    var gone = false
}
