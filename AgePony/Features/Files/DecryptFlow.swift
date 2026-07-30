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
//  After inspection the user sees a FileInfoCard summarising what the
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

    @State private var stage: Stage = .pickFile
    @State private var sourceURL: URL?
    @State private var sourceName: String = ""
    @State private var summary: AgeFileSummary?
    @State private var passphrase: String = ""
    @State private var working: Bool = false
    /// Fraction of the input consumed, or nil before the first report.
    @State private var progressFraction: Double?
    @State private var errorMessage: String?
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
            .navigationTitle("Decrypt a file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { cleanupAndDismiss() }
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
            .alert(
                "Decrypt failed",
                isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
            ) {
                Button("OK", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
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
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "lock.open")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)
            Text("Pick a .age file")
                .font(AgePonyTypography.title)
            Text("Decrypt with one of your stored identities, or with a passphrase for scrypt-encrypted files.")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Button("Pick from Files…") { showFilePicker = true }
                .buttonStyle(.agePonyPrimary)
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
        }
    }

    private var inspectingStage: some View {
        VStack(spacing: 18) {
            Spacer()
            ProgressView()
                .controlSize(.large)
                .tint(AgePonyColors.tealCore)
            Text("Reading file…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var readyStage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if let summary {
                    FileInfoCard(filename: sourceName, summary: summary)
                }

                if summary?.onlyScrypt == true {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Passphrase required")
                            .font(AgePonyTypography.headline)
                        Text("This file was encrypted with a passphrase. Enter it to decrypt.")
                            .font(AgePonyTypography.footnote)
                            .foregroundStyle(.secondary)
                        SecureField("Passphrase", text: $passphrase)
                            .font(AgePonyTypography.body)
                            .textInputAutocapitalization(.never)
                            .padding(12)
                            .background(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .fill(Color.secondary.opacity(0.08))
                            )
                    }
                } else if let summary, !summary.onlyScrypt {
                    Text("Tap **Decrypt** to authenticate with biometrics and reveal the plaintext.")
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.secondary)
                }

                Button {
                    Task { await runDecrypt() }
                } label: {
                    Text("Decrypt")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.agePonyPrimary)
                .disabled(!canDecrypt)
            }
            .padding(.horizontal, 16)
            .padding(.top, 16)
        }
    }

    private var decryptingStage: some View {
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
                ProgressView()
                    .controlSize(.large)
                    .tint(AgePonyColors.tealCore)
            }
            Text("Decrypting…")
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
            Text("Decrypted")
                .font(AgePonyTypography.title)
            if let url = resultURL {
                Text(url.lastPathComponent)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            // The signature is the last thing in a bundle, so its verdict can only
            // be known once the payload has already been written. A failed one has
            // to be shown loudly here -- the file exists either way, and a user who
            // sees only "Decrypted" would reasonably assume it was vouched for.
            if let signature {
                CompactVerifiedBadge(result: signature)
                    .padding(.top, 6)
            }
            Spacer()
            VStack(spacing: 12) {
                if let url = resultURL {
                    ShareLink(item: url) {
                        Text("Share decrypted file")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                }
                Button("Done") {
                    cleanupAndDismiss()
                }
                .buttonStyle(.agePonySecondary)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
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
            errorMessage = error.localizedDescription
        }
    }

    private func handlePicked(url: URL) {
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

    private func runDecrypt() async {
        guard let summary, let url = sourceURL else { return }

        // Authenticate first, on the main actor, before any heavy work begins.
        // The passphrase path needs no biometric: the passphrase is itself the
        // authentication. The identity path prompts before private material is
        // used, even though the master key is already in memory — defence in
        // depth, and a signal to the user that something is being unlocked.
        if !summary.onlyScrypt {
            do {
                try await BiometricGate.authenticate(reason: "Decrypt \"\(sourceName)\"")
            } catch BiometricGateError.userCancelled {
                return
            } catch {
                errorMessage = describeDecrypt(error)
                return
            }
        }

        stage = .decrypting
        working = true
        progressFraction = nil

        let usingPassphrase = summary.onlyScrypt
        let passphraseSnapshot = passphrase
        let identitiesSnapshot: [any AgeIdentity] = usingPassphrase
            ? []
            : vault.identities.compactMap { try? $0.toAgeIdentity() }

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

                let verdict = outcome.signedBundle.map {
                    FileVerifier.verify(
                        bundle: $0,
                        identities: storedIdentities,
                        recipients: storedRecipients,
                        signers: storedSigners
                    )
                }

                DispatchQueue.main.async {
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
        if let e = error as? AgeFileInspectorError {
            switch e {
            case .notAnAgeFile:          return "This file isn't an age-encrypted file."
            case .malformedArmor:        return "The armored block is malformed."
            case .headerParseFailed(let m): return "Couldn't parse the age header: \(m)"
            case .cannotOpenFile(let name): return "Couldn't open \(name)."
            }
        }
        return error.localizedDescription
    }

    private func describeDecrypt(_ error: Error) -> String {
        if let e = error as? FileEncryptorError {
            switch e {
            case .ageError(let m):
                if m.contains("wrongPassphrase") { return "Wrong passphrase." }
                if m.contains("noMatchingIdentity") {
                    return "No identity in this vault can decrypt this file."
                }
                return "Decrypt failed: \(m)"
            case .readFailed(let m):  return "Couldn't read input: \(m)"
            case .bundleDamaged(let m): return "This file decrypted, but the signed bundle inside it is damaged: \(m)"
            case .writeFailed(let m): return "Couldn't write output: \(m)"
            default:                  return String(describing: e)
            }
        }
        if let e = error as? BiometricGateError {
            switch e {
            case .unavailable:       return "Biometric authentication is unavailable."
            case .userCancelled:     return ""
            case .failed(let m):     return m
            }
        }
        return error.localizedDescription
    }
}
