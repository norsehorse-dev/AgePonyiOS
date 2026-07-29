//
//  EncryptFlow.swift
//  AgePony
//
//  Hotfix on 1g: runEncrypt no longer async. The previous version called
//  the synchronous FileEncryptor.encrypt from inside `Task { await ... }`
//  which inherited MainActor isolation and blocked the main thread for the
//  duration. With identity-based encrypt that's ~5ms — invisible. With
//  passphrase encrypt that's a 1-2 second scrypt run, long enough for the
//  iOS watchdog to terminate the process. Moved the work to
//  DispatchQueue.global(qos: .userInitiated) so the main thread stays
//  responsive throughout.
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct EncryptFlow: View {

    let vault: Vault
    let preloadedURL: URL?

    @State private var stage: Stage = .pickFile
    /// Everything the user picked: one file, or several.
    @State private var inputs: [URL] = []
    @State private var sourceSize: Int = 0
    /// Only meaningful when `inputs` holds more than one file.
    @State private var multiMode: MultiMode = .archive
    /// Set when a separate-files batch has run.
    @State private var batchDirectory: URL?
    @State private var batchResults: [FileEncryptor.BatchResult] = []
    @State private var recipients: [any AgeRecipient] = []
    @State private var passphrase: String?
    @State private var armor: Bool = true
    @State private var working: Bool = false
    /// Fraction of the input consumed, or nil before the first report.
    @State private var progressFraction: Double?
    @State private var errorMessage: String?
    @State private var resultURL: URL?
    @State private var signEnabled: Bool = false
    @State private var signingIdentityID: UUID?
    @State private var signatureURL: URL?

    @State private var showFilePicker: Bool = false
    @State private var showRecipientPicker: Bool = false

    @Environment(\.dismiss) private var dismiss

    enum Stage {
        case pickFile
        /// Shown only for multiple files: one archive, or one each.
        case chooseMode
        case configure
        case encrypting
        case done
    }

    enum MultiMode: Hashable {
        /// Bundle everything into a single .tar.age.
        case archive
        /// Produce one .age per input.
        case separate
    }

    init(vault: Vault, preloadedURL: URL? = nil) {
        self.vault = vault
        self.preloadedURL = preloadedURL
    }

    var body: some View {
        contentForStage
            .navigationTitle("Encrypt a file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { cleanupAndDismiss() }
                }
            }
            .task {
                if let url = preloadedURL, inputs.isEmpty {
                    preloadFile(url)
                }
            }
            .fileImporter(
                isPresented: $showFilePicker,
                allowedContentTypes: [.data, .item],
                allowsMultipleSelection: true
            ) { result in
                handleFilePick(result)
            }
            .sheet(isPresented: $showRecipientPicker) {
                NavigationStack {
                    RecipientPickerView(
                        identities: vault.identities,
                        savedRecipients: vault.recipients,
                        initiallySelectedIdentityIDs: defaultSelectedIdentityIDs,
                        onConfirm: { recipients, passphrase in
                            self.recipients = recipients
                            self.passphrase = passphrase
                        }
                    )
                }
            }
            .alert(
                "Encrypt failed",
                isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
            ) {
                Button("OK", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
            .onChange(of: signEnabled) { _, on in
                if on, signingIdentityID == nil {
                    signingIdentityID = defaultSigningIdentityID
                }
            }
    }

    // MARK: - Signing support (C3)

    private var signingIdentities: [StoredIdentity] {
        // Security keys sign over NFC (async); the combined encrypt-then-sign
        // flow is synchronous, so they're offered only in the standalone Sign
        // screen, not here.
        vault.identities.filter { $0.canSign && !$0.isSecurityKey }
    }

    private var defaultSigningIdentityID: UUID? {
        if let active = vault.activeIdentity(), active.canSign {
            return active.id
        }
        return signingIdentities.first?.id
    }

    private var signatureFooter: String {
        if signingIdentities.isEmpty {
            return "Add an SSH identity (Ed25519 or RSA) to sign. A signature proves the encrypted file came from you and wasn't changed in transit."
        }
        if signEnabled {
            return "Produces a detached .age.sig next to the encrypted file, signing the encrypted bytes. Share both so the recipient can verify."
        }
        return "Optionally attach a signature so the recipient can verify the file came from you."
    }

    @ViewBuilder
    private var contentForStage: some View {
        switch stage {
        case .pickFile:
            pickFileStage
        case .chooseMode:
            chooseModeStage
        case .configure:
            configureStage
        case .encrypting:
            encryptingStage
        case .done:
            doneStage
        }
    }

    private var pickFileStage: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "doc.badge.gearshape")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)
            Text("Pick a file to encrypt")
                .font(AgePonyTypography.title)
            Text("Any kind of file works. The encrypted result will have a .age extension and can be shared anywhere. Pick several files to bundle them into one .tar.age.")
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

    private var chooseModeStage: some View {
        VStack(spacing: 0) {
            VStack(spacing: 8) {
                Text("\(inputs.count) files selected")
                    .font(AgePonyTypography.title)
                Text(ByteCountFormatter.string(fromByteCount: Int64(sourceSize), countStyle: .file)
                     + " in total")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 32)
            .padding(.bottom, 24)

            VStack(spacing: 12) {
                modeOption(
                    .archive,
                    icon: "shippingbox",
                    title: "One archive",
                    detail: "Bundle everything into a single bundle.tar.age. The recipient unpacks it after decrypting."
                )
                modeOption(
                    .separate,
                    icon: "doc.on.doc",
                    title: "One file each",
                    detail: "Encrypt every file on its own, producing \(inputs.count) .age files you can share individually."
                )
            }
            .padding(.horizontal, 20)

            Spacer()

            Button("Continue") { stage = .configure }
                .buttonStyle(.agePonyPrimary)
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
        }
    }

    private func modeOption(_ mode: MultiMode, icon: String, title: String, detail: String) -> some View {
        Button {
            multiMode = mode
        } label: {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: icon)
                    .font(.system(size: 22))
                    .foregroundStyle(multiMode == mode ? AgePonyColors.tealCore : .secondary)
                    .frame(width: 28)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(AgePonyTypography.bodyEmph)
                        .foregroundStyle(.primary)
                    Text(detail)
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
                Image(systemName: multiMode == mode ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(multiMode == mode ? AgePonyColors.tealCore : .secondary)
            }
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color.secondary.opacity(multiMode == mode ? 0.14 : 0.06))
            )
        }
        .buttonStyle(.plain)
    }

    private var configureStage: some View {
        Form {
            Section {
                if !inputs.isEmpty {
                    HStack {
                        Image(systemName: inputs.count == 1 ? "doc" : "doc.on.doc")
                            .foregroundStyle(AgePonyColors.tealCore)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(sourceTitle)
                                .font(AgePonyTypography.bodyEmph)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text(ByteCountFormatter.string(fromByteCount: Int64(sourceSize), countStyle: .file))
                                .font(AgePonyTypography.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Change") { showFilePicker = true }
                            .font(AgePonyTypography.footnote)
                            .foregroundStyle(AgePonyColors.tealCore)
                    }
                }
            } header: {
                Text("Source")
            }

            Section {
                Button {
                    showRecipientPicker = true
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(recipientSummaryTitle)
                                .font(AgePonyTypography.bodyEmph)
                                .foregroundStyle(.primary)
                            Text(recipientSummarySubtitle)
                                .font(AgePonyTypography.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(.plain)
            } header: {
                Text("Recipients")
            }

            Section {
                Toggle("Armor as text", isOn: $armor)
            } header: {
                Text("Format")
            } footer: {
                Text(armor
                     ? "Output is text wrapped between BEGIN/END markers — safe to paste into chat, email, or anywhere that mangles binary."
                     : "Output is binary bytes — smaller, but won't survive being pasted as text.")
            }

            Section {
                Toggle("Also sign this file", isOn: $signEnabled)
                    .disabled(signingIdentities.isEmpty || !signingAvailable)
                if !signingAvailable {
                    Text("A signature covers one file. Choose \"One archive\" to sign the bundle.")
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(.secondary)
                }
                if signEnabled, signingAvailable, !signingIdentities.isEmpty {
                    Picker("Sign with", selection: $signingIdentityID) {
                        ForEach(signingIdentities) { identity in
                            Text(identity.name).tag(Optional(identity.id))
                        }
                    }
                }
            } header: {
                Text("Signature")
            } footer: {
                Text(signatureFooter)
            }

            Section {
                Button(action: runEncrypt) {
                    Text("Encrypt")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(!canEncrypt)
            }
        }
    }

    private var encryptingStage: some View {
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
                // No determinate progress yet: a passphrase encrypt sits here for
                // a second or two while scrypt runs before any bytes are read, and
                // the sign-then-encrypt path does not report progress yet.
                ProgressView()
                    .controlSize(.large)
                    .tint(AgePonyColors.tealCore)
            }
            Text("Encrypting…")
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
            Text(batchResults.isEmpty ? "Encrypted" : batchHeadline)
                .font(AgePonyTypography.title)
            if !batchResults.isEmpty {
                batchResultList
            }
            if let url = resultURL {
                Text(url.lastPathComponent)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            if let sig = signatureURL {
                Text("+ " + sig.lastPathComponent)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            VStack(spacing: 12) {
                if let age = resultURL, let sig = signatureURL {
                    ShareLink(items: [age, sig]) {
                        Text("Share file + signature")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                }
                if let url = resultURL, signatureURL == nil {
                    ShareLink(item: url) {
                        Text("Share encrypted file")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                }
                if !batchSuccessURLs.isEmpty {
                    ShareLink(items: batchSuccessURLs) {
                        Text(batchSuccessURLs.count == 1
                             ? "Share encrypted file"
                             : "Share \(batchSuccessURLs.count) encrypted files")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                }
                Button("Encrypt another") {
                    resetForAnother()
                }
                .buttonStyle(.agePonySecondary)
                Button("Done") {
                    finishAfterSuccess()
                }
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
        .onAppear {
            // We reached the success screen — count this toward a possible
            // contextual App Store review prompt later. Counting on appear
            // (rather than on Done) means "Encrypt another" sessions still
            // accrue credit for each file the user actually encrypted.
            ReviewPrompter.recordSuccessfulOperation()
        }
    }

    private var defaultSelectedIdentityIDs: Set<UUID> {
        guard vault.encryptToSelfDefault,
              let active = vault.activeIdentity(),
              active.canBeRecipient else {
            return []
        }
        return [active.id]
    }

    private var batchHeadline: String {
        let ok = batchResults.filter(\.succeeded).count
        if ok == batchResults.count { return "Encrypted \(ok) files" }
        return "Encrypted \(ok) of \(batchResults.count)"
    }

    private var batchSuccessURLs: [URL] {
        batchResults.compactMap(\.output)
    }

    /// Per-file outcome. A batch reports every file rather than failing whole,
    /// so a single unreadable input does not discard the rest.
    private var batchResultList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(batchResults, id: \.source) { result in
                    HStack(spacing: 8) {
                        Image(systemName: result.succeeded
                              ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(result.succeeded ? AgePonyColors.tealCore : .orange)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(result.source.lastPathComponent)
                                .font(AgePonyTypography.monoCaption)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            if let error = result.error {
                                Text(describe(error))
                                    .font(AgePonyTypography.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                        Spacer(minLength: 0)
                    }
                }
            }
            .padding(.horizontal, 24)
        }
        .frame(maxHeight: 220)
    }

    private var canEncrypt: Bool {
        !inputs.isEmpty && (!recipients.isEmpty || passphrase?.isEmpty == false)
    }

    private var sourceTitle: String {
        if inputs.count == 1 { return inputs[0].lastPathComponent }
        return multiMode == .archive
            ? "\(inputs.count) files → bundle.tar.age"
            : "\(inputs.count) files, encrypted separately"
    }

    /// Signing produces one detached signature over one file, so it only makes
    /// sense when the run yields a single output.
    private var signingAvailable: Bool {
        inputs.count == 1 || multiMode == .archive
    }

    private var recipientSummaryTitle: String {
        if passphrase?.isEmpty == false {
            return "Passphrase only"
        }
        if recipients.isEmpty {
            return "Choose recipients"
        }
        let n = recipients.count
        return n == 1 ? "1 recipient" : "\(n) recipients"
    }

    private var recipientSummarySubtitle: String {
        if passphrase?.isEmpty == false {
            return "Encrypted with a passphrase (scrypt)"
        }
        if recipients.isEmpty {
            return "Tap to add the people who can decrypt"
        }
        return "Tap to change"
    }

    private func preloadFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
           let size = attrs[.size] as? NSNumber {
            sourceSize = size.intValue
        } else {
            sourceSize = 0
        }
        inputs = [url]
        stage = .configure
    }

    private static func byteSize(of url: URL) -> Int {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.size] as? NSNumber)?.intValue ?? 0
    }

    private func handleFilePick(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard !urls.isEmpty else { return }
            if urls.count == 1 {
                preloadFile(urls[0])
            } else {
                // Ask rather than assume. Bundling everything was the old
                // behaviour and it is not always what the user wants.
                inputs = urls
                sourceSize = urls.reduce(0) { $0 + Self.byteSize(of: $1) }
                multiMode = .archive
                stage = .chooseMode
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// When several files are chosen, bundle them into a single uncompressed
    /// tar (`bundle.tar`) and feed that through the normal encrypt pipeline, so
    /// the result is one `bundle.tar.age`. Decrypting and running `tar -xf` (or
    /// any unarchiver) recovers the individual files.

    /// Synchronous-entry version of runEncrypt. The actual encrypt
    /// (potentially scrypt-bound) runs on a background queue so the main
    /// thread can keep updating UI during the spinner.
    private func runEncrypt() {
        if signEnabled {
            runSignedEncrypt()
            return
        }
        guard !inputs.isEmpty else { return }
        stage = .encrypting
        working = true
        progressFraction = nil

        let inputsSnapshot = inputs
        let modeSnapshot = multiMode
        let recipientsSnapshot = recipients
        let passphraseSnapshot = passphrase
        let armorSnapshot = armor

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let onProgress: FileProgressHandler = { done, total in
                    guard total > 0 else { return }
                    let fraction = Double(done) / Double(total)
                    DispatchQueue.main.async { progressFraction = fraction }
                }

                if inputsSnapshot.count > 1 && modeSnapshot == .separate {
                    let batch = try FileEncryptor.encryptEach(
                        inputURLs: inputsSnapshot,
                        recipients: recipientsSnapshot,
                        passphrase: passphraseSnapshot,
                        armor: armorSnapshot,
                        fileProgress: { done, total in
                            guard total > 0 else { return }
                            let fraction = Double(done) / Double(total)
                            DispatchQueue.main.async { progressFraction = fraction }
                        }
                    )
                    DispatchQueue.main.async {
                        batchDirectory = batch.directory
                        batchResults = batch.results
                        stage = .done
                        working = false
                    }
                } else {
                    let outURL: URL
                    if inputsSnapshot.count > 1 {
                        outURL = try FileEncryptor.encryptArchive(
                            inputURLs: inputsSnapshot,
                            recipients: recipientsSnapshot,
                            passphrase: passphraseSnapshot,
                            armor: armorSnapshot,
                            progress: onProgress
                        )
                    } else {
                        outURL = try FileEncryptor.encrypt(
                            inputURL: inputsSnapshot[0],
                            recipients: recipientsSnapshot,
                            passphrase: passphraseSnapshot,
                            armor: armorSnapshot,
                            progress: onProgress
                        )
                    }
                    DispatchQueue.main.async {
                        resultURL = outURL
                        stage = .done
                        working = false
                    }
                }
            } catch {
                let description = describe(error)
                DispatchQueue.main.async {
                    errorMessage = description
                    stage = .configure
                    working = false
                }
            }
        }
    }

    private func runSignedEncrypt() {
        guard let url = signableInput(),
              let id = signingIdentityID,
              let identity = signingIdentities.first(where: { $0.id == id }) else { return }

        if vault.biometricEnabled {
            Task {
                do {
                    try await BiometricGate.authenticate(reason: "Sign \"\(url.lastPathComponent)\" with your private key.")
                    performSignedEncrypt(url: url, identity: identity)
                } catch BiometricGateError.userCancelled {
                    // Stay on the configure screen.
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        } else {
            performSignedEncrypt(url: url, identity: identity)
        }
    }

    /// The single file a signature would cover.
    ///
    /// One input signs itself. Several inputs in archive mode need the tar to
    /// exist, so it is streamed to a temp file here -- bounded memory, costing
    /// only disk. Separate-files mode has no single output and is gated out of
    /// signing before this is reached.
    private func signableInput() -> URL? {
        if inputs.count == 1 { return inputs[0] }
        guard multiMode == .archive, !inputs.isEmpty else { return nil }
        do {
            return try FileEncryptor.buildArchiveFile(inputURLs: inputs)
        } catch {
            errorMessage = describe(error)
            return nil
        }
    }

    private func performSignedEncrypt(url: URL, identity: StoredIdentity) {
        stage = .encrypting
        working = true
        progressFraction = nil

        let recipientsSnapshot = recipients
        let passphraseSnapshot = passphrase
        let armorSnapshot = armor

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let out = try SignEncryptService.signEncrypt(
                    inputURL: url,
                    recipients: recipientsSnapshot,
                    passphrase: passphraseSnapshot,
                    armor: armorSnapshot,
                    signingIdentity: identity
                )
                DispatchQueue.main.async {
                    resultURL = out.encryptedURL
                    signatureURL = out.signatureURL
                    stage = .done
                    working = false
                }
            } catch {
                let description = describe(error)
                DispatchQueue.main.async {
                    errorMessage = description
                    stage = .configure
                    working = false
                }
            }
        }
    }

    private func resetForAnother() {
        cleanupOutputs()
        resultURL = nil
        signatureURL = nil
        inputs = []
        sourceSize = 0
        multiMode = .archive
        stage = .pickFile
    }

    /// Batch outputs share one directory, so they are removed as a directory.
    /// Calling cleanupTempFile on one of them would delete its siblings.
    private func cleanupOutputs() {
        if let dir = batchDirectory {
            FileEncryptor.cleanupTempDirectory(at: dir)
            batchDirectory = nil
            batchResults = []
        }
        if let url = resultURL { FileEncryptor.cleanupTempFile(at: url) }
    }

    private func cleanupAndDismiss() {
        cleanupOutputs()
        dismiss()
    }

    /// Done tapped from the success screen specifically (not Cancel). Posts
    /// the operation-succeeded notification so HomeView can consider a
    /// contextual review request once this sheet is gone, then dismisses.
    private func finishAfterSuccess() {
        NotificationCenter.default.post(name: .agePonyOperationSucceeded, object: nil)
        cleanupAndDismiss()
    }

    private func describe(_ error: Error) -> String {
        if let e = error as? FileEncryptorError {
            switch e {
            case .noRecipients:                return "No recipients selected."
            case .scryptCannotMixWithRecipients: return "Passphrase mode can't be combined with other recipients (age spec)."
            case .readFailed(let m):           return "Couldn't read input: \(m)"
            case .writeFailed(let m):          return "Couldn't write output: \(m)"
            case .ageError(let m):             return "Encrypt failed: \(m)"
            case .cannotOpenInput(let name):   return "Couldn't open \(name) for reading."
            case .cannotOpenOutput(let name):  return "Couldn't create \(name)."
            }
        }
        if let e = error as? FileSignerError {
            switch e {
            case .identityCannotSign:        return "That identity can't sign."
            case .keyTypeNotYetSupported:    return "That key type can't sign yet."
            case .malformedIdentityMaterial: return "The signing key looks malformed."
            case .readFailed(let m):         return "Couldn't read the file to sign: \(m)"
            case .writeFailed(let m):        return "Couldn't write the signature: \(m)"
            case .signError(let m):          return "Signing failed: \(m)"
            case .requiresSecurityKey:       return "This identity signs with your security key."
            }
        }
        if let e = error as? SignEncryptError {
            switch e {
            case .signingIdentityCannotSign: return "The chosen identity can't sign."
            case .relocateFailed(let m):     return "Couldn't finalize the signature: \(m)"
            }
        }
        return error.localizedDescription
    }
}
