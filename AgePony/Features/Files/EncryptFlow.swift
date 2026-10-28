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
    @AppStorage("com.agepony.app.encrypt.armor") private var armor: Bool = true
    @State private var working: Bool = false
    /// Fraction of the input consumed, or nil before the first report.
    @State private var progressFraction: Double?
    @State private var errorMessage: String?
    @State private var resultURL: URL?
    @State private var signEnabled: Bool = false
    @State private var signingIdentityID: UUID?
    /// The in-app prompt, with the app password when Face ID only can't use Face ID (E6).
    @State private var ownerCheck = OwnerCheck()
    /// Whether the single output carries a signature sealed inside it. There is
    /// no second file to track any more -- 3.0 signs then encrypts.
    @State private var outputIsSigned: Bool = false

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
            .ownerCheck(ownerCheck, vault: vault)
            .navigationTitle("Encrypt a file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if stage == .done {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { finishAfterSuccess() }
                    }
                } else {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { cleanupAndDismiss() }
                    }
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
                        initiallySelectedRecipientIDs: vault.backupRecipientSelection,
                        initialUseScrypt: vault.sessionPassphrase != nil,
                        initialPassphrase: vault.sessionPassphrase ?? "",
                        onConfirm: { recipients, passphrase in
                            self.recipients = recipients
                            self.passphrase = passphrase
                            vault.sessionPassphrase = passphrase
                        },
                        onSaveRecipient: { try vault.addRecipient($0) }
                    )
                }
            }
            .onChange(of: signingAvailable) { _, available in
                // A signature covers exactly one output. Adding a second file,
                // or switching a multi-file batch to "encrypt separately", makes
                // signing impossible, and the Sign toggle is disabled in that
                // state -- so a value left on from an earlier single-file run
                // could not be switched back off by hand. That stranded signing
                // on and dead-ended runEncrypt in the sign path, which has no
                // single output to sign. Drop it the instant signing stops
                // being available so the toggle stays truthful and encrypt runs.
                if !available, signEnabled { signEnabled = false }
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
            return String(localized: "Add an SSH identity (Ed25519 or RSA) to sign. A signature proves the encrypted file came from you and wasn't changed in transit.")
        }
        if signEnabled {
            return String(localized: "The signature is sealed inside the encrypted file: only someone who can decrypt it sees who signed it. It's still a standard age file, and AgePony on iPhone or Android checks the signature when it decrypts.")
        }
        return String(localized: "Optionally attach a signature so the recipient can verify the file came from you.")
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
        Form {
            Section {
                Button("Choose files…") { showFilePicker = true }
            } footer: {
                Text("Any kind of file works. The encrypted copy gets a .age extension and can be shared anywhere. Choose several files to bundle them into one .tar.age or encrypt them one by one.")
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

    private var chooseModeStage: some View {
        Form {
            Section {
                LabeledContent("Files") {
                    Text(inputs.count, format: .number)
                }
                LabeledContent("Total size", value: ByteCountFormatter.string(fromByteCount: Int64(sourceSize), countStyle: .file))
            }

            Section {
                modeRow(
                    .archive,
                    title: "One archive",
                    detail: "Bundle everything into a single bundle.tar.age. The recipient unpacks it after decrypting."
                )
                modeRow(
                    .separate,
                    title: "One file each",
                    detail: "Encrypt every file on its own, producing \(inputs.count) .age files you can share individually."
                )
            } header: {
                Text("Output")
            }

            Section {
                Button("Continue") { stage = .configure }
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            }
        }
        .textCase(nil)
    }

    /// One choice in a single-choice list: the title and what it does, with a
    /// checkmark on the selected row.
    private func modeRow(_ mode: MultiMode, title: LocalizedStringKey, detail: LocalizedStringKey) -> some View {
        Button {
            multiMode = mode
        } label: {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .foregroundStyle(.primary)
                    Text(detail)
                        .font(AgePonyTypography.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
                if multiMode == mode {
                    Image(systemName: "checkmark")
                        .foregroundStyle(AgePonyColors.accent)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(multiMode == mode ? .isSelected : [])
    }

    private var configureStage: some View {
        Form {
            Section {
                if !inputs.isEmpty {
                    HStack {
                        Image(systemName: inputs.count == 1 ? "doc" : "doc.on.doc")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(sourceTitle)
                                .font(AgePonyTypography.body)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text(ByteCountFormatter.string(fromByteCount: Int64(sourceSize), countStyle: .file))
                                .font(AgePonyTypography.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Change") { showFilePicker = true }
                            .buttonStyle(.borderless)
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
            } header: {
                Text("Recipients")
            }

            Section {
                Toggle("Armor as text", isOn: $armor)
            } header: {
                Text("Format")
            } footer: {
                if armor {
                    Text("Output is text wrapped between BEGIN and END markers, safe to paste into chat, email, or anywhere that mangles binary.")
                } else {
                    Text("Output is binary: smaller, but it won't survive being pasted as text.")
                }
            }

            Section {
                Toggle("Also sign this file", isOn: $signEnabled)
                    .disabled(signingIdentities.isEmpty || !signingAvailable)
                if !signingAvailable {
                    Text("A signature covers one file. Choose \"One archive\" to sign the bundle.")
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.secondary)
                }
                if signEnabled, signingAvailable, !signingIdentities.isEmpty {
                    Picker("Sign with", selection: $signingIdentityID) {
                        ForEach(signingIdentities) { identity in
                            Text(KeyPickerText.menuLine(identity)).tag(Optional(identity.id))
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

            errorSection
        }
        .textCase(nil)
    }

    private var encryptingStage: some View {
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
                // No determinate progress yet: a passphrase encrypt sits here for
                // a second or two while scrypt runs before any bytes are read, and
                // the sign-then-encrypt path does not report progress yet.
                ProgressView()
                    .controlSize(.large)
            }
            Text("Encrypting…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var doneStage: some View {
        Form {
            Section {
                if batchResults.isEmpty {
                    StatusText("Encrypted", kind: .success, verdict: true)
                        .font(AgePonyTypography.headline)
                } else {
                    StatusText(batchHeadline, kind: batchSuccessURLs.count == batchResults.count ? .success : .warning, verdict: true)
                        .font(AgePonyTypography.headline)
                }
                if let url = resultURL {
                    LabeledContent("File") {
                        Text(url.lastPathComponent)
                            .font(AgePonyTypography.monoSmall)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
            } footer: {
                if outputIsSigned {
                    Text("Signed. The signature is sealed inside the file, so the ciphertext doesn't reveal the sender. Whoever decrypts it sees who sent it.")
                }
            }

            if !batchResults.isEmpty {
                batchResultSection
            }

            Section {
                if let url = resultURL {
                    ShareLink(item: url) {
                        Text("Share encrypted file")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                }
                if !batchSuccessURLs.isEmpty {
                    ShareLink(items: batchSuccessURLs) {
                        Group {
                            if batchSuccessURLs.count == 1 {
                                Text("Share encrypted file")
                            } else {
                                Text("Share ^[\(batchSuccessURLs.count) encrypted file](inflect: true)")
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                }
            }

            Section {
                Button("Encrypt another file") {
                    resetForAnother()
                }
            }
        }
        .textCase(nil)
        .onAppear {
            // We reached the success screen: count this toward a possible
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
        if ok == batchResults.count {
            return String(AttributedString(localized: "Encrypted ^[\(ok) file](inflect: true)").characters)
        }
        return String(localized: "Encrypted \(ok) of \(batchResults.count)")
    }

    private var batchSuccessURLs: [URL] {
        batchResults.compactMap(\.output)
    }

    /// Per-file outcome. A batch reports every file rather than failing whole,
    /// so a single unreadable input does not discard the rest.
    private var batchResultSection: some View {
        Section {
            ForEach(batchResults, id: \.source) { result in
                Label {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(result.source.lastPathComponent)
                            .font(AgePonyTypography.monoSmall)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if let error = result.error {
                            Text(describe(error))
                                .font(AgePonyTypography.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                } icon: {
                    Image(systemName: result.succeeded ? "checkmark.circle" : "exclamationmark.triangle")
                        .foregroundStyle(result.succeeded ? AgePonyColors.success : AgePonyColors.warning)
                }
            }
        } header: {
            Text("Files")
        }
    }

    private var canEncrypt: Bool {
        !inputs.isEmpty && (!recipients.isEmpty || passphrase?.isEmpty == false)
    }

    private var sourceTitle: String {
        if inputs.count == 1 { return inputs[0].lastPathComponent }
        if multiMode == .archive {
            return String(localized: "\(inputs.count) files in bundle.tar.age")
        }
        return String(localized: "\(inputs.count) files, encrypted separately")
    }

    /// Signing produces one detached signature over one file, so it only makes
    /// sense when the run yields a single output.
    private var signingAvailable: Bool {
        inputs.count == 1 || multiMode == .archive
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
            errorMessage = nil
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
            errorMessage = UserMessage.text(for: error, fallback: String(localized: "Couldn't open the files you picked."))
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
        if signEnabled && signingAvailable {
            runSignedEncrypt()
            return
        }
        guard !inputs.isEmpty else { return }
        errorMessage = nil
        stage = .encrypting
        working = true
        progressFraction = nil

        let inputsSnapshot = inputs
        let modeSnapshot = multiMode
        let workFactorSnapshot = vault.scryptWorkFactor
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
                        workFactor: workFactorSnapshot,
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
                            workFactor: workFactorSnapshot,
                            progress: onProgress
                        )
                    } else {
                        outURL = try FileEncryptor.encrypt(
                            inputURL: inputsSnapshot[0],
                            recipients: recipientsSnapshot,
                            passphrase: passphraseSnapshot,
                            armor: armorSnapshot,
                            workFactor: workFactorSnapshot,
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
        guard let source = signableInput(),
              let id = signingIdentityID,
              let identity = signingIdentities.first(where: { $0.id == id }) else { return }

        if vault.biometricEnabled {
            Task {
                do {
                    try await ownerCheck.authenticate(vault, reason: String(localized: "Sign \"\(source.url.lastPathComponent)\" with your private key."))
                    performSignedEncrypt(source: source, identity: identity)
                } catch BiometricGateError.userCancelled {
                    // Stay on the configure screen -- but the staged archive, if
                    // there was one, does not outlive the cancellation.
                    discardIfTemporary(source)
                } catch {
                    discardIfTemporary(source)
                    errorMessage = UserMessage.text(for: error, fallback: BiometricGate.didNotConfirmText)
                }
            }
        } else {
            performSignedEncrypt(source: source, identity: identity)
        }
    }

    private func discardIfTemporary(_ source: SignableInput) {
        if source.isTemporary { FileEncryptor.cleanupTempFile(at: source.url) }
    }

    /// What a signature would cover, and whether we made it.
    struct SignableInput {
        let url: URL
        /// True when this is a tar we staged and must therefore delete again.
        let isTemporary: Bool
    }

    /// The single file a signature would cover.
    ///
    /// One input signs itself. Several inputs in archive mode need the tar to
    /// exist, so it is streamed to a temp file here -- bounded memory, costing
    /// only disk. Separate-files mode has no single output and is gated out of
    /// signing before this is reached.
    private func signableInput() -> SignableInput? {
        if inputs.count == 1 { return SignableInput(url: inputs[0], isTemporary: false) }
        guard multiMode == .archive, !inputs.isEmpty else { return nil }
        do {
            return SignableInput(
                url: try FileEncryptor.buildArchiveFile(inputURLs: inputs),
                isTemporary: true
            )
        } catch {
            errorMessage = describe(error)
            return nil
        }
    }

    private func performSignedEncrypt(source: SignableInput, identity: StoredIdentity) {
        errorMessage = nil
        stage = .encrypting
        working = true
        progressFraction = nil

        let recipientsSnapshot = recipients
        let passphraseSnapshot = passphrase
        let armorSnapshot = armor
        let workFactorSnapshot = vault.scryptWorkFactor
        let url = source.url
        let isTemporary = source.isTemporary

        DispatchQueue.global(qos: .userInitiated).async {
            // A staged tar is an implementation detail of signing several files
            // at once; it goes whether the encrypt succeeded or not.
            defer { if isTemporary { FileEncryptor.cleanupTempFile(at: url) } }
            do {
                let onProgress: FileProgressHandler = { done, total in
                    guard total > 0 else { return }
                    let fraction = Double(done) / Double(total)
                    DispatchQueue.main.async { progressFraction = fraction }
                }

                let out = try SignEncryptService.signEncrypt(
                    inputURL: url,
                    recipients: recipientsSnapshot,
                    passphrase: passphraseSnapshot,
                    armor: armorSnapshot,
                    signingIdentity: identity,
                    workFactor: workFactorSnapshot,
                    progress: onProgress
                )
                DispatchQueue.main.async {
                    resultURL = out.encryptedURL
                    outputIsSigned = true
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
        outputIsSigned = false
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
        if let e = error as? SignEncryptError, case .requiresSecurityKey = e {
            return String(localized: "That identity signs with a security key, which Encrypt a file can't use yet. Sign the file from Sign a file instead.")
        }
        return UserMessage.text(for: error, fallback: String(localized: "Couldn't encrypt the file."))
    }
}
