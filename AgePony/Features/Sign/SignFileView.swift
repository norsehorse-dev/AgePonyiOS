//
//  SignFileView.swift
//  AgePony
//
//  Detached file-signing flow, presented as a sheet from the Files tab.
//  Stages mirror EncryptFlow: pick a file, choose a signing identity, sign,
//  then share the resulting `.sig`. If the user has no signing-capable
//  identity, an empty-state explains why and offers to mint an SSH key inline
//  (reusing GenerateIdentityView from B0, where the SSH option lives).
//
//  Signing uses the identity's private key, so when in-app biometric prompts
//  are enabled the sign step is gated by Face ID / Touch ID / passcode, the
//  same posture as revealing a private key.
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct SignFileView: View {

    let vault: Vault

    @State private var stage: Stage = .pickFile
    @State private var sourceURL: URL?
    @State private var sourceSize: Int = 0
    @State private var selectedIdentityID: UUID?
    @State private var working: Bool = false
    @State private var errorMessage: String?
    /// The in-app prompt, with the app password when Face ID only can't use Face ID (E6).
    @State private var ownerCheck = OwnerCheck()
    @State private var resultURL: URL?

    @State private var showFilePicker: Bool = false
    @State private var showCreateKey: Bool = false

    // Security-key PIN entry (shown only when a key reports PIN required).
    @State private var pinPromptVisible: Bool = false
    @State private var pinErrorText: String?
    @State private var pinSubmitting: Bool = false

    @Environment(\.dismiss) private var dismiss

    enum Stage {
        case pickFile
        case configure
        case signing
        case done
    }

    /// Identities that can sign: SSH Ed25519 (C0), SSH RSA (D0), Secure Enclave (E0).
    private var signingIdentities: [StoredIdentity] {
        vault.identities.filter { $0.canSign }
    }

    var body: some View {
        Group {
            if signingIdentities.isEmpty {
                noSigningKeyStage
            } else {
                contentForStage
            }
        }
        .ownerCheck(ownerCheck, vault: vault)
        .navigationTitle("Sign a file")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if stage == .done && !signingIdentities.isEmpty {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { finishAfterSuccess() }
                }
            } else {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { cleanupAndDismiss() }
                }
            }
        }
        .onAppear {
            if selectedIdentityID == nil {
                selectedIdentityID = defaultSigningIdentityID
            }
        }
        .fileImporter(
            isPresented: $showFilePicker,
            allowedContentTypes: [.data, .item],
            allowsMultipleSelection: false
        ) { result in
            handleFilePick(result)
        }
        .sheet(isPresented: $showCreateKey) {
            NavigationStack {
                GenerateIdentityView(vault: vault) {
                    showCreateKey = false
                    selectedIdentityID = defaultSigningIdentityID
                }
            }
        }
        .sheet(isPresented: $pinPromptVisible) {
            SecurityKeyPinPrompt(
                errorText: pinErrorText,
                submitting: pinSubmitting,
                onSubmit: { entered in
                    guard let url = sourceURL,
                          let id = selectedIdentityID,
                          let identity = signingIdentities.first(where: { $0.id == id }) else { return }
                    pinSubmitting = true
                    runSecurityKeySign(url: url, identity: identity, pin: entered)
                },
                onCancel: {
                    pinPromptVisible = false
                    pinSubmitting = false
                    stage = .configure
                    working = false
                }
            )
        }
    }

    // MARK: - Stages

    @ViewBuilder
    private var contentForStage: some View {
        switch stage {
        case .pickFile:  pickFileStage
        case .configure: configureStage
        case .signing:   signingStage
        case .done:      doneStage
        }
    }

    private var noSigningKeyStage: some View {
        ContentUnavailableView {
            Label("No signing key", systemImage: "signature")
        } description: {
            Text("Signing needs an SSH key or a Secure Enclave signing key. Your age identities can encrypt and decrypt, but they can't sign.")
        } actions: {
            Button("Create a signing key") { showCreateKey = true }
        }
    }

    private var pickFileStage: some View {
        Form {
            Section {
                Button("Choose a file…") { showFilePicker = true }
            } footer: {
                Text("AgePony makes a detached signature (a .sig file) to share alongside the original. It shows the file came from you and hasn't changed.")
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
            Section {
                if let url = sourceURL {
                    HStack {
                        Image(systemName: "doc")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(url.lastPathComponent)
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
                Picker("Signing identity", selection: $selectedIdentityID) {
                    ForEach(signingIdentities) { id in
                        Text(KeyPickerText.menuLine(id)).tag(Optional(id.id))
                    }
                }
                .pickerStyle(.menu)
            } header: {
                Text("Signed by")
            } footer: {
                Text("The signature is made with this identity's private key. Anyone you share the public key with can verify it.")
            }

            Section {
                HStack {
                    Text("Namespace")
                    Spacer()
                    Text(SSHSig.defaultNamespace)
                        .font(AgePonyTypography.monoCaption)
                        .foregroundStyle(.secondary)
                }
            } footer: {
                Text("Signatures are scoped to AgePony's namespace. To verify on the command line: ssh-keygen -Y verify -n \(SSHSig.defaultNamespace) ...")
            }

            Section {
                Button(action: startSign) {
                    Text("Sign")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(!canSign)
            }

            errorSection
        }
        .textCase(nil)
    }

    private var signingStage: some View {
        VStack(spacing: 16) {
            Spacer()
            ProgressView()
                .controlSize(.large)
            Text("Signing…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var doneStage: some View {
        Form {
            Section {
                StatusText("Signed", kind: .success, verdict: true)
                    .font(AgePonyTypography.headline)
                if let url = resultURL {
                    LabeledContent("Signature file") {
                        Text(url.lastPathComponent)
                            .font(AgePonyTypography.monoSmall)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                if let id = selectedIdentityID, let identity = signingIdentities.first(where: { $0.id == id }) {
                    LabeledContent("Signed by", value: identity.name)
                }
            } footer: {
                Text("Share the .sig file together with the original file.")
            }

            if let url = resultURL {
                Section {
                    ShareLink(item: url) {
                        Text("Share signature")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                }
            }

            Section {
                Button("Sign another file") {
                    resetForAnother()
                }
            }
        }
        .textCase(nil)
        .onAppear {
            ReviewPrompter.recordSuccessfulOperation()
        }
    }

    // MARK: - Helpers

    private var defaultSigningIdentityID: UUID? {
        if let active = vault.activeIdentity(), active.canSign {
            return active.id
        }
        return signingIdentities.first?.id
    }

    private var canSign: Bool {
        sourceURL != nil && selectedIdentityID != nil
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
        sourceURL = url
        stage = .configure
    }

    private func handleFilePick(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard let url = urls.first else { return }
            errorMessage = nil
            preloadFile(url)
        } catch {
            errorMessage = UserMessage.text(for: error, fallback: String(localized: "Couldn't open the file you picked."))
        }
    }

    private func startSign() {
        guard let url = sourceURL,
              let id = selectedIdentityID,
              let identity = signingIdentities.first(where: { $0.id == id }) else { return }

        if vault.biometricEnabled {
            Task {
                do {
                    try await ownerCheck.authenticate(vault, reason: String(localized: "Sign \"\(url.lastPathComponent)\" with your private key."))
                    runSign(url: url, identity: identity)
                } catch BiometricGateError.userCancelled {
                    // Stay on the configure screen.
                } catch {
                    errorMessage = UserMessage.text(for: error, fallback: BiometricGate.didNotConfirmText)
                }
            }
        } else {
            runSign(url: url, identity: identity)
        }
    }

    private func runSign(url: URL, identity: StoredIdentity) {
        errorMessage = nil
        if identity.isSecurityKey {
            runSecurityKeySign(url: url, identity: identity, pin: nil)
            return
        }
        stage = .signing
        working = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let out = try FileSigner.sign(inputURL: url, identity: identity)
                DispatchQueue.main.async {
                    resultURL = out
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

    /// Sign with an external security key over NFC. On the first try `pin` is
    /// nil; if the key reports PIN required (or a wrong PIN), the PIN sheet is
    /// shown and this is called again with the entered PIN.
    private func runSecurityKeySign(url: URL, identity: StoredIdentity, pin: String?) {
        stage = .signing
        working = true
#if canImport(CoreNFC)
        Task {
            do {
                let out = try await FileSigner.signWithSecurityKey(
                    inputURL: url, identity: identity, pin: pin)
                await MainActor.run {
                    pinPromptVisible = false
                    resultURL = out
                    stage = .done
                    working = false
                }
            } catch let e as SecurityKeyError where e.indicatesWrongPin {
                await MainActor.run {
                    pinErrorText = String(localized: "The PIN was incorrect. Try again.")
                    pinSubmitting = false
                    pinPromptVisible = true
                    stage = .configure
                    working = false
                }
            } catch let e as SecurityKeyError where e.indicatesPinRequired {
                await MainActor.run {
                    pinErrorText = nil
                    pinSubmitting = false
                    pinPromptVisible = true
                    stage = .configure
                    working = false
                }
            } catch {
                let description: String? = UserMessage.isCancellation(error) ? nil : describe(error)
                await MainActor.run {
                    pinPromptVisible = false
                    errorMessage = description
                    stage = .configure
                    working = false
                }
            }
        }
#else
        errorMessage = String(localized: "Security keys require NFC, which isn't available here.")
        stage = .configure
        working = false
#endif
    }

    private func resetForAnother() {
        if let url = resultURL { FileSigner.cleanupTempFile(at: url) }
        resultURL = nil
        sourceURL = nil
        sourceSize = 0
        stage = .pickFile
    }

    private func cleanupAndDismiss() {
        if let url = resultURL { FileSigner.cleanupTempFile(at: url) }
        dismiss()
    }

    private func finishAfterSuccess() {
        NotificationCenter.default.post(name: .agePonyOperationSucceeded, object: nil)
        cleanupAndDismiss()
    }

    private func describe(_ error: Error) -> String {
        UserMessage.text(for: error, fallback: String(localized: "Couldn't sign the file."))
    }
}
