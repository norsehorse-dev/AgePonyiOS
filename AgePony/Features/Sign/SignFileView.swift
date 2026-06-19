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
        .navigationTitle("Sign a file")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { cleanupAndDismiss() }
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
        .alert(
            "Sign failed",
            isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
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
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "signature")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)
            Text("No signing key yet")
                .font(AgePonyTypography.title)
            Text("Signing needs an SSH key. Your age (X25519) identities can encrypt and decrypt, but only an SSH key can produce a signature. Create one and pick \"SSH key\" when prompted.")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Button("Create an SSH key") { showCreateKey = true }
                .buttonStyle(.agePonyPrimary)
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
        }
    }

    private var pickFileStage: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "doc.badge.ellipsis")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)
            Text("Pick a file to sign")
                .font(AgePonyTypography.title)
            Text("AgePony produces a detached signature (a .sig file) you can share alongside the original. It proves the file came from you and hasn't changed.")
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

    private var configureStage: some View {
        Form {
            Section {
                if let url = sourceURL {
                    HStack {
                        Image(systemName: "doc")
                            .foregroundStyle(AgePonyColors.tealCore)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(url.lastPathComponent)
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
                Picker("Signing identity", selection: $selectedIdentityID) {
                    ForEach(signingIdentities) { id in
                        Text(id.name).tag(Optional(id.id))
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
        }
    }

    private var signingStage: some View {
        VStack(spacing: 18) {
            Spacer()
            ProgressView()
                .controlSize(.large)
                .tint(AgePonyColors.tealCore)
            Text("Signing…")
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
            Text("Signed")
                .font(AgePonyTypography.title)
            if let url = resultURL {
                Text(url.lastPathComponent)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            VStack(spacing: 12) {
                if let url = resultURL {
                    ShareLink(item: url) {
                        Text("Share signature")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.agePonyPrimary)
                }
                Button("Sign another") {
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
            preloadFile(url)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func startSign() {
        guard let url = sourceURL,
              let id = selectedIdentityID,
              let identity = signingIdentities.first(where: { $0.id == id }) else { return }

        if vault.biometricEnabled {
            Task {
                do {
                    try await BiometricGate.authenticate(reason: "Sign \"\(url.lastPathComponent)\" with your private key.")
                    runSign(url: url, identity: identity)
                } catch BiometricGateError.userCancelled {
                    // Stay on the configure screen.
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
        } else {
            runSign(url: url, identity: identity)
        }
    }

    private func runSign(url: URL, identity: StoredIdentity) {
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
                    pinErrorText = "The PIN was incorrect. Try again."
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
                let description = describe(error)
                await MainActor.run {
                    pinPromptVisible = false
                    errorMessage = description
                    stage = .configure
                    working = false
                }
            }
        }
#else
        errorMessage = "Security keys require NFC, which isn't available here."
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
        if let e = error as? FileSignerError {
            switch e {
            case .identityCannotSign:          return "That identity can't sign. Use an SSH key."
            case .keyTypeNotYetSupported:
                return "That key type isn't supported for signing yet."
            case .malformedIdentityMaterial:   return "The identity's key material looks corrupted."
            case .readFailed(let m):           return "Couldn't read the file: \(m)"
            case .writeFailed(let m):          return "Couldn't write the signature: \(m)"
            case .signError(let m):            return "Signing failed: \(m)"
            case .requiresSecurityKey:         return "This identity signs with your security key — tap it to sign."
            }
        }
        return error.localizedDescription
    }
}
