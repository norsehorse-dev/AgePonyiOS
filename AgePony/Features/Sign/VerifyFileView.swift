//
//  VerifyFileView.swift
//  AgePony
//
//  Verification flow, presented as a sheet from the Files tab. The user picks
//  the original file and its detached `.sig`, AgePony verifies, and the result
//  is shown with the VerifiedBadge. No private key is used, so there's no
//  biometric gate here.
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct VerifyFileView: View {

    let vault: Vault

    @State private var stage: Stage = .pickInputs
    @State private var fileURL: URL?
    @State private var signatureURL: URL?
    @State private var result: FileVerificationResult?
    @State private var errorMessage: String?
    @State private var showAddSigner: Bool = false

    @State private var showImporter: Bool = false
    @State private var importTarget: ImportTarget = .file

    @Environment(\.dismiss) private var dismiss

    enum Stage {
        case pickInputs
        case verifying
        case result
    }

    enum ImportTarget {
        case file
        case signature
    }

    var body: some View {
        contentForStage
            .navigationTitle("Verify a file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .fileImporter(
                isPresented: $showImporter,
                allowedContentTypes: [.data, .item],
                allowsMultipleSelection: false
            ) { res in
                handleImport(res)
            }
            .alert(
                "Verify failed",
                isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
            ) {
                Button("OK", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
            .sheet(isPresented: $showAddSigner) {
                if let prefill = signerPrefill {
                    NavigationStack {
                        AddSignerView(
                            vault: vault,
                            mode: prefill,
                            source: .fromVerification
                        ) {
                            // Re-verify so the badge updates to "trusted".
                            startVerify()
                        }
                    }
                }
            }
    }

    // MARK: - Add-signer support

    private var canAddSigner: Bool {
        guard let result else { return false }
        if case .validUnknownKey = result.trust, result.signerPublicKeyWire != nil {
            return true
        }
        return false
    }

    private var signerPrefill: AddSignerView.Mode? {
        guard let result,
              let wire = result.signerPublicKeyWire,
              let keyType = result.signerKeyType else { return nil }
        return .prefilled(keyType: keyType, wire: wire, suggestedName: "")
    }

    @ViewBuilder
    private var contentForStage: some View {
        switch stage {
        case .pickInputs: pickInputsStage
        case .verifying:  verifyingStage
        case .result:     resultStage
        }
    }

    private var pickInputsStage: some View {
        Form {
            Section {
                inputRow(
                    title: "File",
                    placeholder: "Pick the original file",
                    url: fileURL,
                    target: .file
                )
                inputRow(
                    title: "Signature",
                    placeholder: "Pick the .sig file",
                    url: signatureURL,
                    target: .signature
                )
            } header: {
                Text("Inputs")
            } footer: {
                Text("Pick the file and the detached signature that came with it. AgePony checks that the signature matches the file and tells you who signed it.")
            }

            Section {
                Button(action: startVerify) {
                    Text("Verify")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(fileURL == nil || signatureURL == nil)
            }
        }
    }

    private func inputRow(title: String, placeholder: String, url: URL?, target: ImportTarget) -> some View {
        Button {
            importTarget = target
            showImporter = true
        } label: {
            HStack {
                Image(systemName: url == nil ? "doc.badge.plus" : "doc")
                    .foregroundStyle(AgePonyColors.tealCore)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(AgePonyTypography.bodyEmph)
                        .foregroundStyle(.primary)
                    Text(url?.lastPathComponent ?? placeholder)
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
    }

    private var verifyingStage: some View {
        VStack(spacing: 18) {
            Spacer()
            ProgressView()
                .controlSize(.large)
                .tint(AgePonyColors.tealCore)
            Text("Verifying…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var resultStage: some View {
        VStack(spacing: 18) {
            Spacer()
            if let result {
                VerifiedBadge(result: result)
            }
            Spacer()
            VStack(spacing: 12) {
                if canAddSigner {
                    Button("Add as trusted signer") {
                        showAddSigner = true
                    }
                    .buttonStyle(.agePonyPrimary)
                    Button("Verify another") {
                        resetForAnother()
                    }
                    .buttonStyle(.agePonySecondary)
                } else {
                    Button("Verify another") {
                        resetForAnother()
                    }
                    .buttonStyle(.agePonyPrimary)
                }
                Button("Done") {
                    dismiss()
                }
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 40)
        }
    }

    // MARK: - Actions

    private func handleImport(_ res: Result<[URL], Error>) {
        do {
            let urls = try res.get()
            guard let url = urls.first else { return }
            switch importTarget {
            case .file:      fileURL = url
            case .signature: signatureURL = url
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func startVerify() {
        guard let fileURL, let signatureURL else { return }
        stage = .verifying
        let identities = vault.identities
        let recipients = vault.recipients
        let signers = vault.signers
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = FileVerifier.verify(
                fileURL: fileURL,
                signatureURL: signatureURL,
                identities: identities,
                recipients: recipients,
                signers: signers
            )
            DispatchQueue.main.async {
                result = outcome
                stage = .result
            }
        }
    }

    private func resetForAnother() {
        fileURL = nil
        signatureURL = nil
        result = nil
        stage = .pickInputs
    }
}
