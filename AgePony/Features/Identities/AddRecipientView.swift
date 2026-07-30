//
//  AddRecipientView.swift
//  AgePony
//
//  Add a recipient to the vault. Three import paths, picked via a
//  segmented control at the top of the sheet:
//
//      • Paste    — paste an age1... string or an ssh-* AAAA… line
//      • Scan     — camera-based QR scanner (the scanned string is parsed
//                   with the same parser the paste path uses)
//      • GitHub   — fetch from https://github.com/<user>.keys
//
//  Parsed candidates appear in a "Found" section. Each row has a name
//  field and a toggle. Save persists every selected row to the Vault.
//

import SwiftUI
import AgePonyCore

struct AddRecipientView: View {

    let vault: Vault
    let onDone: () -> Void

    @State private var mode: RecipientImportService.UIImportSource = .paste

    // Paste path
    @State private var pasteText: String = ""
    @State private var pasteError: String?

    // GitHub path
    @State private var githubUsername: String = ""
    @State private var githubError: String?
    @State private var githubLoading: Bool = false

    // QR path
    @State private var showScanner: Bool = false
    @State private var qrError: String?

    // Shared candidate list
    @State private var candidates: [EditableCandidate] = []
    @State private var saveError: String?
    @State private var saving: Bool = false

    @Environment(\.dismiss) private var dismiss

    /// A candidate plus the user's per-row edits.
    private struct EditableCandidate: Identifiable {
        let id: UUID = UUID()
        var name: String
        var include: Bool
        let candidate: RecipientImportCandidate
        let source: StoredRecipientSource
        let sourceMetadata: String?
    }

    var body: some View {
        Form {
            sourceSection
            inputSection
            if !candidates.isEmpty {
                candidatesSection
                saveSection
            }
        }
        .navigationTitle("Add recipient")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
        .fullScreenCover(isPresented: $showScanner) {
            QRScannerHostView(
                onDetect: { value in
                    showScanner = false
                    handleScannedValue(value)
                },
                onCancel: { showScanner = false },
                onError: { err in
                    showScanner = false
                    qrError = describeQRError(err)
                }
            )
        }
        .alert(
            "Save failed",
            isPresented: Binding(get: { saveError != nil }, set: { if !$0 { saveError = nil } })
        ) {
            Button("OK", role: .cancel) { saveError = nil }
        } message: {
            Text(saveError ?? "")
        }
    }

    // MARK: - Sections

    private var sourceSection: some View {
        Section {
            Picker("Source", selection: $mode) {
                Text("Paste").tag(RecipientImportService.UIImportSource.paste)
                Text("Scan").tag(RecipientImportService.UIImportSource.qr)
                Text("GitHub").tag(RecipientImportService.UIImportSource.github)
            }
            .pickerStyle(.segmented)
        }
    }

    @ViewBuilder
    private var inputSection: some View {
        switch mode {
        case .paste:  pasteInputSection
        case .qr:     qrInputSection
        case .github: githubInputSection
        }
    }

    private var pasteInputSection: some View {
        Section {
            TextField("age1... or ssh-ed25519 / ssh-rsa AAAA...", text: $pasteText, axis: .vertical)
                .font(AgePonyTypography.monoCaption)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .lineLimit(2...8)

            if let msg = pasteError {
                Text(msg)
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(AgePonyColors.destructive)
            }

            Button {
                parsePaste()
            } label: {
                Label("Parse", systemImage: "checkmark.circle")
                    .font(AgePonyTypography.footnote)
            }
            .foregroundStyle(AgePonyColors.tealCore)
            .disabled(pasteText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        } header: {
            Text("Paste a public key")
        } footer: {
            Text("Paste an `age1...` recipient string, or a one-line OpenSSH public key (`ssh-ed25519 AAAA... user@host`).")
        }
    }

    private var qrInputSection: some View {
        Section {
            Button {
                qrError = nil
                showScanner = true
            } label: {
                Label("Open camera and scan", systemImage: "qrcode.viewfinder")
                    .font(AgePonyTypography.body)
            }
            .foregroundStyle(AgePonyColors.tealCore)

            if let msg = qrError {
                Text(msg)
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(AgePonyColors.destructive)
            }
        } header: {
            Text("Scan a QR code")
        } footer: {
            Text("The QR's text content is parsed as if you'd pasted it — `age1...` strings and `ssh-*` lines both work.")
        }
    }

    private var githubInputSection: some View {
        Section {
            HStack {
                Text("github.com /")
                    .foregroundStyle(.secondary)
                    .font(AgePonyTypography.footnote)
                TextField("username", text: $githubUsername)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(AgePonyTypography.body)
            }

            if let msg = githubError {
                Text(msg)
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(AgePonyColors.destructive)
            }

            Button {
                Task { await fetchGitHub() }
            } label: {
                if githubLoading {
                    HStack {
                        ProgressView()
                        Text("Fetching…")
                    }
                    .font(AgePonyTypography.footnote)
                } else {
                    Label("Fetch", systemImage: "arrow.down.circle")
                        .font(AgePonyTypography.footnote)
                }
            }
            .foregroundStyle(AgePonyColors.tealCore)
            .disabled(githubUsername.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || githubLoading)
        } header: {
            Text("Fetch from GitHub")
        } footer: {
            Text("Fetches keys from `https://github.com/<username>.keys`. AgePony reads only ed25519 and RSA SSH public keys; other types are skipped. Your network sees the GitHub request but no AgePony account is used.")
        }
    }

    private var candidatesSection: some View {
        Section {
            ForEach($candidates) { $candidate in
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 12) {
                        Toggle("", isOn: $candidate.include)
                            .labelsHidden()
                        VStack(alignment: .leading, spacing: 2) {
                            Text(typeLabel(candidate.candidate.type))
                                .font(AgePonyTypography.caption)
                                .foregroundStyle(.secondary)
                            TextField("Name", text: $candidate.name)
                                .textInputAutocapitalization(.words)
                                .font(AgePonyTypography.bodyEmph)
                        }
                    }
                    if let comment = candidate.candidate.sshComment, !comment.isEmpty {
                        Text(comment)
                            .font(AgePonyTypography.monoCaption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) {
                        candidates.removeAll { $0.id == candidate.id }
                    } label: {
                        Label("Discard", systemImage: "trash")
                    }
                }
            }
        } header: {
            Text("Found \(candidates.count) recipient\(candidates.count == 1 ? "" : "s")")
        } footer: {
            Text("Toggle off any you don't want to save. Names are local to your vault.")
        }
    }

    private var saveSection: some View {
        Section {
            Button(action: saveAll) {
                if saving {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    Text("Save \(savableCount)").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.agePonyPrimary)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            .disabled(savableCount == 0 || saving)
        }
    }

    // MARK: - Actions

    private func parsePaste() {
        let raw = pasteText.trimmingCharacters(in: .whitespacesAndNewlines)
        pasteError = nil
        do {
            let candidate = try RecipientImportService.parsePastedText(raw)
            appendCandidate(candidate, source: sourceForPaste(candidate.type), sourceMetadata: nil)
            pasteText = ""
        } catch {
            pasteError = describePasteError(error)
        }
    }

    private func handleScannedValue(_ value: String) {
        qrError = nil
        do {
            let candidate = try RecipientImportService.parsePastedText(value)
            appendCandidate(candidate, source: .qrScan, sourceMetadata: nil)
        } catch {
            qrError = describePasteError(error)
        }
    }

    private func fetchGitHub() async {
        let username = githubUsername.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else { return }
        githubError = nil
        githubLoading = true
        do {
            let found = try await RecipientImportService.fetchFromGitHub(username: username)
            for c in found {
                appendCandidate(c, source: .github, sourceMetadata: "github.com/\(username)")
            }
        } catch {
            githubError = describeFetchError(error)
        }
        githubLoading = false
    }

    private func appendCandidate(
        _ candidate: RecipientImportCandidate,
        source: StoredRecipientSource,
        sourceMetadata: String?
    ) {
        candidates.append(EditableCandidate(
            name: candidate.defaultName,
            include: true,
            candidate: candidate,
            source: source,
            sourceMetadata: sourceMetadata
        ))
    }

    private func saveAll() {
        saving = true
        defer { saving = false }
        let toSave = candidates.filter { $0.include }
        for row in toSave {
            let trimmed = row.name.trimmingCharacters(in: .whitespaces)
            let stored = StoredRecipient(
                name: trimmed.isEmpty ? row.candidate.defaultName : trimmed,
                type: row.candidate.type,
                publicKeyMaterial: row.candidate.publicKeyMaterial,
                sshComment: row.candidate.sshComment,
                source: row.source,
                sourceMetadata: row.sourceMetadata
            )
            do {
                _ = try vault.addRecipient(stored)
            } catch {
                saveError = error.localizedDescription
                return
            }
        }
        onDone()
        dismiss()
    }

    // MARK: - Helpers

    private var savableCount: Int {
        candidates.filter { $0.include }.count
    }

    private func sourceForPaste(_ type: StoredRecipientType) -> StoredRecipientSource {
        type.pastedSource
    }

    private func typeLabel(_ t: StoredRecipientType) -> String {
        switch t {
        case .x25519:    return "age X25519"
        case .sshEd25519: return "SSH Ed25519"
        case .sshRSA:    return "SSH RSA"
        case .postQuantum: return "Post-quantum hybrid"
        }
    }

    private func describePasteError(_ error: Error) -> String {
        if let e = error as? RecipientImportError {
            switch e {
            case .unrecognizedFormat:        return "Couldn't recognize that. Expected an `age1...` recipient or an `ssh-ed25519 ...` / `ssh-rsa ...` line."
            case .noUsableKeysInResponse:    return "No usable keys."
            case .fetchFailed(let m):        return "Fetch failed: \(m)"
            case .invalidUsername:           return "Invalid username."
            }
        }
        if let e = error as? Bech32Error {
            return "Not a valid age recipient. (\(e))"
        }
        return error.localizedDescription
    }

    private func describeFetchError(_ error: Error) -> String {
        if let e = error as? RecipientImportError {
            switch e {
            case .invalidUsername:           return "Usernames may only contain letters, numbers, hyphens, and underscores."
            case .fetchFailed(let m):        return "Couldn't fetch: \(m)"
            case .noUsableKeysInResponse:    return "GitHub returned no ed25519 or RSA public keys for that user."
            case .unrecognizedFormat:        return "Unexpected response from GitHub."
            }
        }
        return error.localizedDescription
    }

    private func describeQRError(_ error: QRScannerError) -> String {
        switch error {
        case .cameraUnavailable: return "Camera unavailable on this device."
        case .permissionDenied:  return "Camera access denied. Enable it for AgePony in Settings → AgePony."
        case .setupFailed(let m): return "Camera setup failed: \(m)"
        }
    }
}

// MARK: - QR scanner host

/// Full-screen QR scanner with a cancel chrome on top. Wraps the
/// AVFoundation-backed QRScannerView so the camera UI has a way out
/// even before a code is detected.
private struct QRScannerHostView: View {
    let onDetect: (String) -> Void
    let onCancel: () -> Void
    let onError: (QRScannerError) -> Void

    var body: some View {
        ZStack(alignment: .top) {
            QRScannerView(onDetect: onDetect, onError: onError)
                .ignoresSafeArea()

            VStack {
                HStack {
                    Button("Cancel", action: onCancel)
                        .padding(.vertical, 10)
                        .padding(.horizontal, 16)
                        .background(.ultraThinMaterial, in: Capsule())
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.top, 20)
                Spacer()
                Text("Scan a QR code containing an age recipient or SSH public key.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .padding(.bottom, 40)
            }
        }
    }
}
