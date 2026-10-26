//
//  PassphraseModeView.swift
//  AgePony
//
//  "Continue without unlocking" (5.0.1, #13, matching Android): passphrase work
//  from the lock screen. Encrypt or decrypt text with a passphrase, or decrypt a
//  passphrase-protected file. The vault stays locked and no key is touched;
//  anything that needs a key says so and points back to unlocking.
//
//  A share that arrived while the vault was locked can be finished here when it
//  is something passphrase mode can do.
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct PassphraseModeView: View {

    /// The share waiting at the lock screen, if any. Taken over (and deleted)
    /// when this screen uses it.
    @Binding var pendingShare: ClaimedShare?
    let workFactor: Int
    let onClose: () -> Void

    enum Job: String, CaseIterable, Identifiable {
        case decryptText = "Decrypt text"
        case encryptText = "Encrypt text"
        case decryptFile = "Decrypt file"
        var id: String { rawValue }
    }

    @State private var task: Job = .decryptText
    @State private var input = ""
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var output: String?
    @State private var fileURL: URL?
    @State private var resultURL: URL?
    @State private var signature: FileVerificationResult?
    @State private var working = false
    @State private var message: String?
    @State private var picking = false
    @State private var copied = false
    @State private var usedShare: ClaimedShare?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Task", selection: $task) {
                        ForEach(Job.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                } footer: {
                    Text("Your vault stays locked. Only passphrase-protected (scrypt) files and text work here; anything encrypted to a key needs you to unlock.")
                }

                switch task {
                case .decryptText, .encryptText: textSection
                case .decryptFile: fileSection
                }

                Section {
                    SecureField("Passphrase", text: $passphrase)
                        .textContentType(.password)
                    if task == .encryptText {
                        SecureField("Confirm passphrase", text: $confirm)
                            .textContentType(.password)
                    }
                } footer: {
                    if task == .encryptText {
                        Text("Use a long passphrase. There's no recovery if it's forgotten. Work factor \(ScryptMemory.describe(workFactor: workFactor)).")
                    }
                }

                Section {
                    Button(action: run) {
                        if working {
                            ProgressView().frame(maxWidth: .infinity)
                        } else {
                            Text(actionTitle).frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.agePonyPrimary)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                    .disabled(!canRun || working)
                }

                resultSection
            }
            .navigationTitle("Without unlocking")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { close() }
                }
            }
            .fileImporter(isPresented: $picking, allowedContentTypes: fileTypes, allowsMultipleSelection: false) { result in
                if case .success(let urls) = result, let url = urls.first {
                    resetResult()
                    fileURL = url
                }
            }
            .alert("Couldn't finish", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
                Button("OK", role: .cancel) { message = nil }
            } message: {
                Text(message ?? "")
            }
            .onChange(of: task) { _, _ in resetResult() }
            .onAppear(perform: adoptShare)
            .onDisappear(perform: cleanUp)
        }
    }

    // MARK: - Sections

    private var textSection: some View {
        Section {
            TextEditor(text: $input)
                .font(task == .decryptText ? AgePonyTypography.monoSmall : AgePonyTypography.body)
                .frame(minHeight: 140)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .onChange(of: input) { _, _ in output = nil }
        } header: {
            Text(task == .decryptText ? "Encrypted text (-----BEGIN AGE ENCRYPTED FILE-----)" : "Text to encrypt")
        }
    }

    private var fileSection: some View {
        Section {
            if let fileURL {
                Text(fileURL.lastPathComponent)
                    .font(AgePonyTypography.monoSmall)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Button(fileURL == nil ? "Choose a .age file…" : "Choose another file…") { picking = true }
        } header: {
            Text("Passphrase-protected file")
        }
    }

    @ViewBuilder
    private var resultSection: some View {
        if let output {
            Section {
                Text(output)
                    .font(task == .encryptText ? AgePonyTypography.monoCaption : AgePonyTypography.body)
                    .textSelection(.enabled)
                Button(copied ? "Copied" : "Copy") {
                    ClipboardPreferences.copy(output)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { copied = false }
                }
                if task == .encryptText {
                    ShareLink(item: output) { Text("Share encrypted text") }
                }
            } header: {
                Text(task == .encryptText ? "Encrypted" : "Decrypted")
            }
        }
        if let resultURL {
            Section {
                Text(resultURL.lastPathComponent)
                    .font(AgePonyTypography.monoSmall)
                if let signature {
                    CompactVerifiedBadge(result: signature)
                }
                PlaintextShareButton(url: resultURL)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            } header: {
                Text("Decrypted")
            } footer: {
                Text("Deleted from this iPhone when you close this screen.")
            }
        }
    }

    // MARK: - State

    private var actionTitle: String {
        switch task {
        case .decryptText, .decryptFile: return "Decrypt"
        case .encryptText: return "Encrypt"
        }
    }

    private var canRun: Bool {
        guard !passphrase.isEmpty else { return false }
        switch task {
        case .decryptText: return !input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .encryptText: return !input.isEmpty && passphrase == confirm
        case .decryptFile: return fileURL != nil
        }
    }

    private var fileTypes: [UTType] {
        [UTType("org.age-encryption.age"), .data].compactMap { $0 }
    }

    private func resetResult() {
        output = nil
        if let resultURL { FileEncryptor.cleanupTempFile(at: resultURL) }
        resultURL = nil
        signature = nil
    }

    /// Take over a share passphrase mode can finish. Encrypting a file needs
    /// recipients from the vault, so that one waits for an unlock.
    private func adoptShare() {
        guard let share = pendingShare else { return }
        switch (share.direction, share.kind) {
        case (.decrypt, .text):
            task = .decryptText
            input = share.text ?? ""
        case (.encrypt, .text):
            task = .encryptText
            input = share.text ?? ""
        case (.decrypt, .file):
            task = .decryptFile
            fileURL = share.fileURL
        case (.encrypt, .file):
            return
        }
        usedShare = share
        pendingShare = nil
    }

    private func close() {
        cleanUp()
        onClose()
    }

    private func cleanUp() {
        resetResult()
        usedShare?.discard()
        usedShare = nil
        passphrase = ""
        confirm = ""
    }

    // MARK: - Work

    private func run() {
        working = true
        resetResult()
        let pass = passphrase
        switch task {
        case .encryptText:
            let text = input
            let factor = workFactor
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { AgeArmor.encode(try Age.encrypt(plaintext: Data(text.utf8), passphrase: pass, workFactor: factor)) }
                DispatchQueue.main.async { finish(result) { output = $0 } }
            }
        case .decryptText:
            let summary: AgeFileSummary
            do {
                summary = try AgeFileInspector.inspect(fileBytes: Data(input.utf8), knownIdentities: [])
                try checkPassphraseOnly(summary)
            } catch {
                working = false
                message = describe(error)
                return
            }
            let binary = summary.binaryBytes ?? Data()
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { () throws -> String in
                    let plain = try Age.decrypt(ciphertext: binary, passphrase: pass)
                    return String(data: plain, encoding: .utf8) ?? "(not text: \(plain.count) bytes)"
                }
                DispatchQueue.main.async { finish(result) { output = $0 } }
            }
        case .decryptFile:
            guard let url = fileURL else { working = false; return }
            do {
                try checkPassphraseOnly(try AgeFileInspector.inspect(fileURL: url, knownIdentities: []))
            } catch {
                working = false
                message = describe(error)
                return
            }
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { () throws -> (URL, FileVerificationResult?) in
                    let out = try FileEncryptor.decrypt(inputURL: url, identities: [], passphrase: pass)
                    // Signed: the signature is checked, but with the vault locked
                    // there's nothing to say whose key it is.
                    let verdict = out.signedBundle.map {
                        FileVerifier.verify(bundle: $0, identities: [], recipients: [], signers: [])
                    } ?? FileVerifier.verify(stanza: out.signatureStanza, plaintextURL: out.url,
                                             identities: [], recipients: [], signers: [])
                    return (out.url, verdict)
                }
                DispatchQueue.main.async {
                    finish(result) { pair in
                        resultURL = pair.0
                        signature = pair.1
                    }
                }
            }
        }
    }

    private func finish<T>(_ result: Result<T, Error>, _ apply: (T) -> Void) {
        working = false
        switch result {
        case .success(let value): apply(value)
        case .failure(let error): message = describe(error)
        }
    }

    private struct NeedsKey: Error {}
    private struct TooHeavy: Error { let factor: Int }

    private func checkPassphraseOnly(_ summary: AgeFileSummary) throws {
        guard summary.onlyScrypt else { throw NeedsKey() }
        if let factor = summary.scryptWorkFactor, !ScryptMemory.fits(workFactor: factor) {
            throw TooHeavy(factor: factor)
        }
    }

    private func describe(_ error: Error) -> String {
        if error is NeedsKey {
            return "This was encrypted to a key, not a passphrase. Unlock AgePony to decrypt it with your keys."
        }
        if let e = error as? TooHeavy {
            return "Its passphrase work factor (\(ScryptMemory.describe(workFactor: e.factor))) needs more memory than iOS will give AgePony right now."
        }
        if let e = error as? AgeFileInspectorError {
            switch e {
            case .notAnAgeFile:   return "That isn't age-encrypted text or a .age file."
            case .malformedArmor: return "The armored block is damaged."
            default:              return "Couldn't read the age header."
            }
        }
        let text = String(describing: error)
        if text.contains("wrongPassphrase") || text.contains("WrongPassphrase") { return "Wrong passphrase." }
        return text
    }
}
