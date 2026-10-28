//
//  PaperRestoreView.swift
//  AgePony
//
//  Settings › Restore from a paper backup (5.0.1, parity with Android 5.0.0).
//
//  Scan the page's QR code or type its text. A protected page asks for its passphrase;
//  a plain one, or a bare AGE-SECRET-KEY string, goes straight to the preview. Restored
//  keys are added to the vault but never made the active identity.
//
//  Mirrors Android `ui/portability/PaperScreens.kt` (PaperRestoreScreen).
//

import SwiftUI
import AgePonyCore

struct PaperRestoreView: View {

    let vault: Vault

    private enum Stage { case input, passphrase, preview, done }

    @Environment(\.dismiss) private var dismiss

    @State private var stage: Stage = .input
    @State private var scanned = ""
    @State private var passphrase = ""
    @State private var busy = false
    @State private var found: [StoredIdentity] = []
    @State private var summary: KeyPortability.ImportSummary?
    @State private var error: String?
    @State private var scanning = false
    @State private var scanError: String?

    var body: some View {
        Form {
            switch stage {
            case .input: inputSections
            case .passphrase: passphraseSection
            case .preview: previewSection
            case .done: doneSection
            }
            if let error {
                Section { StatusText(error).font(AgePonyTypography.subheadline) }
            }
        }
        .textCase(nil)
        .navigationTitle("Restore from paper")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $scanning) { scannerSheet }
        .onDisappear {
            scanned = ""
            passphrase = ""
        }
    }

    @ViewBuilder private var inputSections: some View {
        Section {
            Button("Scan the page") {
                scanError = nil
                scanning = true
            }
            .buttonStyle(.agePonyPrimary)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
        }
        Section {
            TextField("…or type or paste the text", text: $scanned, axis: .vertical)
                .lineLimit(4...12)
                // Mono for the key text, not for the prompt.
                .font(scanned.isEmpty ? AgePonyTypography.body : AgePonyTypography.monoSmall)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Continue") { take(scanned) }
                .disabled(scanned.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    private var passphraseSection: some View {
        Section {
            SecureField("Passphrase", text: $passphrase)
                .textContentType(.password)
                .onChange(of: passphrase) { error = nil }
            Button {
                open()
            } label: {
                if busy {
                    Text("Opening…")
                } else {
                    Text("Open backup")
                }
            }
            .disabled(passphrase.isEmpty || busy)
            if busy {
                HStack { Spacer(); ProgressView(); Spacer() }
            }
        } header: {
            Text("This page is passphrase-protected")
        } footer: {
            Text("Opening it takes up to a minute.")
        }
    }

    private var previewSection: some View {
        Section {
            ForEach(found) { identity in
                VStack(alignment: .leading, spacing: 4) {
                    Text(identity.name)
                    Text(KeyPortability.keySummary(identity))
                        .font(AgePonyTypography.monoCaption)
                        .foregroundStyle(.secondary)
                }
            }
            Button("Add to vault") { add() }
        } header: {
            Text("Found")
        } footer: {
            Text("Restored keys are not made your active identity. Choose one in Settings if you want it.")
        }
    }

    @ViewBuilder private var doneSection: some View {
        if let s = summary {
            Section {
                Label {
                    if s.identitiesAdded > 0 {
                        Text("Restored ^[\(s.identitiesAdded) identity](inflect: true)")
                    } else {
                        Text("That key is already in your vault.")
                    }
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(AgePonyColors.success)
                }
                Button("Done") { dismiss() }
            }
        }
    }

    private var scannerSheet: some View {
        NavigationStack {
            ZStack {
                QRScannerView(onDetect: { value in
                    scanning = false
                    take(value)
                }, onError: { failure in
                    switch failure {
                    case .permissionDenied: scanError = String(localized: "Camera access is off. Turn it on in Settings, or type the text instead.")
                    case .cameraUnavailable: scanError = String(localized: "No camera is available.")
                    case .setupFailed: scanError = UserMessage.text(for: failure, fallback: String(localized: "The camera couldn't start. Type the text instead."))
                    }
                })
                .ignoresSafeArea()
                if let scanError {
                    // .thinMaterial only here, over the live camera feed, so the
                    // message stays legible (5.1.0, U4).
                    StatusText(scanError)
                        .padding()
                        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
                        .padding()
                }
            }
            .navigationTitle("Scan the page")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { scanning = false }
                }
            }
        }
    }

    // MARK: Actions

    private func take(_ text: String) {
        error = nil
        scanned = text
        if PaperBackup.isSealed(text) {
            stage = .passphrase
        } else {
            found = KeyPortability.identitiesFromText(text)
            if found.isEmpty {
                error = String(localized: "No age secret key found in that.")
                stage = .input
            } else {
                stage = .preview
            }
        }
    }

    private func open() {
        // A page made elsewhere could ask for more scrypt memory than iOS gives AgePony:
        // refuse it before the derivation starts rather than crash.
        if let factor = Self.largestWorkFactor(scanned), !ScryptMemory.fits(workFactor: factor) {
            error = String(localized: "Its passphrase work factor (\(ScryptMemory.describe(workFactor: factor))) needs more memory than iOS will give AgePony right now.")
            return
        }
        busy = true
        let text = scanned
        let pass = passphrase
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try PaperBackup.open(armored: text, passphrase: pass) }
            DispatchQueue.main.async {
                busy = false
                switch result {
                case .success(let identityFile):
                    found = KeyPortability.identitiesFromText(identityFile)
                    if found.isEmpty {
                        error = String(localized: "The backup opened but held no age key.")
                        stage = .input
                    } else {
                        passphrase = ""
                        stage = .preview
                    }
                case .failure(let e):
                    switch e as? PaperBackupError {
                    case .wrongPassphrase?: error = String(localized: "Wrong passphrase.")
                    case .damaged?, .notSealed?: error = String(localized: "The backup text is damaged or incomplete. Check it against the page.")
                    default:
                        if let age = e as? AgeError, case .wrongPassphrase = age {
                            error = String(localized: "Wrong passphrase.")
                        } else {
                            error = UserMessage.text(for: e, fallback: String(localized: "Couldn't open the backup page."))
                        }
                    }
                }
            }
        }
    }

    private func add() {
        do {
            summary = try KeyPortability.importInto(vault, .init(identities: found, recipients: [], signers: []))
            found = []
            scanned = ""
            stage = .done
        } catch {
            self.error = UserMessage.text(for: error, fallback: String(localized: "Couldn't save the restored keys to the vault."))
        }
    }

    /// The largest scrypt work factor in the page's header, nil if it doesn't parse.
    private static func largestWorkFactor(_ text: String) -> Int? {
        guard let start = text.range(of: "-----BEGIN AGE ENCRYPTED FILE-----"),
              let summary = try? AgeFileInspector.inspect(fileBytes: Data(text[start.lowerBound...].utf8), knownIdentities: []) else {
            return nil
        }
        return summary.stanzas.compactMap(\.scryptWorkFactor).max()
    }
}
