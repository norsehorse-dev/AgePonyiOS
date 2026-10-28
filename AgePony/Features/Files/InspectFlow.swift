//
//  InspectFlow.swift
//  AgePony
//
//  Look at an age file without decrypting it.
//
//  Only the header is read, so this is instant on a file of any size. The
//  point is that you should not have to wait on, or find room for, a
//  gigabyte to answer "what is this, and can I open it?".
//
//  Nothing here is secret. Recipient stanzas are public information: anyone
//  holding the file already has them, so showing them reveals nothing the
//  holder did not already have. That is why this needs no biometric prompt and
//  no passphrase.
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

struct InspectFlow: View {

    let vault: Vault

    @State private var stage: Stage = .pickFile
    @State private var sourceName: String = ""
    @State private var summary: AgeFileSummary?
    @State private var errorMessage: String?
    @State private var showFilePicker: Bool = false

    @Environment(\.dismiss) private var dismiss

    enum Stage {
        case pickFile
        case reading
        case done
    }

    var body: some View {
        content
            .navigationTitle("Inspect a file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .fileImporter(
                isPresented: $showFilePicker,
                allowedContentTypes: ageContentTypes,
                allowsMultipleSelection: false
            ) { result in
                handleFilePick(result)
            }
    }

    @ViewBuilder
    private var content: some View {
        switch stage {
        case .pickFile: pickFileStage
        case .reading:  readingStage
        case .done:     doneStage
        }
    }

    private var pickFileStage: some View {
        Form {
            Section {
                Button("Choose a .age file…") { showFilePicker = true }
            } footer: {
                Text("See which keys can open a file, whether it's quantum-safe and what a passphrase would cost to try, without decrypting it. Only the header is read, so it's instant at any file size.")
            }
            if let errorMessage {
                Section {
                    StatusText(errorMessage)
                }
            }
        }
        .textCase(nil)
    }

    private var readingStage: some View {
        VStack(spacing: 16) {
            Spacer()
            ProgressView().controlSize(.large)
            Text("Reading header…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var doneStage: some View {
        Form {
            if let summary {
                FileInfoSection(filename: sourceName, summary: summary)

                Section {
                    if let canOpen = openabilityText {
                        if summary.matchesAKnownIdentity {
                            StatusText(canOpen, kind: .success)
                        } else {
                            Label(canOpen, systemImage: "questionmark.circle")
                        }
                    }
                    if summary.isPostQuantum {
                        Label("This file is encrypted to a quantum-safe recipient. It stays secret even against a future quantum computer.", systemImage: "atom")
                    }
                } header: {
                    Text("Can you open it?")
                }
            }

            Section {
                Button("Inspect another file") {
                    summary = nil
                    sourceName = ""
                    stage = .pickFile
                }
            }
        }
        .textCase(nil)
    }

    /// A plain-language answer to "can I open this?".
    private var openabilityText: String? {
        guard let summary else { return nil }
        if summary.onlyScrypt {
            return String(localized: "Opening this needs the passphrase it was encrypted with.")
        }
        if summary.matchesAKnownIdentity {
            return String(localized: "One of your identities is listed as a recipient, so you can decrypt this.")
        }
        return String(localized: "None of your identities is listed as a recipient. You would need the matching private key.")
    }

    private var ageContentTypes: [UTType] {
        if let age = UTType("org.age-encryption.age") { return [age, .data] }
        return [.data]
    }

    private func handleFilePick(_ result: Result<[URL], Error>) {
        do {
            guard let url = try result.get().first else { return }
            errorMessage = nil
            sourceName = url.lastPathComponent
            stage = .reading
            Task { await read(url) }
        } catch {
            errorMessage = UserMessage.text(for: error, fallback: String(localized: "Couldn't open the file you picked."))
        }
    }

    private func read(_ url: URL) async {
        do {
            summary = try AgeFileInspector.inspect(fileURL: url, knownIdentities: vault.identities)
            stage = .done
        } catch {
            errorMessage = describe(error)
            stage = .pickFile
        }
    }

    private func describe(_ error: Error) -> String {
        if let e = error as? AgeFileInspectorError, case .notAnAgeFile = e {
            return String(localized: "This file isn't age-encrypted.")
        }
        return UserMessage.text(for: error, fallback: String(localized: "Couldn't read the file's age header."))
    }
}
