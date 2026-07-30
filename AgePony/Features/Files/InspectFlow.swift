//
//  InspectFlow.swift
//  AgePony
//
//  Look at an age file without decrypting it.
//
//  Only the header is read, so this is instant on a file of any size — the
//  point being that you should not have to wait on, or find room for, a
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
                ToolbarItem(placement: .cancellationAction) {
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
            .alert(
                "Couldn't read that file",
                isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
            ) {
                Button("OK", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
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
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)
            Text("Inspect an age file")
                .font(AgePonyTypography.title)
            Text("See which keys can open a file, whether it is post-quantum, and what a passphrase would cost to try — without decrypting it. Only the header is read, so this is instant at any file size.")
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

    private var readingStage: some View {
        VStack(spacing: 18) {
            Spacer()
            ProgressView().controlSize(.large).tint(AgePonyColors.tealCore)
            Text("Reading header…")
                .font(AgePonyTypography.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var doneStage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if let summary {
                    FileInfoCard(filename: sourceName, summary: summary)

                    if summary.isPostQuantum {
                        calloutRow(
                            icon: "atom",
                            text: "This file is encrypted to a post-quantum recipient. It stays secret even against a future quantum computer."
                        )
                    }

                    if let canOpen = openabilityText {
                        calloutRow(
                            icon: summary.matchesAKnownIdentity ? "checkmark.circle" : "questionmark.circle",
                            text: canOpen
                        )
                    }
                }

                Button("Inspect another") {
                    summary = nil
                    sourceName = ""
                    stage = .pickFile
                }
                .buttonStyle(.agePonySecondary)
            }
            .padding(.horizontal, 16)
            .padding(.top, 16)
        }
    }

    private func calloutRow(icon: String, text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(AgePonyColors.tealCore)
            Text(text)
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
    }

    /// A plain-language answer to "can I open this?".
    private var openabilityText: String? {
        guard let summary else { return nil }
        if summary.onlyScrypt {
            return "Opening this needs the passphrase it was encrypted with."
        }
        if summary.matchesAKnownIdentity {
            return "One of your identities is listed as a recipient, so you can decrypt this."
        }
        return "None of your identities is listed as a recipient. You would need the matching private key."
    }

    private var ageContentTypes: [UTType] {
        if let age = UTType("org.age-encryption.age") { return [age, .data] }
        return [.data]
    }

    private func handleFilePick(_ result: Result<[URL], Error>) {
        do {
            guard let url = try result.get().first else { return }
            sourceName = url.lastPathComponent
            stage = .reading
            Task { await read(url) }
        } catch {
            errorMessage = error.localizedDescription
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
        if let e = error as? AgeFileInspectorError {
            switch e {
            case .notAnAgeFile:             return "This file isn't an age-encrypted file."
            case .malformedArmor:           return "The armored block is malformed."
            case .headerParseFailed(let m): return "Couldn't parse the age header: \(m)"
            case .cannotOpenFile(let name): return "Couldn't open \(name)."
            }
        }
        return error.localizedDescription
    }
}
