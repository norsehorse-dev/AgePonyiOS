//
//  CreateNoteView.swift
//  AgePony
//
//  Sheet for creating an encrypted note.
//
//  Hotfix on 1g: replaced Task.detached / await MainActor.run with
//  DispatchQueue.global / DispatchQueue.main.async. With Swift 6 plus the
//  build setting SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor, the inferred
//  isolation of detached task closures isn't reliably nonisolated, so the
//  scrypt run could end up back on the main thread and freeze the UI. The
//  GCD pattern has no isolation inference at all and is guaranteed to run
//  off-main.
//

import SwiftUI
import AgePonyCore

struct CreateNoteView: View {

    let vault: Vault
    let onDone: () -> Void

    @State private var title: String = ""
    @State private var noteBody: String = ""
    @State private var passphrase: String = ""
    @State private var passphraseConfirm: String = ""
    @State private var showPassphrase: Bool = false
    @State private var saving: Bool = false
    @State private var errorMessage: String?

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                TextField("Title", text: $title)
                    .textInputAutocapitalization(.sentences)
                    .autocorrectionDisabled(false)
            } header: {
                Text("Title")
            } footer: {
                Text("The title is searchable from the notes list. It is encrypted at the vault level, but not separately with this note's passphrase.")
            }

            Section {
                TextEditor(text: $noteBody)
                    .frame(minHeight: 200)
                    .font(AgePonyTypography.body)
            } header: {
                Text("Body")
            } footer: {
                Text("The body is encrypted with this note's passphrase. Forgetting the passphrase makes the body unrecoverable.")
            }

            Section {
                if showPassphrase {
                    TextField("Passphrase", text: $passphrase)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Confirm passphrase", text: $passphraseConfirm)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } else {
                    SecureField("Passphrase", text: $passphrase)
                        .textInputAutocapitalization(.never)
                    SecureField("Confirm passphrase", text: $passphraseConfirm)
                        .textInputAutocapitalization(.never)
                }
                Toggle("Show passphrase", isOn: $showPassphrase)
                    .font(AgePonyTypography.footnote)

                if !passphraseConfirm.isEmpty && passphrase != passphraseConfirm {
                    Text("Passphrases don't match.")
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(AgePonyColors.destructive)
                }
            } header: {
                Text("Passphrase")
            } footer: {
                Text("Use a long passphrase you'll remember. scrypt's work factor 2^18 makes brute-force attacks expensive, but it can't help against a guessable phrase.")
            }

            Section {
                Button(action: save) {
                    if saving {
                        HStack {
                            ProgressView()
                            Text("Encrypting…")
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text("Create note").frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(saveDisabled)
            }
        }
        .navigationTitle("New note")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
        .alert(
            "Save failed",
            isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
        .interactiveDismissDisabled(saving)
    }

    private var saveDisabled: Bool {
        saving
        || passphrase.isEmpty
        || passphrase != passphraseConfirm
    }

    private func save() {
        saving = true
        let bodyData = Data(noteBody.utf8)
        let titleSnapshot = title.trimmingCharacters(in: .whitespaces).isEmpty
            ? "Untitled"
            : title.trimmingCharacters(in: .whitespaces)
        let passphraseSnapshot = passphrase

        // Run scrypt off the main thread using GCD. We use GCD instead of
        // Task.detached because Swift 6 + SWIFT_DEFAULT_ACTOR_ISOLATION =
        // MainActor sometimes infers detached-task closures as MainActor,
        // which would freeze the UI for the duration of the scrypt run.
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let ciphertext = try Age.encrypt(
                    plaintext: bodyData,
                    passphrase: passphraseSnapshot,
                    workFactor: 16
                )
                DispatchQueue.main.async {
                    let note = StoredNote(
                        title: titleSnapshot,
                        bodyCiphertext: ciphertext,
                        createdAt: Date(),
                        updatedAt: Date()
                    )
                    do {
                        _ = try vault.addNote(note)
                        saving = false
                        onDone()
                        dismiss()
                    } catch {
                        errorMessage = error.localizedDescription
                        saving = false
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    errorMessage = String(describing: error)
                    saving = false
                }
            }
        }
    }
}
