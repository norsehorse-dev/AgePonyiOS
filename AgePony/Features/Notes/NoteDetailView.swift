//
//  NoteDetailView.swift
//  AgePony
//
//  Two-mode view for a single note: locked → unlocked.
//
//  Hotfix on 1g: scrypt unlock + save now run on DispatchQueue.global,
//  same reason as CreateNoteView. Without this the main thread is wedged
//  for the ~1-2s scrypt run on each unlock or save.
//

import SwiftUI
import AgePonyCore

struct NoteDetailView: View {

    let vault: Vault
    let noteID: UUID

    @State private var phase: Phase = .locked
    @State private var passphraseInput: String = ""
    @State private var passphraseError: String?
    @State private var working: Bool = false

    @State private var unlockedPassphrase: String = ""
    @State private var editingTitle: String = ""
    @State private var editingBody: String = ""
    @State private var originalTitle: String = ""
    @State private var originalBody: String = ""

    @State private var saveError: String?
    @State private var pendingDelete: Bool = false

    @Environment(\.dismiss) private var dismiss

    enum Phase {
        case locked
        case unlocked
    }

    private var note: StoredNote? {
        vault.notes.first(where: { $0.id == noteID })
    }

    var body: some View {
        Group {
            switch phase {
            case .locked:
                lockedView
            case .unlocked:
                unlockedView
            }
        }
        .navigationTitle(note?.title ?? "Note")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { toolbarContent }
        .alert(
            "Save failed",
            isPresented: Binding(get: { saveError != nil }, set: { if !$0 { saveError = nil } })
        ) {
            Button("OK", role: .cancel) { saveError = nil }
        } message: {
            Text(saveError ?? "")
        }
        .confirmationDialog(
            "Delete \"\(note?.title ?? "this note")\"?",
            isPresented: $pendingDelete,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let id = note?.id { try? vault.deleteNote(id: id) }
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This deletes the note permanently. The passphrase won't help recover it.")
        }
        .interactiveDismissDisabled(working || hasUnsavedChanges)
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        if phase == .unlocked {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    lockNote()
                } label: {
                    Image(systemName: "lock.fill")
                }
                .disabled(working)
            }
        }
    }

    private var lockedView: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: "lock.doc.fill")
                        .foregroundStyle(AgePonyColors.tealCore)
                        .font(.system(size: 22))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(note?.title ?? "Note")
                            .font(AgePonyTypography.bodyEmph)
                        if let n = note {
                            Text("Edited " + relativeDate(n.updatedAt))
                                .font(AgePonyTypography.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Section {
                SecureField("Passphrase", text: $passphraseInput)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if let msg = passphraseError {
                    Text(msg)
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(AgePonyColors.destructive)
                }
            } header: {
                Text("Unlock")
            } footer: {
                Text("Enter this note's passphrase. Decryption takes a moment because scrypt is deliberately slow.")
            }

            Section {
                Button(action: unlock) {
                    if working {
                        HStack {
                            ProgressView()
                            Text("Decrypting…")
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text("Unlock").frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(passphraseInput.isEmpty || working)
            }

            Section {
                Button(role: .destructive) {
                    pendingDelete = true
                } label: {
                    Label("Delete note", systemImage: "trash")
                }
            } footer: {
                Text("Deleting doesn't require the passphrase, but is permanent.")
            }
        }
    }

    private var unlockedView: some View {
        Form {
            Section {
                TextField("Title", text: $editingTitle)
                    .textInputAutocapitalization(.sentences)
            } header: {
                Text("Title")
            }

            Section {
                TextEditor(text: $editingBody)
                    .frame(minHeight: 260)
                    .font(AgePonyTypography.body)
            } header: {
                Text("Body")
            } footer: {
                if hasUnsavedChanges {
                    Text("Unsaved changes — tap Save to re-encrypt and store.")
                        .foregroundStyle(AgePonyColors.destructive)
                } else {
                    Text("Saved.")
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                Button(action: save) {
                    if working {
                        HStack {
                            ProgressView()
                            Text("Encrypting…")
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        Text("Save").frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(!hasUnsavedChanges || working)
            }

            Section {
                Button(role: .destructive) {
                    pendingDelete = true
                } label: {
                    Label("Delete note", systemImage: "trash")
                }
            }
        }
    }

    private var hasUnsavedChanges: Bool {
        editingTitle != originalTitle || editingBody != originalBody
    }

    private func unlock() {
        guard let note else { return }
        passphraseError = nil
        working = true
        let pphr = passphraseInput
        let ciphertext = note.bodyCiphertext
        let snapshotTitle = note.title

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let plaintext = try Age.decrypt(ciphertext: ciphertext, passphrase: pphr)
                let bodyString = String(data: plaintext, encoding: .utf8) ?? ""
                DispatchQueue.main.async {
                    unlockedPassphrase = pphr
                    editingBody = bodyString
                    originalBody = bodyString
                    editingTitle = snapshotTitle
                    originalTitle = snapshotTitle
                    passphraseInput = ""
                    phase = .unlocked
                    working = false
                }
            } catch {
                DispatchQueue.main.async {
                    passphraseError = describeUnlockError(error)
                    working = false
                }
            }
        }
    }

    private func save() {
        guard let note, !unlockedPassphrase.isEmpty else { return }
        working = true
        let bodyData = Data(editingBody.utf8)
        let titleSnapshot = editingTitle.trimmingCharacters(in: .whitespaces).isEmpty
            ? "Untitled"
            : editingTitle.trimmingCharacters(in: .whitespaces)
        let pphr = unlockedPassphrase
        let existingID = note.id
        let existingCreatedAt = note.createdAt
        let bodySnapshot = editingBody

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let ciphertext = try Age.encrypt(plaintext: bodyData, passphrase: pphr, workFactor: 16)
                DispatchQueue.main.async {
                    let updated = StoredNote(
                        id: existingID,
                        title: titleSnapshot,
                        bodyCiphertext: ciphertext,
                        createdAt: existingCreatedAt,
                        updatedAt: Date()
                    )
                    do {
                        try vault.deleteNote(id: existingID)
                        _ = try vault.addNote(updated)
                        originalTitle = titleSnapshot
                        originalBody = bodySnapshot
                        editingTitle = titleSnapshot
                        working = false
                    } catch {
                        saveError = error.localizedDescription
                        working = false
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    saveError = String(describing: error)
                    working = false
                }
            }
        }
    }

    private func lockNote() {
        unlockedPassphrase = ""
        editingTitle = ""
        editingBody = ""
        originalTitle = ""
        originalBody = ""
        passphraseInput = ""
        passphraseError = nil
        phase = .locked
    }

    private func describeUnlockError(_ error: Error) -> String {
        let s = String(describing: error)
        if s.contains("wrongPassphrase") || s.contains("noMatchingIdentity") {
            return "Wrong passphrase."
        }
        if s.contains("headerError") || s.contains("payloadError") {
            return "The note's encrypted data is malformed."
        }
        return error.localizedDescription
    }

    private func relativeDate(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}
