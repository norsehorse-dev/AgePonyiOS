//
//  NotesView.swift
//  AgePony
//
//  Notes-tab landing. Lists the user's encrypted notes by recent edit.
//  Each row shows the title (plaintext within the encrypted vault file)
//  and a relative timestamp. Tapping a row navigates to NoteDetailView,
//  which gates on the per-note passphrase before revealing the body.
//
//  "+" toolbar item presents CreateNoteView as a sheet.
//

import SwiftUI

struct NotesView: View {

    let vault: Vault

    @State private var showingCreate: Bool = false
    @State private var pendingDelete: StoredNote?

    var body: some View {
        Group {
            if vault.notes.isEmpty {
                emptyState
            } else {
                noteList
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showingCreate = true
                } label: {
                    Label("New note", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $showingCreate) {
            NavigationStack {
                CreateNoteView(vault: vault, onDone: { showingCreate = false })
            }
        }
        .navigationDestination(for: StoredNote.self) { note in
            NoteDetailView(vault: vault, noteID: note.id)
        }
        .confirmationDialog(
            pendingDelete.map { String(localized: "Delete \"\($0.title)\"?") } ?? "",
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let id = pendingDelete?.id {
                    try? vault.deleteNote(id: id)
                }
                pendingDelete = nil
            }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        } message: {
            Text("This deletes the note permanently. The passphrase won't help recover it.")
        }
    }

    // MARK: - Subviews

    /// The one empty-state pattern (5.1.0, U4): what a note is and how to add one.
    private var emptyState: some View {
        ContentUnavailableView {
            Label("No notes", systemImage: "note.text")
        } description: {
            Text("A note is text kept encrypted in AgePony with its own passphrase, separate from your vault's lock. Tap New note to write one.")
        } actions: {
            Button("New note") { showingCreate = true }
        }
    }

    private var noteList: some View {
        List {
            ForEach(sortedNotes) { note in
                NavigationLink(value: note) {
                    NoteRow(note: note)
                }
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) {
                        pendingDelete = note
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
            }
        }
        .textCase(nil)
        .listStyle(.insetGrouped)
    }

    private var sortedNotes: [StoredNote] {
        vault.notes.sorted { $0.updatedAt > $1.updatedAt }
    }
}

// MARK: - Row

private struct NoteRow: View {
    let note: StoredNote

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.doc")
                .font(AgePonyTypography.body)
                .foregroundStyle(.secondary)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 4) {
                Group {
                    if note.title.isEmpty {
                        Text("Untitled")
                    } else {
                        Text(note.title)
                    }
                }
                .font(AgePonyTypography.body)
                .lineLimit(1)
                Text(timestampLabel)
                    .font(AgePonyTypography.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.vertical, 4)
    }

    private var timestampLabel: String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        let relative = formatter.localizedString(for: note.updatedAt, relativeTo: Date())
        return String(localized: "Edited \(relative)")
    }
}
