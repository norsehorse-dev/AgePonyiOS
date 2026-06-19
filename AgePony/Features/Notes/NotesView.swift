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
                    Image(systemName: "plus")
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
            pendingDelete.map { "Delete \"\($0.title)\"?" } ?? "",
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

    private var emptyState: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: "note.text.badge.plus")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)
            Text("No notes yet")
                .font(AgePonyTypography.title)
            Text("Tap + to create your first encrypted note. Each note has its own passphrase.")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
            Spacer()
        }
        .frame(maxWidth: .infinity)
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
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(AgePonyColors.tealCore)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(note.title.isEmpty ? "Untitled" : note.title)
                    .font(AgePonyTypography.bodyEmph)
                    .lineLimit(1)
                Text(timestampLabel)
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.vertical, 4)
    }

    private var timestampLabel: String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return "Edited " + formatter.localizedString(for: note.updatedAt, relativeTo: Date())
    }
}
