//
//  HomeView.swift
//  AgePony
//
//  The 5-tab shell. Also presents share-extension hand-offs: RootView claims
//  an incoming payload (5.0.1) and hands it down; this view presents the
//  matching flow as a sheet over the current tab, with the input preloaded.
//  The four cases are:
//
//      direction=encrypt + kind=file  → EncryptFlow(preloadedURL:)
//      direction=decrypt + kind=file  → DecryptFlow(preloadedURL:)
//      direction=encrypt + kind=text  → TextEncryptView(preloadedText:)
//      direction=decrypt + kind=text  → TextDecryptView(preloadedText:)
//
//  On sheet dismiss the claimed file is deleted (M-7).
//

import SwiftUI
import Combine
import StoreKit

struct HomeView: View {

    let vault: Vault

    @Environment(\.requestReview) private var requestReview

    /// Owned by RootView, not by this view.
    ///
    /// RootView swaps HomeView out for LockedView when the vault re-locks on
    /// background, which destroys this view's state. Holding the selection here
    /// meant every unlock dropped the user back on Files regardless of where
    /// they had been.
    @Binding var selectedTab: Tab
    @State private var pendingFileURL: URL?
    /// A claimed share waiting to be shown. Owned by RootView, which receives
    /// it even while the vault is locked.
    @Binding var pendingShare: ClaimedShare?
    @State private var showWalkthrough: Bool = false

    enum Tab: String, Hashable {
        case files, notes, text, identities, settings
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                FilesView(vault: vault, pendingExternalDecryptURL: $pendingFileURL)
                    .navigationTitle("Files")
            }
            .tabItem { Label("Files", systemImage: "doc.badge.gearshape") }
            .tag(Tab.files)

            NavigationStack {
                NotesView(vault: vault)
                    .navigationTitle("Notes")
            }
            .tabItem { Label("Notes", systemImage: "note.text") }
            .tag(Tab.notes)

            NavigationStack {
                TextModeView(vault: vault)
                    .navigationTitle("Text")
            }
            .tabItem { Label("Text", systemImage: "textformat.alt") }
            .tag(Tab.text)

            NavigationStack {
                IdentitiesView(vault: vault)
                    .navigationTitle("Identities")
            }
            .tabItem { Label("Identities", systemImage: "key") }
            .tag(Tab.identities)

            NavigationStack {
                SettingsView(vault: vault)
                    .navigationTitle("Settings")
            }
            .tabItem { Label("Settings", systemImage: "gearshape") }
            .tag(Tab.settings)
        }
        .tint(AgePonyColors.accent)
        .onReceive(NotificationCenter.default.publisher(for: .agePonyOpenAgeFile)) { note in
            if let url = note.userInfo?["url"] as? URL {
                selectedTab = .files
                pendingFileURL = url
            }
        }
        .sheet(item: $presentedShare, onDismiss: {
            presentedShare?.discard()
            presentedShare = nil
        }) { share in
            NavigationStack {
                ShareIncomingSheet(vault: vault, share: share)
            }
        }
        .onChange(of: pendingShare) { _, new in takePendingShare(new) }
        .onAppear { takePendingShare(pendingShare) }
        .onReceive(NotificationCenter.default.publisher(for: .agePonyOperationSucceeded)) { _ in
            // A successful encrypt just finished and the user dismissed the
            // flow. Ask StoreKit for a review if our own gating agrees it's a
            // good moment. The short delay lets the encrypt sheet finish
            // dismissing so the native sheet isn't presented on top of it.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                ReviewPrompter.requestReviewIfAppropriate(using: requestReview)
            }
        }
        .onAppear {
            // First unlocked launch after setup: show the feature tour once.
            if !vault.hasSeenWalkthrough {
                showWalkthrough = true
            }
        }
        .fullScreenCover(isPresented: $showWalkthrough) {
            WalkthroughView {
                vault.hasSeenWalkthrough = true
                showWalkthrough = false
            }
        }
    }

    @State private var presentedShare: ClaimedShare?

    /// Move a pending share into the sheet. A share that arrives while another
    /// is on screen replaces it; the one it replaces is deleted.
    private func takePendingShare(_ share: ClaimedShare?) {
        guard let share else { return }
        // A file the wipe or a sweep already removed is dropped quietly.
        if let url = share.fileURL, !FileManager.default.fileExists(atPath: url.path) {
            pendingShare = nil
            return
        }
        if let current = presentedShare, current.id != share.id { current.discard() }
        presentedShare = share
        pendingShare = nil
    }
}

// MARK: - Notification names

extension Notification.Name {
    /// Posted when the user completes a successful encrypt and leaves the
    /// flow. HomeView listens for this to consider a contextual App Store
    /// review request (gated by ReviewPrompter). The same notification can
    /// be posted from the decrypt / text flows later to broaden the signal.
    static let agePonyOperationSucceeded = Notification.Name("com.agepony.app.operationSucceeded")
}

// MARK: - Routing sheet

/// Switches on the payload's direction × kind to present the matching
/// flow. Kept as a small dispatcher so HomeView itself stays focused on
/// tab routing.
private struct ShareIncomingSheet: View {
    let vault: Vault
    let share: ClaimedShare

    var body: some View {
        switch (share.direction, share.kind) {
        case (.encrypt, .file):
            if let url = share.fileURL {
                EncryptFlow(vault: vault, preloadedURL: url)
            } else {
                missingPayload
            }
        case (.decrypt, .file):
            if let url = share.fileURL {
                DecryptFlow(vault: vault, preloadedURL: url)
            } else {
                missingPayload
            }
        case (.encrypt, .text):
            TextEncryptView(vault: vault, preloadedText: share.text ?? "")
        case (.decrypt, .text):
            TextDecryptView(vault: vault, preloadedText: share.text ?? "")
        }
    }

    /// The share's manifest arrived but its file didn't (a sweep removed it, or
    /// the copy from the share extension never finished).
    private var missingPayload: some View {
        ContentUnavailableView {
            Label("The shared file is missing", systemImage: "doc.questionmark")
        } description: {
            Text("AgePony received the share but not the file in it. Share it again from the other app.")
        }
    }
}
