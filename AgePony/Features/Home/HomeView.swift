//
//  HomeView.swift
//  AgePony
//
//  The 5-tab shell. As of 1g, also handles share-extension hand-offs:
//  when the .agePonyShareIncoming notification fires, this view presents
//  the matching flow as a sheet over the current tab, with the payload
//  preloaded. The four cases are:
//
//      direction=encrypt + kind=file  → EncryptFlow(preloadedURL:)
//      direction=decrypt + kind=file  → DecryptFlow(preloadedURL:)
//      direction=encrypt + kind=text  → TextEncryptView(preloadedText:)
//      direction=decrypt + kind=text  → TextDecryptView(preloadedText:)
//
//  On sheet dismiss, the App Group token directory is cleaned up so
//  abandoned payloads don't accumulate. A `.task`-driven sweep also
//  collects any payloads older than 1 hour at view appear.
//

import SwiftUI
import Combine

struct HomeView: View {

    let vault: Vault

    @Environment(\.requestReview) private var requestReview

    @State private var selectedTab: Tab = .files
    @State private var pendingFileURL: URL?
    @State private var sharePayload: SharedPayload?
    @State private var showWalkthrough: Bool = false

    enum Tab: Hashable {
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
        .tint(AgePonyColors.tealCore)
        .onReceive(NotificationCenter.default.publisher(for: .agePonyOpenAgeFile)) { note in
            if let url = note.userInfo?["url"] as? URL {
                selectedTab = .files
                pendingFileURL = url
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .agePonyShareIncoming)) { note in
            if let payload = note.userInfo?["payload"] as? SharedPayload {
                sharePayload = payload
            }
        }
        .sheet(item: $sharePayload, onDismiss: {
            if let token = sharePayload?.token {
                SharedContainer.cleanup(token: token)
            }
        }) { payload in
            NavigationStack {
                ShareIncomingSheet(vault: vault, payload: payload)
            }
        }
        .task {
            // Clean up abandoned share payloads from previous launches that
            // never made it through the flow.
            SharedContainer.sweepStale()
        }
        .onReceive(NotificationCenter.default.publisher(for: .agePonyOperationSucceeded)) { _ in
            // A successful encrypt just finished and the user dismissed the
            // flow. Ask StoreKit for a review if our own gating agrees it's a
            // good moment — the short delay lets the encrypt sheet finish
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
}

// MARK: - Make SharedPayload usable with .sheet(item:)

extension SharedPayload: Identifiable {
    public var id: String { token }
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
    let payload: SharedPayload

    var body: some View {
        switch (payload.direction, payload.kind) {
        case (.encrypt, .file):
            if let url = try? SharedContainer.fileURL(for: payload) {
                EncryptFlow(vault: vault, preloadedURL: url)
            } else {
                missingPayload
            }
        case (.decrypt, .file):
            if let url = try? SharedContainer.fileURL(for: payload) {
                DecryptFlow(vault: vault, preloadedURL: url)
            } else {
                missingPayload
            }
        case (.encrypt, .text):
            TextEncryptView(vault: vault, preloadedText: payload.textPayload ?? "")
        case (.decrypt, .text):
            TextDecryptView(vault: vault, preloadedText: payload.textPayload ?? "")
        }
    }

    private var missingPayload: some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.secondary)
            Text("Couldn't read the shared payload.")
                .font(AgePonyTypography.headline)
            Text("Try sharing it again from the source app.")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(32)
    }
}
