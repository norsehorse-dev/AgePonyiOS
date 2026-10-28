//
//  FilesView.swift
//  AgePony
//
//  The Files tab landing page. A list of rows that open the Encrypt, Decrypt,
//  Sign, Verify, Inspect and Re-encrypt flows as sheets. Each flow handles its own picker +
//  share-sheet lifecycle.
//

import SwiftUI

struct FilesView: View {

    let vault: Vault
    /// External-open passthrough. When the parent (HomeView) gets a
    /// `.onChange` from the app-level pending-decrypt URL holder, it
    /// flips this binding's `url` and we present DecryptFlow with it
    /// preloaded.
    @Binding var pendingExternalDecryptURL: URL?

    @State private var showEncrypt: Bool = false
    @State private var showDecrypt: Bool = false
    @State private var showSign: Bool = false
    @State private var showVerify: Bool = false
    @State private var showInspect: Bool = false
    @State private var showMigrate: Bool = false

    var body: some View {
        List {
            Section("Encryption") {
                row("Encrypt a file", systemImage: "lock") { showEncrypt = true }
                row("Decrypt a file", systemImage: "lock.open") { showDecrypt = true }
            }
            Section {
                row("Sign a file", systemImage: "signature") { showSign = true }
                row("Verify a file", systemImage: "checkmark.seal") { showVerify = true }
            } header: {
                Text("Signatures")
            } footer: {
                Text("A signature shows who made a file and that it hasn't changed since.")
            }
            Section {
                row("Inspect a file", systemImage: "doc.text.magnifyingglass") { showInspect = true }
                row("Re-encrypt a file", systemImage: "arrow.triangle.2.circlepath") { showMigrate = true }
            } header: {
                Text("Other tools")
            } footer: {
                Text("Inspect shows who can open a file without decrypting it. Re-encrypt changes who can open it.")
            }
        }
        .textCase(nil)
        .sheet(isPresented: $showEncrypt) {
            NavigationStack {
                EncryptFlow(vault: vault)
            }
        }
        .sheet(isPresented: $showDecrypt, onDismiss: {
            pendingExternalDecryptURL = nil
        }) {
            NavigationStack {
                DecryptFlow(vault: vault, preloadedURL: pendingExternalDecryptURL)
            }
        }
        .sheet(isPresented: $showSign) {
            NavigationStack {
                SignFileView(vault: vault)
            }
        }
        .sheet(isPresented: $showVerify) {
            NavigationStack {
                VerifyFileView(vault: vault)
            }
        }
        .sheet(isPresented: $showInspect) {
            NavigationStack {
                InspectFlow(vault: vault)
            }
        }
        .sheet(isPresented: $showMigrate) {
            NavigationStack {
                MigrateFlow(vault: vault)
            }
        }
        .onChange(of: pendingExternalDecryptURL) { _, newValue in
            if newValue != nil {
                showDecrypt = true
            }
        }
    }

    /// One tool. Opens its flow as a sheet, so there's no chevron.
    private func row(_ title: LocalizedStringKey, systemImage: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
        }
        .foregroundStyle(.primary)
    }
}
