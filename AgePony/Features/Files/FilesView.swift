//
//  FilesView.swift
//  AgePony
//
//  The Files tab landing page. Entry buttons that open the Encrypt, Decrypt,
//  Sign, and Verify flows as sheets. Each flow handles its own picker +
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

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "lock.doc")
                .font(.system(size: 64, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)

            Text("Files")
                .font(AgePonyTypography.largeTitle)

            Text("Encrypt, decrypt, sign, or verify a file with one of your identities or a passphrase.")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()

            VStack(spacing: 14) {
                Button {
                    showEncrypt = true
                } label: {
                    Label("Encrypt a file", systemImage: "lock.fill")
                }
                .buttonStyle(.agePonyPrimary)

                Button {
                    showDecrypt = true
                } label: {
                    Label("Decrypt a file", systemImage: "lock.open.fill")
                }
                .buttonStyle(.agePonySecondary)

                Button {
                    showSign = true
                } label: {
                    Label("Sign a file", systemImage: "signature")
                }
                .buttonStyle(.agePonySecondary)

                Button {
                    showVerify = true
                } label: {
                    Label("Verify a file", systemImage: "checkmark.seal")
                }
                .buttonStyle(.agePonySecondary)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 32)
        }
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
        .onChange(of: pendingExternalDecryptURL) { _, newValue in
            if newValue != nil {
                showDecrypt = true
            }
        }
    }
}
