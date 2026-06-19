//
//  TextModeView.swift
//  AgePony
//
//  Text-tab landing. Mirrors FilesView shape, but in-memory: paste a text
//  blob → encrypt → get armored output to paste anywhere. Reverse for
//  decrypt. No file picker, no share sheet — copy-to-clipboard is the
//  primary output affordance.
//
//  Useful for chat / email / forum posts where the recipient receives
//  text channels and not binary files.
//

import SwiftUI

struct TextModeView: View {

    let vault: Vault

    @State private var showEncrypt: Bool = false
    @State private var showDecrypt: Bool = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "textformat.alt")
                .font(.system(size: 64, weight: .light))
                .foregroundStyle(AgePonyColors.tealCore)

            Text("Text")
                .font(AgePonyTypography.largeTitle)

            Text("Encrypt or decrypt a block of text. Useful for pasting into chat, email, or anywhere binary attachments are awkward.")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()

            VStack(spacing: 14) {
                Button {
                    showEncrypt = true
                } label: {
                    Label("Encrypt text", systemImage: "lock.fill")
                }
                .buttonStyle(.agePonyPrimary)

                Button {
                    showDecrypt = true
                } label: {
                    Label("Decrypt text", systemImage: "lock.open.fill")
                }
                .buttonStyle(.agePonySecondary)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 32)
        }
        .sheet(isPresented: $showEncrypt) {
            NavigationStack {
                TextEncryptView(vault: vault)
            }
        }
        .sheet(isPresented: $showDecrypt) {
            NavigationStack {
                TextDecryptView(vault: vault)
            }
        }
    }
}
