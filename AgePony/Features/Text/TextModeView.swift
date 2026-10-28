//
//  TextModeView.swift
//  AgePony
//
//  Text-tab landing. Mirrors FilesView shape, but in-memory: paste a text
//  blob → encrypt → get armored output to paste anywhere. Reverse for
//  decrypt. No file picker, no share sheet; copy-to-clipboard is the
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
        List {
            Section {
                row("Encrypt text", systemImage: "lock") { showEncrypt = true }
                row("Decrypt text", systemImage: "lock.open") { showDecrypt = true }
            } footer: {
                Text("Encrypted text is armored, so you can paste it into a chat, an email or anywhere an attachment is awkward.")
            }
        }
        .textCase(nil)
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

    /// One action. Opens its screen as a sheet, so there's no chevron.
    private func row(_ title: LocalizedStringKey, systemImage: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
        }
        .foregroundStyle(.primary)
    }
}
