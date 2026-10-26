//
//  DecryptIdentities.swift
//  AgePony
//
//  The identities a decrypt flow hands to age, shared by Files, Text and
//  Re-encrypt (5.0.1):
//
//    - every vault identity that can decrypt in-process, Secure Enclave keys
//      included, given the context of the prompt the flow just showed so a key
//      that wants Face ID for each use doesn't ask twice;
//    - plus a YubiKey, when the file is addressed to one in the vault and
//      nothing else can open it. That costs a tap (and the PIN when the key's
//      policy wants it), done here before the synchronous decrypt.
//

import SwiftUI
import AgePonyCore

enum DecryptIdentities {

    enum Outcome {
        case ready([any AgeIdentity])
        /// The YubiKey wants its PIN; show the prompt (with this note) and retry.
        case needsPIN(note: String?)
        /// The user closed the NFC sheet.
        case cancelled
        case failed(String)
    }

    @MainActor
    static func prepare(vault: Vault, stanzas: [Stanza], yubiKeyPIN: String?) async -> Outcome {
        let context = BiometricGate.recentContext()
        // Software keys first (plan 2.7, as Android): a file also encrypted to a
        // normal key opens with it, without touching the Secure Enclave.
        let ordered = vault.identities.filter { !$0.isHardwareDecryptionKey }
            + vault.identities.filter { $0.isHardwareDecryptionKey }
        var identities: [any AgeIdentity] = ordered.compactMap {
            try? $0.toAgeIdentity(authenticationContext: context)
        }
        guard let need = YubiKeyDecrypt.need(stanzas: stanzas, identities: vault.identities, others: identities) else {
            return .ready(identities)
        }
        do {
            identities.append(try await YubiKeyDecrypt.identity(for: need, pin: yubiKeyPIN))
            return .ready(identities)
        } catch {
            if YubiKeyDecrypt.needsPIN(error) { return .needsPIN(note: nil) }
            if let e = error as? PivError, case .wrongPIN(let left) = e, left > 0 {
                return .needsPIN(note: YubiKeyDecrypt.message(for: error))
            }
            if YubiKeyDecrypt.isCancelled(error) { return .cancelled }
            return .failed(YubiKeyDecrypt.message(for: error))
        }
    }
}

extension View {
    /// The YubiKey PIV PIN prompt. `onSubmit` gets the PIN; the flow taps again.
    func yubiKeyPINPrompt(isPresented: Binding<Bool>, note: String?, onSubmit: @escaping (String) -> Void) -> some View {
        modifier(YubiKeyPINPrompt(isPresented: isPresented, note: note, onSubmit: onSubmit))
    }
}

private struct YubiKeyPINPrompt: ViewModifier {
    @Binding var isPresented: Bool
    let note: String?
    let onSubmit: (String) -> Void
    @State private var pin = ""

    func body(content: Content) -> some View {
        content.alert("YubiKey PIN", isPresented: $isPresented) {
            SecureField("PIN", text: $pin)
                .textContentType(.oneTimeCode)
            Button("Cancel", role: .cancel) { pin = "" }
            Button("Continue") {
                let entered = pin
                pin = ""
                onSubmit(entered)
            }
        } message: {
            Text((note.map { $0 + " " } ?? "") + "Enter the PIV PIN for this YubiKey, then hold it to your iPhone again. AgePony keeps it only until this decrypt is done.")
        }
    }
}
