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
//  The PIN comes before the tap (5.1.0 item 1). A key whose policy is required
//  or not known yet gets the PIN prompt first and then one tap that runs VERIFY
//  and the ECDHs; a key known to need no PIN gets one tap without it. What a tap
//  learns about the policy is written back to the vault. The PIN itself is only
//  ever held by the calling flow for one decrypt, never stored.
//

import SwiftUI
import AgePonyCore

/// What the YubiKey PIN prompt gave back, for one decrypt only.
enum YubiKeyPINEntry: Equatable {
    case pin(String)
    /// "This key has no PIN": tap without one.
    case noPIN
}

enum DecryptIdentities {

    enum Outcome {
        case ready([any AgeIdentity])
        /// Show the YubiKey PIN prompt (with this note, and with "This key has no
        /// PIN" when `offersNoPIN`), then call `prepare` again with the answer.
        case needsPIN(note: String?, offersNoPIN: Bool)
        /// The user closed the NFC sheet.
        case cancelled
        case failed(String)
    }

    /// `yubiKeyPIN` is nil on the first call; the flow passes the prompt's answer
    /// after `.needsPIN`, and drops it once this returns.
    @MainActor
    static func prepare(vault: Vault, stanzas: [Stanza], yubiKeyPIN: YubiKeyPINEntry?) async -> Outcome {
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
        let policy = need.identity.yubiKeyPINPolicy
        let pin: String?
        switch yubiKeyPIN {
        case .some(.pin(let entered)):
            // A PIN of the wrong length would only fail on the key and could
            // spend a try: ask again without a tap.
            guard pinLengthIsValid(entered) else {
                return .needsPIN(note: YubiKeyDecrypt.message(for: PivError.pinLength), offersNoPIN: policy == .unknown)
            }
            pin = entered
        case .some(.noPIN):
            pin = nil
        case .none:
            // Decide before the tap: only a key known to need no PIN is tapped
            // without asking first.
            guard policy == .notRequired else {
                return .needsPIN(note: nil, offersNoPIN: policy == .unknown)
            }
            pin = nil
        }
        do {
            let tapped = try await YubiKeyDecrypt.identity(for: need, pin: pin,
                                                           readPINPolicy: pin != nil && policy == .unknown)
            identities.append(tapped.identity)
            if pin == nil {
                learn(.notRequired, for: need, vault: vault)
            } else if tapped.pinPolicy != .unknown {
                learn(tapped.pinPolicy, for: need, vault: vault)
            }
            return .ready(identities)
        } catch {
            if YubiKeyDecrypt.needsPIN(error) {
                // Tapped without a PIN and the key wants one after all (its policy
                // changed, or "This key has no PIN" was wrong): ask, then tap again.
                learn(.required, for: need, vault: vault)
                return .needsPIN(note: YubiKeyDecrypt.message(for: error), offersNoPIN: false)
            }
            if let e = error as? PivError, case .wrongPIN(let left) = e, left > 0 {
                return .needsPIN(note: YubiKeyDecrypt.message(for: error), offersNoPIN: policy == .unknown)
            }
            if YubiKeyDecrypt.isCancelled(error) { return .cancelled }
            return .failed(YubiKeyDecrypt.message(for: error))
        }
    }

    /// A YubiKey PIV PIN is 6 to 8 characters (bytes as sent to the key).
    nonisolated static func pinLengthIsValid(_ pin: String) -> Bool {
        (6...8).contains(pin.utf8.count)
    }

    /// Write a learned PIN policy back to the vault. Best effort: if it can't be
    /// saved, the next decrypt just asks the way it did this time.
    @MainActor
    private static func learn(_ policy: YubiKeyPINPolicy, for need: YubiKeyDecrypt.Need, vault: Vault) {
        try? vault.setYubiKeyPINPolicy(policy, forIdentity: need.identity.id)
    }
}

extension View {
    /// The YubiKey PIV PIN prompt, shown before the tap. `onSubmit` gets the PIN, or
    /// `.noPIN` from "This key has no PIN" (shown when `offersNoPIN`); the flow then
    /// calls `DecryptIdentities.prepare` again, which taps.
    func yubiKeyPINPrompt(isPresented: Binding<Bool>, note: String?, offersNoPIN: Bool,
                          onSubmit: @escaping (YubiKeyPINEntry) -> Void) -> some View {
        modifier(YubiKeyPINPrompt(isPresented: isPresented, note: note, offersNoPIN: offersNoPIN, onSubmit: onSubmit))
    }
}

private struct YubiKeyPINPrompt: ViewModifier {
    @Binding var isPresented: Bool
    let note: String?
    let offersNoPIN: Bool
    let onSubmit: (YubiKeyPINEntry) -> Void
    @State private var pin = ""

    func body(content: Content) -> some View {
        content.alert("YubiKey PIN", isPresented: $isPresented) {
            SecureField("PIN", text: $pin)
                .textContentType(.oneTimeCode)
            Button("Continue") {
                let entered = pin
                pin = ""
                onSubmit(.pin(entered))
            }
            if offersNoPIN {
                Button("This key has no PIN") {
                    pin = ""
                    onSubmit(.noPIN)
                }
            }
            Button("Cancel", role: .cancel) { pin = "" }
        } message: {
            if let note {
                Text("\(note) Enter the PIV PIN for this YubiKey, then hold the key to the top of your iPhone. AgePony keeps the PIN only until this decrypt is done.")
            } else {
                Text("Enter the PIV PIN for this YubiKey, then hold the key to the top of your iPhone. AgePony keeps the PIN only until this decrypt is done.")
            }
        }
    }
}
