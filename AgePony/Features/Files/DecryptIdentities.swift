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
//  A tag match on a Secure Enclave key no longer skips the tap (5.1.1, M-4).
//  When the file is also addressed to one, that key is tried for real first; if
//  it can't open the file (a key a Face ID change destroyed, a lockout, a
//  cancelled prompt), the tap is offered instead of failing on the Enclave error.
//
//  The PIN comes before the tap (5.1.0 item 1). A key whose policy is required
//  or not known yet gets the PIN prompt first and then one tap that runs VERIFY
//  and the ECDHs; a key known to need no PIN gets one tap without it. What a tap
//  learns about the policy is written back to the vault. The PIN itself is only
//  ever held by the calling flow for one decrypt, never stored.
//

import SwiftUI
import LocalAuthentication
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
        let software = vault.identities.filter { !$0.isHardwareDecryptionKey }
        let hardware = vault.identities.filter { $0.isHardwareDecryptionKey }
        var identities: [any AgeIdentity] = (software + hardware).compactMap {
            try? $0.toAgeIdentity(authenticationContext: context)
        }
        // Only software keys count here (5.1.1, M-4): a Secure Enclave key is
        // counted on its tag alone, which says nothing about whether it still works.
        guard let need = YubiKeyDecrypt.need(stanzas: stanzas, identities: vault.identities, others: identities) else {
            return .ready(identities)
        }
        // The file is addressed to an Enclave key too: try it before asking for the
        // tap (5.1.1, M-4). Skipped on the call after the PIN prompt, which only
        // comes once this has already failed.
        if yubiKeyPIN == nil, enclaveIsAddressed(stanzas: stanzas, identities: identities) {
            if context == nil {
                // One context for the try and the decrypt, so a key that asks for
                // Face ID each use asks once.
                let shared = LAContext()
                identities = (software + hardware).compactMap {
                    try? $0.toAgeIdentity(authenticationContext: shared)
                }
            }
            let tryIdentities = identities
            let opened = await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
                // An Enclave operation can wait on a system prompt: keep it off the main thread.
                DispatchQueue.global(qos: .userInitiated).async {
                    cont.resume(returning: DecryptIdentities.enclaveOpens(stanzas: stanzas, identities: tryIdentities))
                }
            }
            if opened { return .ready(identities) }
        }
        // The tapped YubiKey opens the file, so leave the Enclave keys out: one that
        // just failed would only fail or prompt again (5.1.1, M-4).
        identities = identities.filter { !($0 is HardwareIdentity) }
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

    /// Whether a Secure Enclave identity in `identities` is addressed by one of
    /// `stanzas`, from its tag alone (5.1.1, M-4).
    nonisolated static func enclaveIsAddressed(stanzas: [Stanza], identities: [any AgeIdentity]) -> Bool {
        identities.contains { id in
            guard let hw = id as? HardwareIdentity else { return false }
            return stanzas.contains { hw.matches(stanza: $0) }
        }
    }

    /// Whether a Secure Enclave identity actually opens one of `stanzas` (5.1.1,
    /// M-4). Runs the Enclave, so it can prompt. Any error (a key destroyed by a
    /// Face ID change, a lockout, a cancelled prompt) counts as "doesn't open", so
    /// the caller offers the YubiKey tap instead.
    /// Bounded like the decrypt (5.1.1, L-7): a key that throws isn't asked again,
    /// and each key tries at most `Age.maxStanzasPerHardwareIdentity` stanzas.
    nonisolated static func enclaveOpens(stanzas: [Stanza], identities: [any AgeIdentity]) -> Bool {
        let hardware: [any HardwareIdentity] = identities.compactMap { $0 as? HardwareIdentity }
        var tries = [Int](repeating: 0, count: hardware.count)
        var failed = [Bool](repeating: false, count: hardware.count)
        for stanza in stanzas {
            for (i, hw) in hardware.enumerated() where !failed[i] && hw.matches(stanza: stanza) {
                guard tries[i] < Age.maxStanzasPerHardwareIdentity else { continue }
                tries[i] += 1
                do {
                    if let key = try hw.unwrap(stanza: stanza), key.count == Age.fileKeySize { return true }
                } catch {
                    failed[i] = true
                }
            }
        }
        return false
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
