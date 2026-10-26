//
//  YubiKeyDecrypt.swift
//  AgePony
//
//  YubiKey (age-plugin-yubikey) keys over NFC (5.0.1). Two jobs, one tap each:
//
//    - On import, read the public key the stub points at and check it belongs.
//    - On decrypt, run the ECDHs the file's header needs. The age code is
//      synchronous and NFC isn't, so the tap happens first and the results go
//      into a `RecordedKeyAgreement`; the decrypt then runs as usual.
//
//  The tap is only asked for when the file is addressed to a YubiKey in the vault
//  (tag match first) and nothing else in the vault can open it, so a file with a
//  software recipient as well never needs the key. NFC only, matching Android;
//  USB-C and Lightning come later on both platforms.
//
//  The PIV logic itself (select, serial check, PIN, ECDH) is AgePonyCore's
//  `PivSession`, tested there against a simulated card.
//

import Foundation
import AgePonyCore
#if canImport(CoreNFC)
import CoreNFC
#endif

enum YubiKeyDecrypt {

    /// A file's need for a YubiKey tap: which key, and the points it must ECDH.
    struct Need {
        let identity: StoredIdentity
        let stub: YubiKeyStub
        let points: [Data]
    }

    /// The YubiKey tap `stanzas` need, or nil when there's none to ask for: no
    /// YubiKey in `identities` is addressed, or something else can open the file.
    /// `others` are the identities that will be tried without a tap.
    static func need(stanzas: [Stanza], identities: [StoredIdentity], others: [any AgeIdentity]) -> Need? {
        for stored in identities where stored.type == .yubikey {
            guard let stub = stored.yubiKeyStub,
                  let probe = try? YubiKeyIdentity.probe(stub: stub, publicKey: stored.publicKeyMaterial) else { continue }
            let points = probe.peerPoints(in: stanzas)
            guard !points.isEmpty else { continue }
            // A software key, or a Secure Enclave key addressed by the file, opens it without a tap.
            if (try? Age.anyOpens(stanzas: stanzas, identities: others)) == true { return nil }
            return Need(identity: stored, stub: stub, points: points)
        }
        return nil
    }

    /// Tap the YubiKey and build the identity that opens the file.
    static func identity(for need: Need, pin: String?) async throws -> any AgeIdentity {
        let results = try await runPiv(alert: "Hold your YubiKey to the top of your iPhone to decrypt.") { card in
            try PivSession.keyAgreements(card, stub: need.stub, points: need.points, pin: pin)
        }
        return try YubiKeyIdentity(stub: need.stub, publicKey: need.identity.publicKeyMaterial,
                                   keyAgreement: RecordedKeyAgreement(results: results))
    }

    /// Tap the YubiKey and read the public key in the stub's slot.
    static func readKey(stub: YubiKeyStub) async throws -> Data {
        try await runPiv(alert: "Hold your YubiKey to the top of your iPhone to read its key.") { card in
            try PivSession.readKey(card, stub: stub)
        }
    }

    /// Whether `error` means the YubiKey wants its PIN (ask and tap again).
    static func needsPIN(_ error: Error) -> Bool {
        (error as? PivError) == .pinRequired
    }

    /// Whether the user closed the NFC sheet.
    static func isCancelled(_ error: Error) -> Bool {
        #if canImport(CoreNFC)
        if let e = error as? SecurityKeyError, case .cancelled = e { return true }
        #endif
        return false
    }

    /// Words for an error from either of the above.
    static func message(for error: Error) -> String {
        if let e = error as? PivError {
            switch e {
            case .pinRequired:            return "This YubiKey key needs its PIN."
            case .wrongPIN(let left) where left == 0:
                return "The PIV PIN is blocked. Unblock it with the PUK in YubiKey Manager."
            case .wrongPIN(let left):     return "Wrong PIN. \(left) \(left == 1 ? "try" : "tries") left before it locks."
            case .pinLength:              return "A YubiKey PIN is 6 to 8 characters."
            case .notPIV:                 return "That key has no PIV applet."
            case .noKeyInSlot:            return "That YubiKey has no key in the slot this identity uses."
            case .notP256:                return "The key in that slot isn't a P-256 key."
            case .refused(let sw):        return String(format: "The YubiKey refused (status %04X).", sw)
            case .malformedResponse(let m): return "The YubiKey's answer didn't make sense: \(m)"
            }
        }
        if let e = error as? YubiKeyError {
            switch e {
            case .wrongYubiKey(let expected, let found):
                return "That's YubiKey \(found). This identity is on YubiKey \(expected)."
            case .keyDoesNotMatchStub:    return "The key in that slot isn't the one this identity points at."
            case .notAStub, .malformedStub: return "That isn't an age-plugin-yubikey identity (AGE-PLUGIN-YUBIKEY-1…)."
            case .notARetiredSlot:        return "That identity points at a slot age-plugin-yubikey doesn't use."
            }
        }
        #if canImport(CoreNFC)
        if let e = error as? SecurityKeyError { return e.errorDescription ?? "The YubiKey couldn't be read." }
        #endif
        return error.localizedDescription
    }

    // MARK: - Transport

    private static func runPiv<T>(alert: String, _ work: @escaping (PivCard) throws -> T) async throws -> T {
        #if canImport(CoreNFC)
        return try await SecurityKeyTransport.run(alertMessage: alert, applet: pivAppletAID) { channel in
            // The PIV code is synchronous: run it on a worker thread, blocking on
            // each APDU while the NFC session's own queue delivers the answers.
            try await withCheckedThrowingContinuation { cont in
                DispatchQueue.global(qos: .userInitiated).async {
                    let card = BlockPivCard { try channel.transmitBlocking($0) }
                    do { cont.resume(returning: try work(card)) } catch { cont.resume(throwing: error) }
                }
            }
        }
        #else
        throw YubiKeyError.notAStub
        #endif
    }
}
