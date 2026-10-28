//
//  YubiKeyDecrypt.swift
//  AgePony
//
//  YubiKey (age-plugin-yubikey) keys over NFC (5.0.1). Two jobs, one tap each:
//
//    - On import, read the public key the stub points at and check it belongs,
//      and the slot's PIN policy (GET METADATA, 5.1.0).
//    - On decrypt, run the ECDHs the file's header needs. The age code is
//      synchronous and NFC isn't, so the tap happens first and the results go
//      into a `RecordedKeyAgreement`; the decrypt then runs as usual. Whether the
//      PIN is asked for before the tap is decided in `DecryptIdentities.prepare`
//      from the identity's stored PIN policy (5.1.0 item 1).
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

    /// What one decrypt tap gave: the identity that opens the file, and the slot's PIN
    /// policy when the tap read it (`.unknown` otherwise).
    struct Tapped {
        let identity: any AgeIdentity
        let pinPolicy: YubiKeyPINPolicy
    }

    /// Tap the YubiKey and build the identity that opens the file. With `pin`, VERIFY
    /// runs first in the same tap. `readPINPolicy` also sends GET METADATA, for a key
    /// whose policy isn't known yet; a failed read leaves it `.unknown`.
    static func identity(for need: Need, pin: String?, readPINPolicy: Bool) async throws -> Tapped {
        let (results, policy) = try await runPiv(alert: "Hold your YubiKey to the top of your iPhone to decrypt.") { (card: PivCard) -> ([Data: Data], YubiKeyPINPolicy) in
            let results = try PivSession.keyAgreements(card, stub: need.stub, points: need.points, pin: pin)
            let policy = readPINPolicy ? ((try? Piv.pinPolicy(card, slot: need.stub.slot)) ?? .unknown) : .unknown
            return (results, policy)
        }
        let identity = try YubiKeyIdentity(stub: need.stub, publicKey: need.identity.publicKeyMaterial,
                                           keyAgreement: RecordedKeyAgreement(results: results))
        return Tapped(identity: identity, pinPolicy: policy)
    }

    /// Tap the YubiKey and read the public key in the stub's slot, plus the slot's PIN
    /// policy (`.unknown` on firmware before 5.3).
    static func readKey(stub: YubiKeyStub) async throws -> (key: Data, pinPolicy: YubiKeyPINPolicy) {
        try await runPiv(alert: "Hold your YubiKey to the top of your iPhone to read its key.") { card in
            try PivSession.readKeyAndPINPolicy(card, stub: stub)
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

    /// Words for an error from either of the above. The PIV, YubiKey and NFC
    /// mappings live in `UserMessage` with every other error (5.1.0, U5).
    static func message(for error: Error) -> String {
        UserMessage.text(for: error, fallback: String(localized: "The YubiKey couldn't be read."))
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
