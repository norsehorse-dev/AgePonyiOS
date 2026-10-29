//
//  PivSession.swift
//  AgePonyCore
//
//  What the app does with a YubiKey in one NFC tap, on top of the APDU layer in
//  Piv.swift: read the key a stub points at, or run the ECDHs a file needs. Kept
//  here, against the `PivCard` protocol, so it is tested with the simulated card;
//  the app only supplies the transport (`BlockPivCard` over CoreNFC).
//
//  Mirrors the YubiKey flow in Android's `security/piv`.
//

import Foundation

/// A `PivCard` over a closure, for transports that live outside the core.
public struct BlockPivCard: PivCard {
    let block: (Data) throws -> Data

    public init(_ transmit: @escaping (Data) throws -> Data) { self.block = transmit }

    public func transmit(_ apdu: Data) throws -> Data { try block(apdu) }
}

public enum PivSession {

    /// Select the PIV applet and check the serial against the stub's, when the key
    /// reports one (YubiKey 5 does; older firmware may not).
    static func open(_ card: PivCard, stub: YubiKeyStub) throws {
        try Piv.select(card)
        if let found = try Piv.serial(card), found != stub.serial {
            throw YubiKeyError.wrongYubiKey(expected: stub.serial, found: found)
        }
    }

    /// Read the compressed public key in the stub's slot and check it is the key
    /// the stub names.
    public static func readKey(_ card: PivCard, stub: YubiKeyStub) throws -> Data {
        try open(card, stub: stub)
        let key = try Piv.readPublicKey(card, slot: stub.slot)
        guard stub.matchesKey(compressedPublicKey: key) else { throw YubiKeyError.keyDoesNotMatchStub }
        return key
    }

    /// `readKey`, plus the slot's PIN policy from GET METADATA in the same tap (5.1.0
    /// item 1). Firmware before 5.3 doesn't have the command and gives `.unknown`; a
    /// failed metadata read never fails the key read.
    public static func readKeyAndPINPolicy(_ card: PivCard, stub: YubiKeyStub) throws -> (key: Data, pinPolicy: YubiKeyPINPolicy) {
        let key = try readKey(card, stub: stub)
        let policy = (try? Piv.pinPolicy(card, slot: stub.slot)) ?? .unknown
        return (key, policy)
    }

    /// Run one ECDH per point in the stub's slot and return the shared x-coordinates
    /// keyed by point, for a `RecordedKeyAgreement`. With `pin`, the PIN is verified
    /// first; without it, a slot whose PIN policy wants one throws `.pinRequired`
    /// and the app asks for it and taps again. At most `Age.maxStanzasPerHardwareIdentity`
    /// points are used, matching `YubiKeyIdentity.peerPoints` (5.1.1, L-7).
    public static func keyAgreements(_ card: PivCard, stub: YubiKeyStub, points: [Data], pin: String?) throws -> [Data: Data] {
        try open(card, stub: stub)
        if let pin { try Piv.verifyPIN(card, pin: pin) }
        var results: [Data: Data] = [:]
        for point in points.prefix(Age.maxStanzasPerHardwareIdentity) where results[point] == nil {
            results[point] = try Piv.ecdh(card, slot: stub.slot, peerUncompressed: point)
        }
        return results
    }
}

extension YubiKeyIdentity {
    /// An identity that can only say which stanzas are its own (public data), for
    /// working out whether a file needs the YubiKey before asking for a tap.
    public static func probe(stub: YubiKeyStub, publicKey: Data) throws -> YubiKeyIdentity {
        try YubiKeyIdentity(stub: stub, publicKey: publicKey, keyAgreement: RecordedKeyAgreement(results: [:]))
    }
}

extension YubiKeyStub {
    /// What an `age-plugin-yubikey` identity file (or a bare stub line) holds: the
    /// stub; when the file has its `# Recipient:` comment, the public key, which saves a
    /// tap on import; and the slot's PIN policy from its `#    PIN policy:` comment
    /// (5.1.0 item 1), `.unknown` without one. A recipient that doesn't belong to the
    /// stub is ignored.
    public static func parseIdentityFile(_ text: String) throws -> (stub: YubiKeyStub, publicKey: Data?, pinPolicy: YubiKeyPINPolicy) {
        var stub: YubiKeyStub?
        var recipientKey: Data?
        var pinPolicy = YubiKeyPINPolicy.unknown
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") {
                if let r = line.range(of: "age1yubikey1", options: .caseInsensitive) {
                    let token = line[r.lowerBound...].prefix { !$0.isWhitespace }
                    recipientKey = try? P256Recipient(ageRecipient: String(token).lowercased()).compressedPublicKey
                } else if stub == nil, let value = pinPolicyComment(line) {
                    // Comments come before their stub: only the first identity's
                    // block counts, as only the first stub is read.
                    pinPolicy = YubiKeyPINPolicy(identityFileValue: value)
                }
            } else if stub == nil, isStub(line) {
                stub = try YubiKeyStub(parsing: line)
            }
        }
        guard let stub else { throw YubiKeyError.notAStub }
        if let key = recipientKey, stub.matchesKey(compressedPublicKey: key) {
            return (stub, key, pinPolicy)
        }
        return (stub, nil, pinPolicy)
    }

    /// The text after `PIN policy:` in a comment line, or nil for any other line.
    static func pinPolicyComment(_ line: String) -> String? {
        let body = line.drop { $0 == "#" }.trimmingCharacters(in: .whitespaces)
        let label = "PIN policy:"
        guard body.lowercased().hasPrefix(label.lowercased()) else { return nil }
        return String(body.dropFirst(label.count))
    }
}
