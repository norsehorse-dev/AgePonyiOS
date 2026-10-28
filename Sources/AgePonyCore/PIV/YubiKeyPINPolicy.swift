//
//  YubiKeyPINPolicy.swift
//  AgePonyCore
//
//  Whether a YubiKey PIV slot wants the PIN before it will do an ECDH (5.1.0 item 1).
//  The 9-byte stub doesn't say, so the app learns it from the identity file's comment,
//  from GET METADATA on the import tap, or from what a decrypt tap answers, and asks for
//  the PIN before the tap when the key needs one.
//
//  Raw values are what the vault and `agepony.json` store (`pinPolicy`); a missing value
//  means `unknown`.
//

import Foundation

public enum YubiKeyPINPolicy: String, Codable, Sendable, Equatable, CaseIterable {
    /// Not known yet (a 5.0.1 identity, a bare stub on old firmware). Ask for the PIN
    /// first, with a way to say the key has none.
    case unknown
    /// PIN policy Once or Always (age-plugin-yubikey's default is Once). Every NFC tap
    /// is a new PIV session, so either one needs the PIN on every tap.
    case required
    /// PIN policy Never: one tap, no PIN.
    case notRequired

    /// A value this version doesn't know (written by a newer one) reads as `.unknown`
    /// instead of failing the whole record, so the vault and a transfer still open.
    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = YubiKeyPINPolicy(rawValue: raw) ?? .unknown
    }

    /// The value of age-plugin-yubikey's `#    PIN policy: Never|Once|Always` comment.
    /// Takes the first word, so `Once   (A PIN is required once per session, if set)`
    /// reads as `Once`.
    public init(identityFileValue: String) {
        let word = identityFileValue.trimmingCharacters(in: .whitespaces)
            .prefix { !$0.isWhitespace }
            .lowercased()
        switch word {
        case "never": self = .notRequired
        case "once", "always": self = .required
        default: self = .unknown
        }
    }

    /// Byte 0 of tag 02 in a GET METADATA answer: 1 never, 2 once, 3 always, 0 the
    /// slot's default (a PIN for the retired key-management slots). 4 and 5 are the
    /// Bio "match" policies, which also gate the key.
    public init(metadataByte: UInt8) {
        switch metadataByte {
        case 1: self = .notRequired
        case 0, 2, 3, 4, 5: self = .required
        default: self = .unknown
        }
    }
}
