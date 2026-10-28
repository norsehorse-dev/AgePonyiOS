//
//  KeyPickerText.swift
//  AgePony
//
//  How a key reads where one is picked (5.1.0 item 3, PLANNED_FEATURES item 1): its
//  name, its type in words, and enough of its public key to tell two keys with the
//  same name apart. Rows in a list show the public string on its own line, truncated
//  in the middle, exactly as the Identities and Recipients lists do. A menu picker
//  gets one line of text per option, so it uses this instead.
//

import Foundation

enum KeyPickerText {

    /// One line for a menu picker: `Work · age X25519 · age1qyqszqgpqyqs…7k3m3x9a`.
    /// The key part is the short form the key-transfer preview already uses
    /// (`KeyPortability.keySummary`): the public string shortened in the middle, or the
    /// SHA256 fingerprint for SSH keys, whose public lines all start the same way.
    static func menuLine(_ identity: StoredIdentity) -> String {
        line(name: identity.name, type: identity.type.sectionTitle, key: KeyPortability.keySummary(identity))
    }

    static func menuLine(_ recipient: StoredRecipient) -> String {
        line(name: recipient.name, type: recipient.type.sectionTitle, key: KeyPortability.keySummary(recipient))
    }

    private static func line(name: String, type: String, key: String) -> String {
        String(localized: "\(name) · \(type) · \(key)",
               comment: "One option in a key picker menu: the key's name, its type, and a short form of its public key.")
    }
}
