//
//  KeyPickerTextTests.swift
//  AgePonyTests
//
//  5.1.0 item 3 (PLANNED_FEATURES item 1): two keys with the same name and the same
//  type must read differently in a picker. Menu pickers show `KeyPickerText.menuLine`;
//  list rows show `publicDisplayString()` on its own line.
//

import Testing
import Foundation
import AgePonyCore
@testable import AgePony

@MainActor
struct KeyPickerTextTests {

    private func x25519(_ name: String) -> StoredIdentity {
        let id = X25519Identity.generate()
        return StoredIdentity(name: name, type: .x25519, publicKeyMaterial: id.publicKey, privateKeyMaterial: id.privateKey)
    }

    private func ed25519(_ name: String, comment: String) -> StoredIdentity {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        return StoredIdentity(name: name, type: .sshEd25519, publicKeyMaterial: SSHSig.ed25519PublicKeyWire(pub),
                              privateKeyMaterial: seed + pub, sshComment: comment)
    }

    @Test func sameNameSameType_identitiesDiffer() {
        let a = x25519("Work"), b = x25519("Work")
        #expect(KeyPickerText.menuLine(a) != KeyPickerText.menuLine(b))
        #expect(a.publicDisplayString() != b.publicDisplayString())
        // Name and type in words are both there.
        #expect(KeyPickerText.menuLine(a).contains("Work"))
        #expect(KeyPickerText.menuLine(a).contains(StoredIdentityType.x25519.sectionTitle))
    }

    @Test func sameNameSameComment_sshIdentitiesDiffer() {
        // Every ssh-ed25519 line starts the same way and these end the same way, so the
        // menu line has to carry the fingerprint rather than the start of the key.
        let a = ed25519("Laptop", comment: "me@laptop"), b = ed25519("Laptop", comment: "me@laptop")
        let lineA = KeyPickerText.menuLine(a), lineB = KeyPickerText.menuLine(b)
        #expect(lineA != lineB)
        #expect(lineA.contains("SHA256:"))
    }

    @Test func sameNameSameType_recipientsDiffer() {
        let a = StoredRecipient(name: "Work", type: .x25519, publicKeyMaterial: X25519Identity.generate().publicKey, source: .pasteAge)
        let b = StoredRecipient(name: "Work", type: .x25519, publicKeyMaterial: X25519Identity.generate().publicKey, source: .pasteAge)
        #expect(KeyPickerText.menuLine(a) != KeyPickerText.menuLine(b))
        #expect(a.publicDisplayString() != b.publicDisplayString())
    }
}
