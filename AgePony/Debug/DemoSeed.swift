//
//  DemoSeed.swift
//  AgePony
//
//  UI-test-only demo data for App Store screenshots, compiled out of Release
//  builds (the whole file is behind `#if DEBUG`). fastlane snapshot launches
//  with `-seedDemoVault`; RootView then skips onboarding and the lock screen
//  and opens a fresh demo vault, so the test never depends on what an earlier
//  run left on the simulator (snapshot reuses the install between runs).
//
//  The vault is No lock with no password: the simulator has no passcode, so
//  the default Face ID lock can't be stored there anyway (plan 2.8).
//
//  Every name here is demo data, not UI chrome; the snapshot test finds rows
//  by these strings. Keep `SnapshotTests.swift` in sync if any change.
//

#if DEBUG
import Foundation
import AgePonyCore

enum DemoSeed {

    static var requested: Bool {
        ProcessInfo.processInfo.arguments.contains("-seedDemoVault")
    }

    /// Wipe whatever an earlier run left, then build a populated vault and
    /// leave it unlocked.
    @MainActor
    static func seed(into vault: Vault) async {
        try? vault.reset()
        do {
            try await vault.bootstrap(lockMode: .none)
            vault.hasCompletedOnboarding = true
            vault.hasSeenWalkthrough = true

            let personal = X25519Identity.generate()
            let personalStored = try vault.addIdentity(StoredIdentity(
                name: "Personal", type: .x25519,
                publicKeyMaterial: personal.publicKey, privateKeyMaterial: personal.privateKey))

            let pq = try HybridIdentity.generate()
            try vault.addIdentity(StoredIdentity(
                name: "Quantum-safe", type: .postQuantum,
                publicKeyMaterial: pq.publicKey, privateKeyMaterial: pq.seed))

            let (seed, pub) = OpenSSHEd25519Export.generate()
            try vault.addIdentity(StoredIdentity(
                name: "Work laptop", type: .sshEd25519,
                publicKeyMaterial: SSHSig.ed25519PublicKeyWire(pub), privateKeyMaterial: seed + pub,
                sshComment: "work-laptop"))
            vault.activeIdentityID = personalStored.id

            let alice = X25519Identity.generate()
            try vault.addRecipient(StoredRecipient(
                name: "Alice", type: .x25519, publicKeyMaterial: alice.publicKey, source: .qrScan))
            let team = try HybridIdentity.generate()
            try vault.addRecipient(StoredRecipient(
                name: "Team backup key", type: .postQuantum, publicKeyMaterial: team.publicKey, source: .pasteAge))
            let (_, bobPub) = OpenSSHEd25519Export.generate()
            try vault.addRecipient(StoredRecipient(
                name: "Bob (GitHub)", type: .sshEd25519, publicKeyMaterial: SSHSig.ed25519PublicKeyWire(bobPub),
                sshComment: "bob", source: .github))

            let (_, signerPub) = OpenSSHEd25519Export.generate()
            try vault.addSigner(StoredSigner(
                name: "Release signing", keyType: "ssh-ed25519",
                publicKeyWire: SSHSig.ed25519PublicKeyWire(signerPub), source: .pasteKey))

            for (title, body) in [("Recovery phrase", "demo recovery words"),
                                  ("Server credentials", "demo server login"),
                                  ("Guest Wi-Fi", "demo network password")] {
                let sealed = try Age.encrypt(plaintext: Data(body.utf8), passphrase: "demo passphrase", workFactor: 16)
                _ = try vault.addNote(StoredNote(title: title, bodyCiphertext: sealed))
            }
        } catch {
            assertionFailure("Demo seed failed: \(error)")
        }
    }
}
#endif
