//
//  AgePonyShortcuts.swift
//  AgePony — App Intents
//
//  Registers AgePony's App Intents as App Shortcuts so they appear in the
//  Shortcuts app, Spotlight, and Siri without the user building anything. As
//  more intents are added (recipient encrypt, decrypt, sign), they're listed
//  here too.
//

import AppIntents

@available(iOS 16.0, *)
struct AgePonyShortcuts: AppShortcutsProvider {

    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: EncryptWithPassphraseIntent(),
            phrases: [
                "Encrypt a file with \(.applicationName)",
                "Passphrase encrypt with \(.applicationName)"
            ],
            shortTitle: "Encrypt with Passphrase",
            systemImageName: "lock.doc"
        )
    }
}
