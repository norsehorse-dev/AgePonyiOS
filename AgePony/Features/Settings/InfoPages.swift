//
//  InfoPages.swift
//  AgePony
//
//  In-app Help (FAQ), Security, and Licenses pages (4.0.0). Reached from
//  Settings. Plain-language, on-device, no external links needed to read them.
//

import SwiftUI

// MARK: - Help (FAQ)

struct HelpView: View {
    var body: some View {
        Form {
            faq("What is AgePony?",
                "AgePony encrypts and decrypts files and text on your device using the age format, and signs and verifies them with SSH keys. Nothing is uploaded. There is no account and no server.")

            faq("Where are my keys stored?",
                "In an encrypted vault on this device only. There is no cloud copy. To keep a key safe off the phone, make a paper backup of it or send it to another device you own. Without one of those, deleting the app or losing the phone takes the keys with it.")

            faq("How do I move my keys to another phone?",
                "On the new phone open Settings › Receive keys from another device, and on the old one Settings › Send keys to another device. Scan the code and check both phones show the same codes. On the same Wi-Fi the keys go straight across; otherwise you get a file to move any way you like. Either way they're encrypted to a one-time key on the receiving phone. It works between iPhone and Android.")

            faq("What is a paper backup?",
                "A printable page with one age key as a QR code and as text. By default it's protected with a passphrase, which makes the page an ordinary age file: restore it in AgePony (Settings › Restore from a paper backup) or with age -d on a computer. Open an identity and tap Paper backup to make one.")

            faq("What is a hardware key?",
                "A key made inside this iPhone's Secure Enclave, or one that lives on a YubiKey. The private half never leaves the hardware, so it can't be shown, sent or backed up. A Secure Enclave key is gone if the iPhone is erased or replaced, so encrypt important files to a second key as well (Settings › Also encrypt to). A YubiKey decrypts with a tap over NFC, and its PIN when the key asks for it.")

            faq("Can I open a passphrase file without unlocking?",
                "Yes. On the lock screen, Continue without unlocking handles passphrase-protected text and files. Anything encrypted to a key still needs the vault unlocked.")

            faq("Can I open AgePony files with other tools?",
                "Yes. Files are standard age. The age command-line tool, rage, and AgePony for Android read them, and they read AgePony files. Post-quantum files need age 1.3 or newer.")

            faq("What is a post-quantum key?",
                "A hybrid key that keeps a file secret even if X25519 is broken by a future quantum computer. It cannot be combined with a classical recipient on the same file, because the weaker of the two would set the bar.")

            faq("I forgot my password. Can it be recovered?",
                "No. There is no recovery path. AgePony never stores your password in a form that can be reversed. If you lose it and have not set biometric unlock, the vault cannot be opened.")

            faq("What is a duress password?",
                "A second password that wipes the vault when entered and then opens an empty one. It looks exactly like a normal unlock, with no warning. You set it under Lock & password, and it needs a real password first. While one is set, only the app password opens the vault and Face ID is off, so a forced unlock always goes through the field where the duress password works.")

            faq("My iPhone has no passcode.",
                "Face ID, Touch ID and the passcode lock all need a device passcode, so without one AgePony protects the vault with its own password or PIN instead. If you set a passcode later, you can switch under Lock & password.")

            faq("How do I share my public key?",
                "Open the identity or recipient, tap QR, and have the other person scan it from their Add Recipient screen. You can also copy the age1 string and send it however you like. Public keys are safe to share.")
        }
        .navigationTitle("Help")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func faq(_ q: String, _ a: String) -> some View {
        Section {
            Text(a)
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
        } header: {
            Text(q)
        }
    }
}

// MARK: - Security

struct SecurityInfoView: View {
    var body: some View {
        Form {
            Section {
                Text("Your identities, recipients, and notes live in an encrypted vault on this device. There are no servers, no accounts, and no analytics.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("On device")
            }

            Section {
                Text("A 256-bit key seals the vault. That key is held in the device Keychain behind Face ID, Touch ID, or your passcode, or behind an app password you set. The vault file on disk is useless without the key. An app password is mixed with a secret that never leaves this iPhone, so a copied vault can't be guessed at anywhere else, and the vault is kept out of iCloud and computer backups. Wrong guesses slow down after a few tries, and you can choose to erase the vault after 10.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("How the vault is protected")
            }

            Section {
                Text("AgePony uses the network for two things, and only when you ask: fetching a recipient's public keys from GitHub, which can go through an HTTP proxy you set, and sending keys straight to your other phone on the same Wi-Fi. The second stays on your local network and carries only data encrypted to the receiving phone's one-time key. Everything else runs offline.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Network")
            }

            Section {
                Text("Before a received transfer can be imported, both phones show a transfer code over the exact data sent. If the codes differ, someone else sent it, and nothing should be imported. Received keys never become your active identity, and trusted signers arrive unticked.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Moving keys")
            }

            Section {
                Text("A signature verifies as trusted only when the key is one of your identities or a trusted signer you added. A key you only encrypt to, a saved recipient, isn't trusted for signatures.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Signatures")
            }

            Section {
                Text("AgePony cannot protect a file once you decrypt it and hand it to another app. It cannot recover a lost password. It cannot stop someone who already holds your unlocked phone, which is what the duress password is for. On iOS it cannot fully block screenshots: it hides content in the app switcher and blurs private keys, but a screenshot on an unlocked screen is still possible.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("What it does not do")
            }
        }
        .navigationTitle("Security")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Licenses

struct LicensesView: View {
    var body: some View {
        Form {
            Section {
                Text("AgePony is open source under the Apache License 2.0.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
                Link(destination: URL(string: "https://github.com/norsehorse-dev/AgePonyiOS")!) {
                    HStack {
                        Text("Source code")
                        Spacer()
                        Image(systemName: "arrow.up.right.square").foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("License")
            }

            Section {
                Text("AgePony bundles no third-party runtime libraries. The cryptography is built on Apple's CryptoKit, Security, and CommonCrypto, plus code written for this app where those frameworks stop short: SHA-3 and the SHAKE functions, ML-KEM-768, the HPKE hybrid, and the FIDO/CTAP2 stack for security keys.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Dependencies")
            }

            Section {
                attribution("age", "age-encryption.org/v1")
                attribution("SSHSIG", "the OpenSSH ssh-keygen -Y signing format")
                attribution("ML-KEM", "FIPS 203")
                attribution("HPKE", "RFC 9180")
                attribution("Bech32", "BIP-0173")
            } header: {
                Text("Standards implemented")
            } footer: {
                Text("AgePony is an independent app built on the open age format and is not affiliated with the age project.")
            }
        }
        .navigationTitle("Licenses")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func attribution(_ name: String, _ detail: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(name).font(AgePonyTypography.bodyEmph)
            Spacer()
            Text(detail)
                .font(AgePonyTypography.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
        }
    }
}
