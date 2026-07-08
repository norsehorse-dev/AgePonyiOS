//
//  SettingsView.swift
//  AgePony
//
//  Settings tab. Surfaces:
//    • Biometric on/off (cosmetic — the master key Keychain ACL gates
//      Vault access regardless; this toggle drives whether AgePony shows
//      its OWN auth prompts for in-app reveals on top of the system one).
//    • Encrypt-to-self default — auto-add the active identity's recipient
//      when encrypting from the Files / Notes / Text tabs.
//    • Active identity — which identity is the default "encrypt-to-self"
//      recipient and the default decrypt attempt order.
//    • About — version, age-spec link, NorseHorse credit.
//    • Reset App — destroy the vault. Guarded by a confirmation dialog.
//

import SwiftUI

struct SettingsView: View {

    let vault: Vault

    @Environment(\.openURL) private var openURL

    @State private var biometricEnabled: Bool
    @State private var encryptToSelfDefault: Bool
    @State private var activeIdentityID: UUID?

    @State private var pendingReset: Bool = false
    @State private var resetError: String?
    @State private var showWalkthrough: Bool = false

    init(vault: Vault) {
        self.vault = vault
        _biometricEnabled       = State(initialValue: vault.biometricEnabled)
        _encryptToSelfDefault   = State(initialValue: vault.encryptToSelfDefault)
        _activeIdentityID       = State(initialValue: vault.activeIdentityID)
    }

    var body: some View {
        Form {
            biometricSection
            encryptionSection
            identitySection
            signingSection
            helpSection
            aboutSection
            dangerZoneSection
        }
        .fullScreenCover(isPresented: $showWalkthrough) {
            WalkthroughView {
                showWalkthrough = false
            }
        }
        .alert(
            "Reset AgePony?",
            isPresented: $pendingReset
        ) {
            Button("Reset", role: .destructive) { reset() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This deletes every identity, recipient, and encrypted note in the vault. Files already saved outside AgePony are unaffected. This cannot be undone.")
        }
        .alert(
            "Reset failed",
            isPresented: Binding(get: { resetError != nil }, set: { if !$0 { resetError = nil } })
        ) {
            Button("OK", role: .cancel) { resetError = nil }
        } message: {
            Text(resetError ?? "")
        }
    }

    // MARK: - Sections

    private var biometricSection: some View {
        Section {
            if BiometricGate.availableBiometric() == .none {
                Text("This device doesn't support biometric authentication. AgePony will use your device passcode.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } else {
                Toggle("In-app biometric prompts", isOn: $biometricEnabled)
                    .onChange(of: biometricEnabled) { _, new in
                        vault.biometricEnabled = new
                    }
            }
        } header: {
            Text("Security")
        } footer: {
            Text("When on, AgePony prompts for \(biometricLabel) before revealing private keys or decrypting sensitive notes. The vault itself is always biometrically protected at the OS level.")
        }
    }

    private var encryptionSection: some View {
        Section {
            Toggle("Encrypt to self by default", isOn: $encryptToSelfDefault)
                .onChange(of: encryptToSelfDefault) { _, new in
                    vault.encryptToSelfDefault = new
                }
        } header: {
            Text("Encryption")
        } footer: {
            Text("When on, AgePony automatically adds your active identity as a recipient on every file you encrypt — so you can still decrypt it yourself later.")
        }
    }

    private var identitySection: some View {
        Section {
            if vault.identities.isEmpty {
                Text("No identities yet. Add one from the Identities tab.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } else {
                Picker("Active identity", selection: $activeIdentityID) {
                    ForEach(vault.identities) { id in
                        Text(id.name).tag(Optional(id.id))
                    }
                }
                .pickerStyle(.menu)
                .onChange(of: activeIdentityID) { _, new in
                    vault.activeIdentityID = new
                }
            }
        } header: {
            Text("Identity")
        } footer: {
            Text("The active identity is the default \"encrypt-to-self\" recipient and the first identity tried when decrypting.")
        }
    }

    private var signingSection: some View {
        Section {
            NavigationLink {
                SignersView(vault: vault)
            } label: {
                HStack {
                    Text("Trusted signers")
                    Spacer()
                    if !vault.signers.isEmpty {
                        Text("\(vault.signers.count)")
                            .foregroundStyle(.secondary)
                    }
                }
            }
        } header: {
            Text("Signing")
        } footer: {
            Text("Public keys you trust to sign files. When a signature matches one, it verifies as signed by that name.")
        }
    }

    private var helpSection: some View {
        Section {
            Button {
                showWalkthrough = true
            } label: {
                HStack {
                    Text("Show walkthrough again")
                        .foregroundStyle(.primary)
                    Spacer()
                    Image(systemName: "play.circle")
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)

            if ReviewPrompter.hasAppStoreID, let url = ReviewPrompter.writeReviewURL {
                Link(destination: url) {
                    HStack {
                        Text("Rate AgePony")
                        Spacer()
                        Image(systemName: "star")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if let url = feedbackURL {
                Button {
                    openURL(url)
                } label: {
                    HStack {
                        Text("Send feedback")
                            .foregroundStyle(.primary)
                        Spacer()
                        Image(systemName: "envelope")
                            .foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(.plain)
            }
        } header: {
            Text("Help & Support")
        } footer: {
            Text("Replay the feature tour, rate AgePony on the App Store, or email feedback straight to NorseHorse.")
        }
    }

    private var aboutSection: some View {
        Section {
            HStack {
                Text("Version")
                Spacer()
                Text(versionString).foregroundStyle(.secondary)
            }
            Link(destination: URL(string: "https://agepony.com")!) {
                HStack {
                    Text("Website")
                    Spacer()
                    Image(systemName: "arrow.up.right.square")
                        .foregroundStyle(.secondary)
                }
            }
            Link(destination: URL(string: "https://age-encryption.org/v1")!) {
                HStack {
                    Text("age spec")
                    Spacer()
                    Image(systemName: "arrow.up.right.square")
                        .foregroundStyle(.secondary)
                }
            }
            Link(destination: URL(string: "https://github.com/norsehorse-dev/AgePonyiOS")!) {
                HStack {
                    Text("Source code")
                    Spacer()
                    Image(systemName: "arrow.up.right.square")
                        .foregroundStyle(.secondary)
                }
            }
            Link(destination: URL(string: "https://apps.apple.com/us/app/pgpony/id6759994432")!) {
                HStack {
                    Text("PGPony")
                    Spacer()
                    Image(systemName: "arrow.up.right.square")
                        .foregroundStyle(.secondary)
                }
            }
            HStack {
                Text("Made by")
                Spacer()
                Text("NorseHorse").foregroundStyle(.secondary)
            }
        } header: {
            Text("About")
        }
    }

    private var dangerZoneSection: some View {
        Section {
            Button(role: .destructive) {
                pendingReset = true
            } label: {
                Label("Reset AgePony", systemImage: "exclamationmark.triangle")
            }
        } header: {
            Text("Danger zone")
        } footer: {
            Text("Erases all stored identities, recipients, and notes. Files outside AgePony are untouched.")
        }
    }

    // MARK: - Helpers

    private var biometricLabel: String {
        switch BiometricGate.availableBiometric() {
        case .faceID:  return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        case .none:    return "your passcode"
        }
    }

    private var versionString: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(v) (\(b))"
    }

    /// Pre-filled support email to the public contact address. The subject
    /// carries the version so incoming feedback is easy to triage.
    private var feedbackURL: URL? {
        let subject = "AgePony feedback (\(versionString))"
        let encoded = subject.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? subject
        return URL(string: "mailto:NorseHorse@norsehor.se?subject=\(encoded)")
    }

    private func reset() {
        do {
            try vault.reset()
        } catch {
            resetError = error.localizedDescription
        }
    }
}
