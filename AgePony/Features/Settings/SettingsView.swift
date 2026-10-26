//
//  SettingsView.swift
//  AgePony
//
//  Settings tab. Surfaces:
//    • In-app biometric prompts on/off. This only drives whether AgePony
//      shows its OWN auth prompts for in-app reveals; how the vault locks is
//      LockSettingsView's job, and this toggle never changes it (L-25).
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
    @State private var scryptWorkFactor: Int
    @State private var activeIdentityID: UUID?
    @State private var backupRecipientID: UUID?

    @State private var pendingReset: Bool = false
    @State private var resetError: String?
    @State private var showWalkthrough: Bool = false
    @AppStorage(AppTheme.storageKey) private var themeRaw: String = AppTheme.system.rawValue
    @AppStorage(ClipboardPreferences.enabledKey) private var clipboardAutoClear: Bool = true
    @AppStorage(ClipboardPreferences.intervalKey) private var clipboardInterval: Double = 60
    @State private var showTempCleared: Bool = false
    @State private var tempFreedBytes: Int64 = 0

    init(vault: Vault) {
        self.vault = vault
        _biometricEnabled       = State(initialValue: vault.biometricEnabled)
        _encryptToSelfDefault   = State(initialValue: vault.encryptToSelfDefault)
        _scryptWorkFactor       = State(initialValue: vault.scryptWorkFactor)
        _activeIdentityID       = State(initialValue: vault.activeIdentityID)
        _backupRecipientID      = State(initialValue: vault.backupRecipientSelection.first)
    }

    var body: some View {
        Form {
            biometricSection
            encryptionSection
            identitySection
            portabilitySection
            signingSection
            appearanceSection
            clipboardSection
            helpSection
            moreFromNorseHorseSection
            aboutSection
            dataSection
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
            NavigationLink {
                LockSettingsView(vault: vault)
            } label: {
                Label("Lock & password", systemImage: "lock.shield")
            }
            NavigationLink {
                NetworkSettingsView(vault: vault)
            } label: {
                Label("Network", systemImage: "network")
            }
            if BiometricGate.availableBiometric() == .none {
                Text("This device doesn't support biometric authentication. AgePony will use your device passcode.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } else {
                Toggle("In-app biometric prompts", isOn: $biometricEnabled)
                    .onChange(of: biometricEnabled) { _, new in
                        guard !new, vault.biometricEnabled else {
                            vault.biometricEnabled = new
                            return
                        }
                        // Turning prompts off weakens the app: confirm it's the owner (L-15).
                        Task {
                            do {
                                try await BiometricGate.authenticate(reason: "Confirm it's you to turn off in-app prompts")
                                vault.biometricEnabled = false
                            } catch BiometricGateError.unavailable {
                                vault.biometricEnabled = false
                            } catch {
                                biometricEnabled = true
                            }
                        }
                    }
            }
        } header: {
            Text("Security")
        } footer: {
            Text("When on, AgePony prompts for \(biometricLabel) before revealing private keys or decrypting sensitive notes. How the vault itself locks is set under Lock & password.")
        }
    }

    private var encryptionSection: some View {
        Section {
            Toggle("Encrypt to self by default", isOn: $encryptToSelfDefault)

            Picker("Also encrypt to", selection: $backupRecipientID) {
                Text("No one").tag(UUID?.none)
                ForEach(vault.recipients) { r in
                    Text(r.name).tag(Optional(r.id))
                }
            }
            .pickerStyle(.menu)
            .onChange(of: backupRecipientID) { _, new in vault.backupRecipientID = new }

            Picker("Passphrase strength", selection: $scryptWorkFactor) {
                ForEach(
                    Array(ScryptMemory.minimumWorkFactor...ScryptMemory.maximumWorkFactor),
                    id: \.self
                ) { factor in
                    Text(ScryptMemory.describe(workFactor: factor)).tag(factor)
                }
            }
            Text(scryptFootnote)
                .font(AgePonyTypography.caption)
                .foregroundStyle(.secondary)
                .onChange(of: scryptWorkFactor) { _, new in
                    vault.scryptWorkFactor = new
                }
                .onChange(of: encryptToSelfDefault) { _, new in
                    vault.encryptToSelfDefault = new
                }
        } header: {
            Text("Encryption")
        } footer: {
            Text("When on, AgePony automatically adds your active identity as a recipient on every file you encrypt, so you can still decrypt it yourself later. \"Also encrypt to\" ticks a saved recipient by default too: pick a key you have backed up, so a file you encrypt to this iPhone's hardware key can still be opened if the phone is lost.")
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
            NavigationLink {
                RecentlyDeletedView(vault: vault)
            } label: {
                Label("Recently deleted", systemImage: "trash")
            }
        } header: {
            Text("Identity")
        } footer: {
            Text("The active identity is the default \"encrypt-to-self\" recipient and the first identity tried when decrypting.")
        }
    }

    /// Keys on other devices and on paper (5.0.1).
    private var portabilitySection: some View {
        Section {
            NavigationLink {
                SendKeysView(vault: vault)
            } label: {
                Label("Send keys to another device", systemImage: "square.and.arrow.up.on.square")
            }
            NavigationLink {
                ReceiveKeysView(vault: vault)
            } label: {
                Label("Receive keys from another device", systemImage: "square.and.arrow.down.on.square")
            }
            NavigationLink {
                PaperRestoreView(vault: vault)
            } label: {
                Label("Restore from a paper backup", systemImage: "doc.viewfinder")
            }
        } header: {
            Text("Move and back up keys")
        } footer: {
            Text("To make a paper backup, open an identity on the Identities tab. Hardware keys stay on this device and can't be moved or backed up.")
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
            NavigationLink { HelpView() } label: {
                Label("Help", systemImage: "questionmark.circle")
            }
            NavigationLink { SecurityInfoView() } label: {
                Label("Security", systemImage: "lock.shield")
            }
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
            NavigationLink { LicensesView() } label: {
                Text("Licenses")
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

    // MARK: - Appearance

    private var appearanceSection: some View {
        Section {
            Picker(selection: Binding(
                get: { AppTheme(rawValue: themeRaw) ?? .system },
                set: { themeRaw = $0.rawValue }
            )) {
                ForEach(AppTheme.allCases) { theme in
                    Text(theme.displayName).tag(theme)
                }
            } label: {
                Label("Theme", systemImage: "paintbrush")
            }
        } header: {
            Text("Appearance")
        }
    }

    // MARK: - Clipboard

    private var clipboardSection: some View {
        Section {
            Toggle("Auto-clear clipboard", isOn: $clipboardAutoClear)
            if clipboardAutoClear {
                Picker(selection: $clipboardInterval) {
                    Text("30 seconds").tag(30.0)
                    Text("1 minute").tag(60.0)
                    Text("2 minutes").tag(120.0)
                    Text("5 minutes").tag(300.0)
                } label: {
                    Label("Clear after", systemImage: "clock")
                }
            }
        } header: {
            Text("Clipboard")
        } footer: {
            Text("Copied keys and text are erased from the clipboard after the chosen time. Turn this off to keep copies until you replace them.")
        }
    }

    // MARK: - Data

    private var dataSection: some View {
        Section {
            Button {
                tempFreedBytes = TempFileCleanup.sweepAll()
                showTempCleared = true
            } label: {
                Label("Clear temporary files", systemImage: "internaldrive")
            }
        } header: {
            Text("Data")
        } footer: {
            Text("Removes leftover files from encrypting or decrypting large files. Your identities, recipients, and notes are untouched.")
        }
        .alert("Temporary files cleared", isPresented: $showTempCleared) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(tempFreedBytes > 0
                 ? "Freed \(ByteCountFormatter.string(fromByteCount: tempFreedBytes, countStyle: .file))."
                 : "There was nothing to clear.")
        }
    }

    // MARK: - More from NorseHorse

    private var moreFromNorseHorseSection: some View {
        Section {
            appLink("PGPony", "OpenPGP encryption and signing", "envelope.fill", .indigo,
                    "https://apps.apple.com/us/app/pgpony/id6759994432")
            appLink("QuorumPony", "Quorum key backup and recovery", "person.3.fill", .teal,
                    "https://apps.apple.com/us/app/quorumpony-key-backup/id6783608628")
            appLink("CarrierPony", "PGP chat and encrypted files", "bubble.left.and.bubble.right.fill", .green,
                    "https://apps.apple.com/us/app/carrierpony-pgp-chat-files/id6786930072")
            appLink("BurnPony", "Self-destructing encrypted messages", "flame.fill", .orange,
                    "https://apps.apple.com/us/app/burnpony/id6788513233")
            appLink("RelayPony", "Encrypted file transfer", "paperplane.fill", .blue,
                    "https://apps.apple.com/us/app/relaypony-file-transfer/id6785085525")
            appLink("ScrubPony", "Strip metadata from your files", "eraser.fill", .pink,
                    "https://scrubpony.app")
            appLink("VaultPony", "Encrypted vault for your files", "lock.rectangle.stack.fill", .brown,
                    "https://vaultpony.app")
            appLink("PassPony", "Password manager", "key.fill", .yellow,
                    "https://passpony.app")
            appLink("See the full pony family", "Every NorseHorse app in one place", "square.grid.2x2.fill", .indigo,
                    "https://pony.norsehor.se")
            appLink("Source code on GitHub", "AgePony is fully open source (Apache-2.0). Inspect all of it.",
                    "chevron.left.forwardslash.chevron.right", .primary,
                    "https://github.com/norsehorse-dev/AgePonyiOS")
        } header: {
            Text("More from NorseHorse")
        } footer: {
            Text("Other apps from the same developer.")
        }
    }

    private func appLink(_ name: String, _ subtitle: String, _ systemImage: String,
                         _ color: Color, _ urlString: String) -> some View {
        Link(destination: URL(string: urlString)!) {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).foregroundStyle(.primary)
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: systemImage).foregroundStyle(color)
            }
        }
    }

    // MARK: - Helpers

    /// Explains the trade-off in the terms the user actually feels: time and
    /// memory. Also warns when the current choice will not fit right now, since
    /// the encrypt would otherwise fail only when attempted.
    private var scryptFootnote: String {
        var text = "Passphrase encryption deliberately costs memory to resist guessing. "
        text += "Higher is stronger and slower; "
        text += ScryptMemory.describe(workFactor: scryptWorkFactor)
        text += " is what each passphrase file will cost to open, on any device. "
        text += "This is unrelated to file size."
        if !ScryptMemory.fits(workFactor: scryptWorkFactor) {
            text += " This device may not have enough free memory for that right now."
        }
        return text
    }

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
