//
//  GenerateIdentityView.swift
//  AgePony
//
//  Generate a fresh identity. Two kinds:
//
//    • age key (X25519) — encryption only. Shows the resulting age1... public
//      string (safe to share). This is the original default.
//
//    • SSH key (Ed25519) — encryption AND signing. Usable as an age recipient
//      (ssh-ed25519 stanza) and as a detached-signing identity (SSHSIG, added
//      in AgePony 2.0). Shows the ssh-ed25519 public line.
//
//    • Secure Enclave decryption (5.0.1) — an age1tag1 key, or age1tagpq1 with a
//      software ML-KEM-768 half, whose P-256 private key is made inside the
//      Secure Enclave and never leaves it. Same formats as Android's hardware
//      keys and age 1.3. Optional Face ID for every use.
//
//    • Secure Enclave (P-256) — signing only, hardware-backed. The private key
//      is generated inside the Secure Enclave and never leaves the device;
//      only shown when the device has a Secure Enclave. Produces ecdsa
//      SSHSIG signatures. Not usable as an age recipient.
//
//  The matching private material lives in the vault and can be revealed later
//  from IdentityDetailView with a biometric re-prompt. For X25519 that's the
//  AGE-SECRET-KEY-1... string; for Ed25519 it's an unencrypted OpenSSH private
//  key PEM that ssh-keygen, ssh-agent, and git all accept.
//

import SwiftUI
import Security
import AgePonyCore

struct GenerateIdentityView: View {

    let vault: Vault
    let onDone: () -> Void

    /// Which kind of identity is being generated.
    enum KeyKind: String, CaseIterable, Identifiable {
        case ageX25519
        case postQuantum
        case secureEnclaveTag
        case secureEnclaveTagPQ
        case sshEd25519
        case secureEnclaveP256
        case securityKey
        var id: String { rawValue }

        var isSecureEnclaveTag: Bool { self == .secureEnclaveTag || self == .secureEnclaveTagPQ }

        var needsSecureEnclave: Bool { isSecureEnclaveTag || self == .secureEnclaveP256 }

        /// Full name. No longer abbreviated: these used to be squeezed into five
        /// segments of a segmented control, where "Post-q..." and "Securit..."
        /// were all that fit -- and worse at larger text sizes.
        var label: String {
            switch self {
            case .ageX25519:         return "age key"
            case .postQuantum:       return "Post-quantum"
            case .secureEnclaveTag:  return "Hardware key"
            case .secureEnclaveTagPQ: return "Hardware key, quantum-safe"
            case .sshEd25519:        return "SSH key"
            case .secureEnclaveP256: return "Secure Enclave signing"
            case .securityKey:       return "Security key"
            }
        }

        /// What it can do, in a few words. The full explanation stays in the
        /// section footer for whichever kind is selected.
        var summary: String {
            switch self {
            case .ageX25519:         return "Encryption only"
            case .postQuantum:       return "Encryption only, quantum-safe"
            case .secureEnclaveTag:  return "Encryption, in this iPhone's Secure Enclave"
            case .secureEnclaveTagPQ: return "Encryption, Secure Enclave plus ML-KEM"
            case .sshEd25519:        return "Encryption and signing"
            case .secureEnclaveP256: return "Signing only, in this device's hardware"
            case .securityKey:       return "Signing only, on an external key"
            }
        }

        /// Matches the icons the identity list uses for the same key types, so a
        /// key looks the same where it is made and where it is kept.
        var iconName: String {
            switch self {
            case .ageX25519:         return "key.fill"
            case .postQuantum:       return "atom"
            case .secureEnclaveTag:  return "cpu"
            case .secureEnclaveTagPQ: return "cpu"
            case .sshEd25519:        return "lock.shield"
            case .secureEnclaveP256: return "cpu"
            case .securityKey:       return "key.radiowaves.forward"
            }
        }
    }

    /// Secure Enclave is hidden on devices that don't have one.
    private var availableKinds: [KeyKind] {
        KeyKind.allCases.filter { !$0.needsSecureEnclave || SecureEnclaveSigner.isAvailable }
    }

    @State private var keyKind: KeyKind = .ageX25519

    // X25519 (original path).
    @State private var identity: X25519Identity = X25519Identity.generate()

    // MLKEM768-X25519 hybrid. The 32-byte seed is the whole key: both halves
    // derive from it, so it is also the whole backup.
    @State private var pqIdentity: HybridIdentity? = nil

    // SSH Ed25519 (new in 2.0).
    @State private var sshSeed: Data = Data()
    @State private var sshPub: Data = Data()

    // Secure Enclave P-256 (E0). The private key lives in the Enclave; we hold
    // only its opaque dataRepresentation and the public wire blob.
    @State private var sePrivateBlob: Data = Data()
    @State private var sePublicWire: Data = Data()

    // Secure Enclave decryption keys (5.0.1). The Enclave key's blob and public
    // point, plus the ML-KEM seed for the quantum-safe kind.
    @State private var seTagBlob: Data = Data()
    @State private var seTagPublic: Data = Data()
    @State private var seTagMLKEMSeed: Data = Data()
    @State private var seTagRequirePresence: Bool = false

    @State private var name: String = "Personal"
    @State private var saveError: String?
    @State private var saving: Bool = false

    // Security-key PIN entry (shown only when a key reports PIN required).
    @State private var pinPromptVisible: Bool = false
    @State private var pinErrorText: String?
    @State private var pinSubmitting: Bool = false

    var body: some View {
        Form {
            Section {
                ForEach(availableKinds) { kind in
                    Button {
                        select(kind)
                    } label: {
                        KeyKindRow(kind: kind, isSelected: kind == keyKind)
                    }
                    .buttonStyle(.plain)
                }
            } header: {
                Text("Key type")
            } footer: {
                Text(keyKindFooter)
            }

            Section {
                TextField("Identity name", text: $name)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
            } header: {
                Text("Name")
            } footer: {
                Text("A label only you see. Something like \"personal phone\" or \"work\".")
            }

            Section {
                AgePonyKeyBlock(
                    label: publicLabel,
                    value: publicValue
                )
            } footer: {
                Text(publicFooter)
            }

            if keyKind.isSecureEnclaveTag {
                Section {
                    Toggle("Ask for Face ID each time", isOn: $seTagRequirePresence)
                        .onChange(of: seTagRequirePresence) { _, _ in regenerate(keyKind) }
                } footer: {
                    Text("When on, the Secure Enclave itself refuses to decrypt without Face ID, Touch ID or your passcode. This is fixed when the key is made.")
                }
                Section {
                    Label {
                        Text("This key lives only in this iPhone's Secure Enclave. It can't be exported, backed up, sent to another phone or put on paper, and it's gone if this iPhone is erased, lost or replaced. Removing the passcode doesn't delete it on iOS. Encrypt anything you can't lose to a key you have backed up as well.")
                            .font(AgePonyTypography.footnote)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
            }

            Section {
                Button {
                    regenerateCurrent()
                } label: {
                    Label("Regenerate", systemImage: "arrow.clockwise")
                        .font(AgePonyTypography.footnote)
                }
                .foregroundStyle(AgePonyColors.tealCore)
            }

            Section {
                Button(action: save) {
                    if saving {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text("Save & continue")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.agePonyPrimary)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || saving)
            }
        }
        .navigationTitle("Generate identity")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            // Ensure SSH material exists if the user switches to it immediately.
            if sshSeed.isEmpty { generateSSH() }
        }
        .alert("Could not save identity", isPresented: Binding(
            get: { saveError != nil },
            set: { if !$0 { saveError = nil } }
        ), actions: {
            Button("OK", role: .cancel) { saveError = nil }
        }, message: {
            Text(saveError ?? "")
        })
        .sheet(isPresented: $pinPromptVisible) {
            SecurityKeyPinPrompt(
                errorText: pinErrorText,
                submitting: pinSubmitting,
                onSubmit: { entered in
                    pinSubmitting = true
                    Task { await saveSecurityKey(name.trimmingCharacters(in: .whitespaces), pin: entered) }
                },
                onCancel: {
                    pinPromptVisible = false
                    pinSubmitting = false
                    saving = false
                }
            )
        }
    }

    // MARK: - Display helpers

    private var keyKindFooter: String {
        switch keyKind {
        case .ageX25519:
            return "Encryption only. The simplest age identity."
        case .postQuantum:
            return "Encryption only, and safe against a future quantum computer. Files stay secret even if X25519 is broken later. Readable by the age CLI 1.3 and newer. A post-quantum recipient can't be combined with a classical one on the same file, since the weaker of the two would set the bar."
        case .secureEnclaveTag:
            return "Encryption only. The private key is made inside this iPhone's Secure Enclave and decryption happens there, so it never leaves the hardware. Anyone can encrypt to it with age 1.3 or newer, or AgePony on Android."
        case .secureEnclaveTagPQ:
            return "Encryption only, quantum-safe. The P-256 half lives in the Secure Enclave; the ML-KEM-768 half is kept in the vault. A file needs both to open. Readable by age 1.3 or newer."
        case .sshEd25519:
            return "Encryption and signing. Use it as an age recipient and to sign files. Exportable as an OpenSSH key."
        case .secureEnclaveP256:
            return "Signing only, backed by this device's Secure Enclave. The private key is generated in hardware and never leaves the device, so it can't be exported or backed up."
        case .securityKey:
            return "Signing only, on an external FIDO security key (YubiKey 5 NFC and similar). You'll tap your key to create the credential. The private key never leaves the key, and it can't receive encrypted files."
        }
    }

    private var publicLabel: String {
        switch keyKind {
        case .ageX25519:  return "Public string (age recipient)"
        case .postQuantum: return "Public string (post-quantum recipient)"
        case .secureEnclaveTag: return "Public string (age1tag recipient)"
        case .secureEnclaveTagPQ: return "Public string (age1tagpq recipient)"
        case .sshEd25519: return "Public key (SSH ed25519)"
        case .secureEnclaveP256: return "Public key (Secure Enclave P-256)"
        case .securityKey:       return "Public key (security key)"
        }
    }

    private var publicValue: String {
        switch keyKind {
        case .ageX25519:
            return identity.ageRecipient
        case .postQuantum:
            guard let pqIdentity else { return "(generating post-quantum key…)" }
            return (try? pqIdentity.recipient().ageRecipient) ?? "(invalid post-quantum key)"
        case .secureEnclaveTag, .secureEnclaveTagPQ:
            guard let recipient = seTagRecipient else { return "(making a Secure Enclave key…)" }
            return recipient.toBech32()
        case .sshEd25519:
            return OpenSSHEd25519Export.publicKeyLine(publicKey: sshPub, comment: "agepony")
        case .secureEnclaveP256:
            guard !sePublicWire.isEmpty else { return "(generating Secure Enclave key…)" }
            return "ecdsa-sha2-nistp256 \(sePublicWire.base64EncodedString()) agepony"
        case .securityKey:
            return "(your security key's public key appears after you tap it when you press Save)"
        }
    }

    private var publicFooter: String {
        switch keyKind {
        case .ageX25519:
            return "Safe to share. Anyone with this string can encrypt files to you."
        case .postQuantum:
            return "Safe to share, and long — about 1,950 characters, because it carries an ML-KEM key alongside an X25519 one."
        case .secureEnclaveTag:
            return "Safe to share. Anyone with this string can encrypt files to this iPhone."
        case .secureEnclaveTagPQ:
            return "Safe to share. Long, because it carries an ML-KEM key alongside the P-256 one."
        case .sshEd25519:
            return "Safe to share. Others can encrypt to you with it, and verify files you sign."
        case .secureEnclaveP256:
            return "Safe to share. Others can verify files you sign with it. It can't receive encrypted files (signing only)."
        case .securityKey:
            return "You'll tap your security key when you press Save. After that, this becomes an sk-* public line others can verify against."
        }
    }

    // MARK: - Generation

    /// Choosing a kind also produces its key material, so the public string on
    /// screen always belongs to the selected row.
    private func select(_ kind: KeyKind) {
        guard kind != keyKind else { return }
        keyKind = kind
        // Passed explicitly rather than read back off `keyKind`: the write above
        // is to view state, and reading it again in the same call is the kind of
        // thing that works until it doesn't.
        regenerate(kind)
    }

    private func regenerateCurrent() {
        regenerate(keyKind)
    }

    private func regenerate(_ kind: KeyKind) {
        switch kind {
        case .ageX25519:
            identity = X25519Identity.generate()
        case .postQuantum:
            pqIdentity = try? HybridIdentity.generate()
        case .secureEnclaveTag, .secureEnclaveTagPQ:
            generateSETag(hybrid: kind == .secureEnclaveTagPQ)
        case .sshEd25519:
            generateSSH()
        case .secureEnclaveP256:
            generateSE()
        case .securityKey:
            break  // Nothing to pre-generate; the key is tapped at save time.
        }
    }

    private func generateSE() {
        do {
            let (priv, wire) = try SecureEnclaveSigner.generate()
            sePrivateBlob = priv
            sePublicWire = wire
        } catch {
            sePrivateBlob = Data()
            sePublicWire = Data()
            saveError = "Couldn't create a Secure Enclave key: \(error.localizedDescription)"
        }
    }

    private func generateSETag(hybrid: Bool) {
        do {
            let (blob, point) = try SecureEnclaveKeyAgreement.generate(requirePresence: seTagRequirePresence)
            seTagBlob = blob
            seTagPublic = point
            seTagMLKEMSeed = hybrid ? Self.randomBytes(StoredIdentity.mlkemSeedSize) : Data()
        } catch {
            seTagBlob = Data()
            seTagPublic = Data()
            seTagMLKEMSeed = Data()
            saveError = "Couldn't create a Secure Enclave key: \(error.localizedDescription)"
        }
    }

    /// The recipient for the Secure Enclave key on screen, from public data only.
    private var seTagRecipient: TagRecipient? {
        guard !seTagPublic.isEmpty else { return nil }
        let none = RecordedKeyAgreement(results: [:])
        if keyKind == .secureEnclaveTagPQ {
            guard seTagMLKEMSeed.count == StoredIdentity.mlkemSeedSize else { return nil }
            return try? TagIdentity.hybrid(mlkemSeed: seTagMLKEMSeed, p256PublicKey: seTagPublic, p256: none).recipient
        }
        return try? TagIdentity.classic(publicKey: seTagPublic, p256: none).recipient
    }

    private static func randomBytes(_ n: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &bytes) == errSecSuccess else { return Data() }
        return Data(bytes)
    }

    private func generateSSH() {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        sshSeed = seed
        sshPub = pub
    }

    // MARK: - Save

    private func save() {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        saving = true
        if keyKind == .securityKey {
            Task { await saveSecurityKey(trimmed) }
            return
        }
        do {
            let stored: StoredIdentity
            switch keyKind {
            case .ageX25519:
                stored = StoredIdentity(
                    name: trimmed,
                    type: .x25519,
                    publicKeyMaterial: identity.publicKey,
                    privateKeyMaterial: identity.privateKey,
                    sshComment: nil
                )
            case .postQuantum:
                if pqIdentity == nil { pqIdentity = try? HybridIdentity.generate() }
                guard let pq = pqIdentity else {
                    saveError = "Couldn't generate a post-quantum key. Try Regenerate."
                    saving = false
                    return
                }
                stored = StoredIdentity(
                    name: trimmed,
                    type: .postQuantum,
                    publicKeyMaterial: pq.publicKey,
                    privateKeyMaterial: pq.seed,
                    sshComment: nil
                )
            case .secureEnclaveTag, .secureEnclaveTagPQ:
                let hybrid = keyKind == .secureEnclaveTagPQ
                if seTagBlob.isEmpty || (hybrid && seTagMLKEMSeed.isEmpty) { generateSETag(hybrid: hybrid) }
                guard let recipient = seTagRecipient, !seTagBlob.isEmpty else {
                    saveError = "The Secure Enclave key isn't ready yet. Try Regenerate."
                    saving = false
                    return
                }
                stored = StoredIdentity(
                    name: trimmed,
                    type: hybrid ? .secureEnclaveTagPQ : .secureEnclaveTag,
                    publicKeyMaterial: recipient.publicKey,
                    privateKeyMaterial: hybrid ? seTagMLKEMSeed + seTagBlob : seTagBlob,
                    sshComment: nil
                )
            case .sshEd25519:
                if sshSeed.isEmpty { generateSSH() }
                let wire = SSHSig.ed25519PublicKeyWire(sshPub)
                stored = StoredIdentity(
                    name: trimmed,
                    type: .sshEd25519,
                    publicKeyMaterial: wire,
                    privateKeyMaterial: sshSeed + sshPub,
                    sshComment: "agepony"
                )
            case .secureEnclaveP256:
                if sePrivateBlob.isEmpty { generateSE() }
                guard !sePrivateBlob.isEmpty, !sePublicWire.isEmpty else {
                    saveError = "The Secure Enclave key isn't ready yet. Try Regenerate."
                    saving = false
                    return
                }
                stored = StoredIdentity(
                    name: trimmed,
                    type: .secureEnclaveP256,
                    publicKeyMaterial: sePublicWire,
                    privateKeyMaterial: sePrivateBlob,
                    sshComment: "agepony"
                )
            case .securityKey:
                // Handled asynchronously above (NFC enrol). Unreachable here.
                saving = false
                return
            }
            _ = try vault.addIdentity(stored)
            onDone()
        } catch {
            saveError = error.localizedDescription
        }
        saving = false
    }

    /// Enrol an external FIDO security key over NFC and store the resulting
    /// sk-* identity. The credentialId becomes the private material; the public
    /// key is wrapped into the sk SSHSIG wire blob.
    @available(iOS 13.0, *)
    @MainActor
    private func saveSecurityKey(_ trimmed: String, pin: String? = nil) async {
#if canImport(CoreNFC)
        do {
            let result = try await SecurityKeyService.enroll(pin: pin)
            let wire: Data
            let type: StoredIdentityType
            switch result.algorithm {
            case .ed25519:
                wire = SSHSig.skEd25519PublicKeyWire(
                    rawPublicKey: result.publicKey, application: result.application
                )
                type = .skEd25519
            case .ecdsaP256:
                wire = SSHSig.skEcdsaP256PublicKeyWire(
                    x963Q: result.publicKey, application: result.application
                )
                type = .skEcdsaP256
            }
            let stored = StoredIdentity(
                name: trimmed,
                type: type,
                publicKeyMaterial: wire,
                privateKeyMaterial: result.credentialId,
                sshComment: "agepony"
            )
            _ = try vault.addIdentity(stored)
            pinPromptVisible = false
            saving = false
            onDone()
        } catch let e as SecurityKeyError where e.indicatesWrongPin {
            pinErrorText = "The PIN was incorrect. Try again."
            pinSubmitting = false
            pinPromptVisible = true
            saving = false
        } catch let e as SecurityKeyError where e.indicatesPinRequired {
            pinErrorText = nil
            pinSubmitting = false
            pinPromptVisible = true
            saving = false
        } catch {
            pinPromptVisible = false
            pinSubmitting = false
            saveError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            saving = false
        }
#else
        saveError = "Security keys require NFC, which isn't available on this platform."
        saving = false
#endif
    }
}

// MARK: - Key type row

/// One selectable key type: icon, full name, and what it can do.
///
/// Replaces a five-segment segmented control that could not fit its own labels.
/// The choice matters — a Secure Enclave or security key cannot receive encrypted
/// files at all — so the trade-off is visible while choosing rather than only
/// discoverable afterwards.
private struct KeyKindRow: View {

    let kind: GenerateIdentityView.KeyKind
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: kind.iconName)
                .font(.system(size: 18))
                .foregroundStyle(isSelected ? AgePonyColors.tealCore : .secondary)
                .frame(width: 26)

            VStack(alignment: .leading, spacing: 2) {
                Text(kind.label)
                    .font(AgePonyTypography.headline)
                    .foregroundStyle(.primary)
                Text(kind.summary)
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)

            Image(systemName: "checkmark")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(AgePonyColors.tealCore)
                .opacity(isSelected ? 1 : 0)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        // One control to VoiceOver, reading as a radio button rather than as an
        // icon, two labels and a tick.
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
    }
}
