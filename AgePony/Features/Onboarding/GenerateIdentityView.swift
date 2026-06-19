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
import AgePonyCore

struct GenerateIdentityView: View {

    let vault: Vault
    let onDone: () -> Void

    /// Which kind of identity is being generated.
    enum KeyKind: String, CaseIterable, Identifiable {
        case ageX25519
        case sshEd25519
        case secureEnclaveP256
        case securityKey
        var id: String { rawValue }
        var label: String {
            switch self {
            case .ageX25519:         return "age key"
            case .sshEd25519:        return "SSH key"
            case .secureEnclaveP256: return "Enclave"
            case .securityKey:       return "Security Key"
            }
        }
    }

    /// Secure Enclave is hidden on devices that don't have one.
    private var availableKinds: [KeyKind] {
        KeyKind.allCases.filter { $0 != .secureEnclaveP256 || SecureEnclaveSigner.isAvailable }
    }

    @State private var keyKind: KeyKind = .ageX25519

    // X25519 (original path).
    @State private var identity: X25519Identity = X25519Identity.generate()

    // SSH Ed25519 (new in 2.0).
    @State private var sshSeed: Data = Data()
    @State private var sshPub: Data = Data()

    // Secure Enclave P-256 (E0). The private key lives in the Enclave; we hold
    // only its opaque dataRepresentation and the public wire blob.
    @State private var sePrivateBlob: Data = Data()
    @State private var sePublicWire: Data = Data()

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
                Picker("Key type", selection: $keyKind) {
                    ForEach(availableKinds) { kind in
                        Text(kind.label).tag(kind)
                    }
                }
                .pickerStyle(.segmented)
                .onChange(of: keyKind) { _, _ in
                    regenerateCurrent()
                }
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
        case .sshEd25519: return "Public key (SSH ed25519)"
        case .secureEnclaveP256: return "Public key (Secure Enclave P-256)"
        case .securityKey:       return "Public key (security key)"
        }
    }

    private var publicValue: String {
        switch keyKind {
        case .ageX25519:
            return identity.ageRecipient
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
        case .sshEd25519:
            return "Safe to share. Others can encrypt to you with it, and verify files you sign."
        case .secureEnclaveP256:
            return "Safe to share. Others can verify files you sign with it. It can't receive encrypted files (signing only)."
        case .securityKey:
            return "You'll tap your security key when you press Save. After that, this becomes an sk-* public line others can verify against."
        }
    }

    // MARK: - Generation

    private func regenerateCurrent() {
        switch keyKind {
        case .ageX25519:
            identity = X25519Identity.generate()
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
