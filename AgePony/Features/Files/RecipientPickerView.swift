//
//  RecipientPickerView.swift
//  AgePony
//
//  Multi-select recipient picker used by the EncryptFlow. As of 1e, three
//  sources feed this view:
//
//      1. Encrypt-to-self  — the user's own identities. Each is hydrated
//                            into the matching AgeRecipient type.
//      2. Saved recipients — public keys persisted in the vault. Added
//                            via the Recipients tab (1e). Multi-select.
//      3. Ad-hoc paste     — for one-off encrypts, paste an `age1...`
//                            recipient string or an `ssh-* AAAA…` line.
//                            Parsed immediately, validated, and added to
//                            the selection. Not persisted.
//
//  Passphrase escape hatch: "Passphrase only (scrypt)" toggle replaces
//  all of the above with scrypt-based encryption — the file gets a single
//  scrypt stanza, recipient selection is ignored on Confirm.
//

import SwiftUI
import AgePonyCore

struct RecipientPickerView: View {

    let identities: [StoredIdentity]
    let savedRecipients: [StoredRecipient]
    /// Pre-selected identity IDs (typically the active identity when
    /// encrypt-to-self default is on).
    let initiallySelectedIdentityIDs: Set<UUID>
    /// Called when the user confirms. Returns a fully-hydrated recipient
    /// list, PLUS an optional passphrase if the user picked scrypt mode.
    let onConfirm: (_ recipients: [any AgeRecipient], _ passphrase: String?) -> Void
    /// Persist a pasted key as a named recipient. Nil disables saving, leaving
    /// the paste field one-time only.
    let onSaveRecipient: ((StoredRecipient) throws -> Void)?

    @State private var selectedIdentityIDs: Set<UUID>
    @State private var selectedRecipientIDs: Set<UUID> = []
    @State private var adHocRecipients: [AdHocRecipient] = []
    @State private var pasteText: String = ""
    @State private var pasteName: String = ""
    @State private var pasteError: String?

    @State private var useScrypt: Bool = false
    @State private var passphrase: String = ""
    @State private var passphraseConfirm: String = ""

    @Environment(\.dismiss) private var dismiss

    init(
        identities: [StoredIdentity],
        savedRecipients: [StoredRecipient],
        initiallySelectedIdentityIDs: Set<UUID>,
        onConfirm: @escaping (_ recipients: [any AgeRecipient], _ passphrase: String?) -> Void,
        onSaveRecipient: ((StoredRecipient) throws -> Void)? = nil
    ) {
        self.identities = identities
        self.savedRecipients = savedRecipients
        self.initiallySelectedIdentityIDs = initiallySelectedIdentityIDs
        self.onConfirm = onConfirm
        self.onSaveRecipient = onSaveRecipient
        _selectedIdentityIDs = State(initialValue: initiallySelectedIdentityIDs)
    }

    struct AdHocRecipient: Identifiable {
        let id: UUID = UUID()
        let displayLabel: String
        let recipient: any AgeRecipient
        /// Set when this key was also saved to the vault, so the row can say so
        /// instead of claiming it is one-time.
        var savedName: String?
    }

    var body: some View {
        Form {
            modeSection
            if useScrypt {
                passphraseSection
            } else {
                identitiesSection
                savedRecipientsSection
                adHocSection
            }
            confirmSection
        }
        .navigationTitle("Choose recipients")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
    }

    // MARK: - Sections

    private var modeSection: some View {
        Section {
            Toggle("Passphrase only (scrypt)", isOn: $useScrypt)
        } footer: {
            Text("When on, the file is encrypted with a passphrase instead of recipient keys. Anyone with the passphrase can decrypt; nobody else can. Cannot be combined with recipients (age spec).")
        }
    }

    /// Only identities that can actually be age recipients. Secure Enclave
    /// P-256 keys are signing-only, so they never appear in encrypt-to-self.
    private var recipientCapableIdentities: [StoredIdentity] {
        identities.filter { $0.canBeRecipient }
    }

    private var identitiesSection: some View {
        Section {
            if recipientCapableIdentities.isEmpty {
                Text("You have no identities in this vault.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(recipientCapableIdentities) { identity in
                    identityRow(identity)
                }
            }
        } header: {
            Text("Encrypt to self")
        } footer: {
            Text("Including an identity here lets you decrypt this file later from this device.")
        }
    }

    @ViewBuilder
    private var savedRecipientsSection: some View {
        if !savedRecipients.isEmpty {
            Section {
                ForEach(savedRecipients) { recipient in
                    recipientRow(recipient)
                }
            } header: {
                Text("Saved recipients")
            } footer: {
                Text("Recipients you've added in the Recipients tab.")
            }
        }
    }

    private var adHocSection: some View {
        Section {
            ForEach(adHocRecipients) { ad in
                HStack(spacing: 12) {
                    Image(systemName: "person.crop.circle.badge.plus")
                        .foregroundStyle(AgePonyColors.tealCore)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ad.displayLabel)
                            .font(AgePonyTypography.footnote)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(ad.savedName.map { "saved as \"\($0)\"" } ?? "this file only, not saved")
                            .font(AgePonyTypography.caption)
                            .foregroundStyle(ad.savedName == nil
                                             ? Color.secondary : AgePonyColors.tealCore)
                    }
                    Spacer()
                    Button(role: .destructive) {
                        adHocRecipients.removeAll { $0.id == ad.id }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                }
            }

            TextField("Paste age1... or ssh-* AAAA... line", text: $pasteText, axis: .vertical)
                .font(AgePonyTypography.monoCaption)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .lineLimit(1...4)

            if let msg = pasteError {
                Text(msg)
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(AgePonyColors.destructive)
            }

            if onSaveRecipient != nil {
                TextField("Name (to save it for reuse)", text: $pasteName)
                    .font(AgePonyTypography.footnote)
                    .textInputAutocapitalization(.words)
            }

            Button {
                addPasted(save: false)
            } label: {
                Label("Use for this file only", systemImage: "plus.circle")
                    .font(AgePonyTypography.footnote)
            }
            .foregroundStyle(AgePonyColors.tealCore)
            .disabled(pasteIsEmpty)

            if onSaveRecipient != nil {
                Button {
                    addPasted(save: true)
                } label: {
                    Label("Save as recipient and use", systemImage: "square.and.arrow.down")
                        .font(AgePonyTypography.footnote)
                }
                .foregroundStyle(AgePonyColors.tealCore)
                .disabled(pasteIsEmpty)
            }
        } header: {
            Text("Paste a recipient")
        } footer: {
            Text(onSaveRecipient == nil
                 ? "Recipients added here apply only to this file. To reuse them, save in the Recipients tab."
                 : "Use it once, or give it a name and keep it. Saved recipients appear in the Recipients tab. Without a name, a saved key is filed under the key's own label.")
        }
    }

    private var passphraseSection: some View {
        Section {
            SecureField("Passphrase", text: $passphrase)
                .textInputAutocapitalization(.never)
            SecureField("Confirm passphrase", text: $passphraseConfirm)
                .textInputAutocapitalization(.never)
            if !passphraseConfirm.isEmpty && passphrase != passphraseConfirm {
                Text("Passphrases don't match.")
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(AgePonyColors.destructive)
            }
        } header: {
            Text("Passphrase")
        } footer: {
            Text("Use a long, random passphrase. There is no recovery if you forget it — scrypt is a brute-force-resistant KDF (work factor 2^18).")
        }
    }

    private var confirmSection: some View {
        Section {
            Button(action: confirm) {
                Text(confirmLabel)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.agePonyPrimary)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            .disabled(confirmDisabled)
        }
    }

    // MARK: - Rows

    private func identityRow(_ identity: StoredIdentity) -> some View {
        Button {
            toggle(identity.id, in: &selectedIdentityIDs)
        } label: {
            HStack(spacing: 12) {
                Image(systemName: selectedIdentityIDs.contains(identity.id) ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selectedIdentityIDs.contains(identity.id) ? AgePonyColors.tealCore : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(identity.name)
                        .font(AgePonyTypography.bodyEmph)
                        .foregroundStyle(.primary)
                    Text(identityTypeLabel(identity.type))
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
        .buttonStyle(.plain)
    }

    private func recipientRow(_ recipient: StoredRecipient) -> some View {
        Button {
            toggle(recipient.id, in: &selectedRecipientIDs)
        } label: {
            HStack(spacing: 12) {
                Image(systemName: selectedRecipientIDs.contains(recipient.id) ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selectedRecipientIDs.contains(recipient.id) ? AgePonyColors.tealCore : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(recipient.name)
                        .font(AgePonyTypography.bodyEmph)
                        .foregroundStyle(.primary)
                    Text(recipientTypeLabel(recipient.type))
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
        .buttonStyle(.plain)
    }

    private func toggle(_ id: UUID, in set: inout Set<UUID>) {
        if set.contains(id) { set.remove(id) } else { set.insert(id) }
    }

    private var confirmLabel: String {
        if useScrypt { return "Use passphrase" }
        let n = selectedIdentityIDs.count + selectedRecipientIDs.count + adHocRecipients.count
        if n == 0 { return "Pick at least one recipient" }
        if n == 1 { return "Use this recipient" }
        return "Use these \(n) recipients"
    }

    private var confirmDisabled: Bool {
        if useScrypt {
            return passphrase.isEmpty || passphrase != passphraseConfirm
        }
        return selectedIdentityIDs.isEmpty && selectedRecipientIDs.isEmpty && adHocRecipients.isEmpty
    }

    // MARK: - Actions

    private var pasteIsEmpty: Bool {
        pasteText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Parse the pasted key once and either keep it for this file or also save
    /// it. Both outcomes go through RecipientImportService, the same parser the
    /// Recipients tab uses, so a key saved here is indistinguishable from one
    /// added there.
    private func addPasted(save: Bool) {
        let raw = pasteText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return }
        pasteError = nil
        do {
            let candidate = try RecipientImportService.parsePastedText(raw)
            let typed = pasteName.trimmingCharacters(in: .whitespaces)
            let name = typed.isEmpty ? candidate.defaultName : typed

            let stored = StoredRecipient(
                name: name,
                type: candidate.type,
                publicKeyMaterial: candidate.publicKeyMaterial,
                sshComment: candidate.sshComment,
                source: candidate.type.pastedSource,
                sourceMetadata: nil
            )
            let recipient = try stored.toAgeRecipient()

            if save {
                guard let onSaveRecipient else { return }
                try onSaveRecipient(stored)
            }

            adHocRecipients.append(AdHocRecipient(
                displayLabel: save ? name : shorten(raw),
                recipient: recipient,
                savedName: save ? name : nil
            ))
            pasteText = ""
            pasteName = ""
        } catch {
            pasteError = readable(error)
        }
    }


    private enum AdHocParseError: Error {
        case unrecognized
    }

    private func confirm() {
        if useScrypt {
            onConfirm([], passphrase)
        } else {
            var built: [any AgeRecipient] = []
            for id in identities where selectedIdentityIDs.contains(id.id) {
                if let recipient = try? id.toAgeRecipient() {
                    built.append(recipient)
                }
            }
            for r in savedRecipients where selectedRecipientIDs.contains(r.id) {
                if let recipient = try? r.toAgeRecipient() {
                    built.append(recipient)
                }
            }
            for ad in adHocRecipients {
                built.append(ad.recipient)
            }
            onConfirm(built, nil)
        }
        dismiss()
    }

    // MARK: - Helpers

    private func identityTypeLabel(_ t: StoredIdentityType) -> String {
        switch t {
        case .x25519:    return "age X25519"
        case .sshEd25519: return "SSH Ed25519"
        case .sshRSA:    return "SSH RSA"
        case .secureEnclaveP256: return "Secure Enclave (P-256)"
        case .skEd25519: return "Security Key (Ed25519)"
        case .skEcdsaP256: return "Security Key (P-256)"
        case .postQuantum: return "Post-quantum hybrid"
        }
    }

    private func recipientTypeLabel(_ t: StoredRecipientType) -> String {
        switch t {
        case .x25519:    return "age X25519"
        case .sshEd25519: return "SSH Ed25519"
        case .sshRSA:    return "SSH RSA"
        case .postQuantum: return "Post-quantum hybrid"
        }
    }

    private func shorten(_ s: String) -> String {
        if s.count <= 28 { return s }
        let head = s.prefix(14)
        let tail = s.suffix(10)
        return "\(head)…\(tail)"
    }

    private func readable(_ error: Error) -> String {
        if error is AdHocParseError {
            return "Couldn't recognize that. Expected an `age1...` recipient or a one-line `ssh-* AAAA…` public key."
        }
        if let e = error as? Bech32Error {
            return "That doesn't look like a valid age recipient string. (\(e))"
        }
        return error.localizedDescription
    }
}
