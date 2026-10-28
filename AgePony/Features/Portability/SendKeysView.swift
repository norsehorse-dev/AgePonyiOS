//
//  SendKeysView.swift
//  AgePony
//
//  Settings › Send keys to another device (5.0.1, parity with Android 5.0.0).
//
//  Choose keys, scan the receiving phone, compare the confirmation code, prove it's you,
//  and the keys go out encrypted to the receiver's one-time key: directly over Wi-Fi when
//  the QR code carried an address, or as a file or text to move any way the user likes.
//  Either way the screen then shows the transfer code over what was sealed, for the
//  receiving phone to compare before it imports (audit M-6).
//
//  Hardware keys never move. YubiKey identities travel as their stub, a pointer to the key.
//
//  Mirrors Android `ui/portability/TransferScreens.kt` (SendKeysScreen).
//

import SwiftUI
import UIKit
import AgePonyCore

struct SendKeysView: View {

    let vault: Vault

    private enum Stage { case pick, confirm, working, sent, done }

    @Environment(\.dismiss) private var dismiss

    @State private var stage: Stage = .pick
    @State private var chosen: Set<UUID> = []
    @State private var includeRecipients = true
    @State private var includeSigners = true
    @State private var scanning = false
    @State private var scanError: String?

    @State private var recipientText = ""
    @State private var target: (any AgeRecipient)?
    @State private var invite: LanTransfer.Invite?
    @State private var sealed: Data?
    @State private var sentCode: String?
    @State private var fileURL: URL?
    @State private var error: String?
    @State private var owner = OwnerCheck()
    @State private var started = false

    private var movable: [StoredIdentity] { vault.identities.filter(KeyPortability.isTransferable) }
    private var bound: [StoredIdentity] { vault.identities.filter { !KeyPortability.isTransferable($0) } }

    private var anything: Bool {
        !chosen.isEmpty || (includeRecipients && !vault.recipients.isEmpty) || (includeSigners && !vault.signers.isEmpty)
    }

    var body: some View {
        Form {
            switch stage {
            case .pick: pickSections
            case .confirm: confirmSections
            case .working: workingSection
            case .sent: sentSection
            case .done: doneSections
            }
            if let error {
                Section { StatusText(error).font(AgePonyTypography.subheadline) }
            }
        }
        .textCase(nil)
        .navigationTitle("Send keys")
        .navigationBarTitleDisplayMode(.inline)
        .ownerCheck(owner, vault: vault)
        .onAppear {
            guard !started else { return }
            started = true
            chosen = Set(movable.map(\.id))
        }
        .onDisappear { PortabilityTemp.remove(fileURL) }
        .sheet(isPresented: $scanning) { scannerSheet }
    }

    // MARK: Pick

    @ViewBuilder private var pickSections: some View {
        Section {
            Text("Your keys are encrypted to a one-time key shown by the receiving device, so the file you move is useless to anyone else. Start Receive keys on the other device first.")
                .font(AgePonyTypography.subheadline)
        }
        Section {
            if movable.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("No identities to send")
                        .font(AgePonyTypography.headline)
                    Text("Only identities stored in AgePony itself can move to another device. Keys in the Secure Enclave, on a YubiKey or on a security key stay where they are. You can still send your saved recipients and trusted signers.")
                        .font(AgePonyTypography.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            ForEach(movable) { id in
                CheckLine(label: id.name, checked: chosen.contains(id.id)) { chosen.formSymmetricDifference([id.id]) }
            }
            ForEach(bound) { id in
                Text("\(id.name): stays on this device (hardware key)")
                    .font(AgePonyTypography.subheadline)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Identities")
        }
        Section {
            CheckLine(label: "Saved recipients (\(vault.recipients.count))", checked: includeRecipients) { includeRecipients.toggle() }
            CheckLine(label: "Trusted signers (\(vault.signers.count))", checked: includeSigners) { includeSigners.toggle() }
        }
        Section {
            Button("Scan the receiving device") {
                scanError = nil
                scanning = true
            }
            .buttonStyle(.agePonyPrimary)
            .disabled(!anything)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
        }
        Section {
            TextField("…or paste its key (age1pq1…)", text: $recipientText)
                // Mono for the key itself, not for the prompt.
                .font(recipientText.isEmpty ? AgePonyTypography.body : AgePonyTypography.monoSmall)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Use pasted key") { useRecipient(recipientText) }
                .disabled(!anything || recipientText.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    private var scannerSheet: some View {
        NavigationStack {
            ZStack {
                QRScannerView(onDetect: { value in
                    scanning = false
                    useRecipient(value)
                }, onError: { failure in
                    switch failure {
                    case .permissionDenied: scanError = String(localized: "Camera access is off. Turn it on in Settings, or paste the key instead.")
                    case .cameraUnavailable: scanError = String(localized: "No camera is available.")
                    case .setupFailed: scanError = UserMessage.text(for: failure, fallback: String(localized: "The camera couldn't start. Paste the key instead."))
                    }
                })
                .ignoresSafeArea()
                if let scanError {
                    // .thinMaterial only here, over the live camera feed, so the
                    // message stays legible (5.1.0, U4).
                    StatusText(scanError)
                        .padding()
                        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
                        .padding()
                }
            }
            .navigationTitle("Scan the receiving device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { scanning = false }
                }
            }
        }
    }

    // MARK: Confirm

    @ViewBuilder private var confirmSections: some View {
        Section {
            BigCode(code: KeyTransfer.confirmationCode(recipient: recipientText), size: 24)
            if !recipientText.hasPrefix("age1pq1") {
                Label {
                    Text("This receiving key isn't quantum-safe. Quantum-safe identities sent to it lose that protection in transit.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(AgePonyColors.warning)
                }
                .font(AgePonyTypography.subheadline)
            }
        } header: {
            Text("Does the receiving device show this code?")
        }
        Section {
            Button("It matches, send") {
                owner.confirm(vault, title: String(localized: "Send keys")) { seal() }
            }
            .buttonStyle(.agePonyPrimary)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            Button("It doesn't match") {
                target = nil
                invite = nil
                stage = .pick
            }
            .frame(maxWidth: .infinity)
        }
    }

    // MARK: Working / sent / done

    private var workingSection: some View {
        Section {
            HStack { Spacer(); ProgressView(); Spacer() }
            if invite != nil {
                Text("Sending to the other phone…").frame(maxWidth: .infinity)
            }
        }
    }

    @ViewBuilder private var sentSection: some View {
        Section {
            Label {
                Text("Sent")
            } icon: {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(AgePonyColors.success)
            }
            .font(AgePonyTypography.headline)
            Text("The other phone has the keys. Check what it lists and tap Import there.")
        }
        if let sentCode { transferCodeSection(sentCode) }
        Section {
            Button("Done") { dismiss() }
        }
    }

    @ViewBuilder private var doneSections: some View {
        Section {
            Group {
                if invite != nil {
                    Text("Couldn't send directly, so here's the file instead")
                } else {
                    Text("Transfer ready")
                }
            }
            .font(AgePonyTypography.headline)
            Text("Move it to the other device any way you like: only that receive session can open it. Delete it from wherever it passed through once it's imported.")
                .font(AgePonyTypography.subheadline)
        }
        // The same code for the file and the text version: it covers the transfer itself,
        // not how it travels.
        if let sentCode { transferCodeSection(sentCode) }
        Section {
            if let fileURL {
                ShareLink(item: fileURL) {
                    Label("Save or share the file…", systemImage: "square.and.arrow.up")
                }
            }
            if let sealed, sealed.count < 64 * 1024 {
                ShareLink(item: AgeArmor.encode(sealed)) {
                    Label("Share as text…", systemImage: "text.alignleft")
                }
            }
            Button("Done") { dismiss() }
        }
    }

    /// The sender's half of the audit M-6 check.
    private func transferCodeSection(_ code: String) -> some View {
        Section {
            BigCode(code: code, size: 22)
        } header: {
            Text("Transfer code")
        } footer: {
            Text("Check that it matches the code on the other phone before it imports. If it doesn't, tell the other phone to cancel.")
        }
    }

    // MARK: Actions

    /// The receiver's QR carries its address and a one-time token alongside the key when it
    /// can take the transfer directly; a bare age1pq1 key means the file route.
    private func useRecipient(_ raw: String) {
        error = nil
        do {
            let inv = LanTransfer.Invite.isInvite(raw) ? try LanTransfer.Invite.decode(raw) : nil
            let key = inv?.recipient ?? raw
            target = try KeyTransfer.parseRecipient(key)
            invite = inv
            recipientText = key.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            stage = .confirm
        } catch {
            self.error = String(localized: "That isn't a receiving key. Scan the code on the other phone's Receive keys screen.")
            stage = .pick
        }
    }

    private func seal() {
        guard stage == .confirm, let to = target else { return }
        stage = .working
        error = nil
        let ids = movable.filter { chosen.contains($0.id) }
        let recips = includeRecipients ? vault.recipients : []
        let signers = includeSigners ? vault.signers : []
        let bundle: KeyTransfer.Bundle
        do {
            bundle = try KeyPortability.buildBundle(identities: ids, recipients: recips, signers: signers)
        } catch {
            self.error = UserMessage.text(for: error, fallback: String(localized: "Couldn't build the transfer."))
            stage = .confirm
            return
        }
        let inv = invite
        let fileName = "agepony-keys-\(portabilityDateStamp()).age"
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let bytes = try KeyTransfer.seal(bundle, to: to)
                let code = TransferCode.of(sealed: bytes)
                DispatchQueue.main.async {
                    sealed = bytes
                    sentCode = code
                    PortabilityTemp.remove(fileURL)
                    fileURL = try? PortabilityTemp.write(bytes, named: fileName)
                    guard let inv else {
                        stage = .done
                        return
                    }
                    Task { @MainActor in
                        do {
                            try await TransferSender.send(invite: inv, sealed: bytes, deviceName: UIDevice.current.model)
                            stage = .sent
                            PortabilityTemp.remove(fileURL)
                            fileURL = nil
                        } catch {
                            // Direct delivery failed: keep the sealed transfer and offer the file.
                            self.error = UserMessage.text(for: error, fallback: String(localized: "Couldn't send directly to the other phone."))
                            stage = .done
                        }
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = UserMessage.text(for: error, fallback: String(localized: "Couldn't seal the transfer."))
                    stage = .confirm
                }
            }
        }
    }
}
