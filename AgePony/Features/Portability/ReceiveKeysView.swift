//
//  ReceiveKeysView.swift
//  AgePony
//
//  Settings › Receive keys from another device (5.0.1, parity with Android 5.0.0).
//
//  Makes a one-time post-quantum identity that lives only in memory, shows its recipient
//  in a QR code along with this phone's address, a port and a one-time token, and listens
//  while the screen is open. The sender's transfer arrives directly over Wi-Fi, or as a
//  file or pasted text. Nothing is imported until the user has compared the transfer code
//  over what arrived with the one on the sending phone (audit M-6) and chosen what to take.
//
//  Mirrors Android `ui/portability/TransferScreens.kt` (ReceiveKeysScreen).
//

import SwiftUI
import UniformTypeIdentifiers
import AgePonyCore

/// The one-time receive key, held for the process rather than the screen, so an auto-lock
/// while the user fetches the file doesn't swap it for a new one (which would make the
/// sender's file unopenable). Never written anywhere.
enum ReceiveSession {
    static let lifetime: TimeInterval = 15 * 60
    private static let minReuse: TimeInterval = 5 * 60

    private static var identity: HybridIdentity?
    private static var startedAt = Date.distantPast

    static func current() throws -> HybridIdentity {
        // Reuse a session across a screen reopen, but not one that's nearly out of time.
        if let id = identity, remaining() > minReuse { return id }
        return try fresh()
    }

    static func fresh() throws -> HybridIdentity {
        let id = try HybridIdentity.generate()
        identity = id
        startedAt = Date()
        return id
    }

    static func remaining() -> TimeInterval {
        max(0, lifetime - Date().timeIntervalSince(startedAt))
    }

    static func end() { identity = nil }
}

struct ReceiveKeysView: View {

    let vault: Vault

    private enum Stage { case waiting, opening, preview, done, expired }

    @Environment(\.dismiss) private var dismiss

    @State private var session: HybridIdentity?
    @State private var recipient = ""
    @State private var stage: Stage = .waiting
    @State private var error: String?

    @State private var incoming: KeyPortability.Incoming?
    @State private var transferCode: String?
    @State private var codeConfirmed = false
    @State private var pickedIdentities: Set<Int> = []
    @State private var pickedRecipients: Set<Int> = []
    @State private var pickedSigners: Set<Int> = []
    @State private var leftOut = 0
    @State private var summary: KeyPortability.ImportSummary?

    @State private var pasted = ""
    @State private var showFileRoute = false
    @State private var importingFile = false

    @State private var listener: TransferListener?
    @State private var token = Data()
    @State private var addresses: [LocalNetwork.Address] = []
    @State private var port: UInt16?
    @State private var boundHost: String?
    @State private var sessionStamp: UUID?

    private var code: String { KeyTransfer.confirmationCode(recipient: recipient) }

    /// The invite when the listener is up, the bare recipient otherwise (file route only).
    private var qrContent: String {
        let hosts = boundHost.map { [$0] } ?? addresses.map(\.ip)
        if let port, !hosts.isEmpty, let invite = try? LanTransfer.Invite(recipient: recipient, token: token, port: port, hosts: hosts) {
            return invite.encode()
        }
        return recipient.uppercased()
    }

    var body: some View {
        Form {
            if let error {
                Section { StatusText(error).font(AgePonyTypography.subheadline) }
            }
            switch stage {
            case .waiting, .opening: waitingSections
            case .preview: previewSections
            case .done: doneSection
            case .expired: expiredSection
            }
        }
        .textCase(nil)
        .navigationTitle("Receive keys")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(stage == .preview)
        .toolbar {
            if stage == .preview {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { cancel() }
                }
            }
        }
        .onAppear(perform: begin)
        .onDisappear {
            stopListening()
            // Leaving a transfer under review retires the receive key, same as Cancel.
            if stage == .preview { ReceiveSession.end() }
        }
        .task(id: sessionStamp) {
            guard sessionStamp != nil else { return }
            let left = ReceiveSession.remaining()
            try? await Task.sleep(for: .seconds(left))
            guard !Task.isCancelled, stage == .waiting else { return }
            ReceiveSession.end()
            stopListening()
            stage = .expired
        }
        .fileImporter(isPresented: $importingFile, allowedContentTypes: [.data, .item]) { result in
            if case .success(let url) = result { openFile(url) }
        }
    }

    // MARK: Waiting

    @ViewBuilder private var waitingSections: some View {
        Section {
            Text("On the other phone, open Send keys to another device in AgePony's Settings and scan this code. Keep this screen open: with both phones on the same Wi-Fi, the keys arrive here directly in a few seconds.")
                .font(AgePonyTypography.subheadline)
            if addresses.isEmpty || port == nil {
                Label {
                    Text("This phone isn't on a Wi-Fi network, so the keys can't come across directly. Join the same Wi-Fi as the other phone (or its hotspot) and reopen this screen, or use a file below.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(AgePonyColors.warning)
                }
                .font(AgePonyTypography.subheadline)
            }
            if !recipient.isEmpty {
                AsyncQRImage(content: qrContent, correctionLevel: "L", side: 300)
                    .accessibilityLabel("One-time key for receiving a transfer")
                    .listRowInsets(EdgeInsets(top: 12, leading: 0, bottom: 12, trailing: 0))
            }
        }
        Section {
            BigCode(code: code, size: 24)
            if stage == .opening {
                HStack { Spacer(); ProgressView(); Spacer() }
            }
        } header: {
            Text("Check the sender shows this code")
        }
        Section {
            Button {
                showFileRoute.toggle()
            } label: {
                if showFileRoute {
                    Text("Hide the file option")
                } else {
                    Text("No shared Wi-Fi? Use a file instead")
                }
            }
            if showFileRoute {
                Button("Copy the key as text") { ClipboardPreferences.copy(recipient) }
                Button("Open the transfer file…") { importingFile = true }
                TextField("…or paste the transfer text", text: $pasted, axis: .vertical)
                    .lineLimit(3...8)
                    // Mono for the pasted data, not for the prompt.
                    .font(pasted.isEmpty ? AgePonyTypography.body : AgePonyTypography.monoSmall)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Open pasted text") { openBytes(Data(pasted.trimmingCharacters(in: .whitespacesAndNewlines).utf8)) }
                    .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        } footer: {
            if showFileRoute {
                Text("Then open what the sender made. If the other phone says it can't reach this one, check on both phones that AgePony is allowed under Privacy & Security, Local Network, in the Settings app.")
            }
        }
    }

    // MARK: Preview (audit M-6)

    @ViewBuilder private var previewSections: some View {
        if let inc = incoming {
            Section {
                BigCode(code: transferCode ?? "")
                Label {
                    Text("The sending phone (AgePony 5.0.1 or later) shows a transfer code too. If the two codes differ, someone else sent this transfer: tap Cancel and import nothing.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(AgePonyColors.warning)
                }
                .font(AgePonyTypography.subheadline)
                CheckLine(label: "The code matches the other phone", checked: codeConfirmed) { codeConfirmed.toggle() }
            } header: {
                Text("Transfer code")
            }

            if inc.identities.isEmpty && inc.recipients.isEmpty && inc.signers.isEmpty {
                Section {
                    Label {
                        Text("Nothing this phone can import.")
                    } icon: {
                        Image(systemName: "xmark.octagon.fill")
                            .foregroundStyle(AgePonyColors.destructive)
                    }
                }
            }

            if !inc.identities.isEmpty {
                Section {
                    ForEach(Array(inc.identities.enumerated()), id: \.offset) { i, identity in
                        let known = KeyPortability.isKnown(vault, identity)
                        PreviewRow(
                            title: identity.name,
                            detail: "\(KeyPortability.typeLabel(identity.type)) · \(KeyPortability.keySummary(identity))",
                            notes: identityNotes(identity, known: known),
                            checked: pickedIdentities.contains(i),
                            enabled: !known
                        ) { pickedIdentities.formSymmetricDifference([i]) }
                    }
                } header: {
                    Text("Identities (\(inc.identities.count))")
                } footer: {
                    Text("Imported identities are not made your active identity. Choose one in Settings if you want it.")
                }
            }

            if !inc.recipients.isEmpty {
                Section {
                    ForEach(Array(inc.recipients.enumerated()), id: \.offset) { i, r in
                        let known = KeyPortability.isKnown(vault, r)
                        PreviewRow(
                            title: r.name,
                            detail: "\(KeyPortability.typeLabel(r.type)) · \(KeyPortability.keySummary(r))",
                            notes: recipientNotes(r, known: known),
                            checked: pickedRecipients.contains(i),
                            enabled: !known
                        ) { pickedRecipients.formSymmetricDifference([i]) }
                    }
                } header: {
                    Text("Saved recipients (\(inc.recipients.count))")
                }
            }

            if !inc.signers.isEmpty {
                Section {
                    ForEach(Array(inc.signers.enumerated()), id: \.offset) { i, s in
                        let known = KeyPortability.isKnown(vault, s.signer)
                        PreviewRow(
                            title: s.signer.name,
                            detail: "\(s.signer.keyType) · \(s.signer.fingerprint)",
                            notes: signerNotes(s, known: known),
                            checked: pickedSigners.contains(i),
                            enabled: !known && s.refusalReason == nil
                        ) { pickedSigners.formSymmetricDifference([i]) }
                    }
                } header: {
                    Text("Trusted signers (\(inc.signers.count))")
                } footer: {
                    Text("Files signed by a trusted signer show as signed by that name. None are trusted unless you tick them.")
                }
            }

            Section {
                Button("Import") { runImport(inc) }
                    .buttonStyle(.agePonyPrimary)
                    .disabled(!codeConfirmed || !anyPicked)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                Button("Cancel", role: .cancel) { cancel() }
                    .frame(maxWidth: .infinity)
            } footer: {
                if !codeConfirmed {
                    Text("Tick \"The code matches the other phone\" above to import.")
                }
            }
        }
    }

    private var anyPicked: Bool {
        !pickedIdentities.isEmpty || !pickedRecipients.isEmpty || !pickedSigners.isEmpty
    }

    private func identityNotes(_ identity: StoredIdentity, known: Bool) -> [PreviewNote] {
        var notes: [PreviewNote] = []
        if known { notes.append(.init(text: String(localized: "Already on this phone, skipped."), warning: false)) }
        if let clash = KeyPortability.nameClash(vault, identity) {
            notes.append(.init(text: String(localized: "You already have an identity named \"\(clash.name)\" with a different key."), warning: true))
        }
        if let note = KeyPortability.unverifiableNote(identity) { notes.append(.init(text: note, warning: false)) }
        return notes
    }

    private func recipientNotes(_ r: StoredRecipient, known: Bool) -> [PreviewNote] {
        var notes: [PreviewNote] = []
        if known { notes.append(.init(text: String(localized: "Already on this phone, skipped."), warning: false)) }
        if let clash = KeyPortability.nameClash(vault, r) {
            notes.append(.init(text: String(localized: "You already have a recipient named \"\(clash.name)\" with a different key."), warning: true))
        }
        return notes
    }

    private func signerNotes(_ s: IncomingSigner, known: Bool) -> [PreviewNote] {
        var notes: [PreviewNote] = []
        if known { notes.append(.init(text: String(localized: "Already trusted on this phone, skipped."), warning: false)) }
        if let refused = s.refusalReason { notes.append(.init(text: refused, warning: true)) }
        if let clash = KeyPortability.nameClash(vault, s.signer) {
            notes.append(.init(text: String(localized: "Same name as \(clash), with a different key."), warning: true))
        }
        return notes
    }

    // MARK: Done / expired

    @ViewBuilder private var doneSection: some View {
        if let s = summary {
            Section {
                Label {
                    Text("Imported")
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(AgePonyColors.success)
                }
                .font(AgePonyTypography.headline)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Added ^[\(s.identitiesAdded) identity](inflect: true), ^[\(s.recipientsAdded) recipient](inflect: true) and ^[\(s.signersAdded) signer](inflect: true).")
                    if s.skipped > 0 {
                        Text("Skipped ^[\(s.skipped) item](inflect: true) already on this phone.")
                    }
                    if leftOut > 0 {
                        Text("Left out ^[\(leftOut) item](inflect: true) you didn't tick.")
                    }
                }
                Button("Done") { dismiss() }
            } footer: {
                Text("If you moved it with a file, delete that file from wherever it went through.")
            }
        }
    }

    @ViewBuilder private var expiredSection: some View {
        Section {
            Text("This receive session timed out and its one-time key is gone.")
            Button("Start a new session") {
                ReceiveSession.end()
                error = nil
                stage = .waiting
                begin()
            }
        }
    }

    // MARK: Actions

    private func begin() {
        guard stage == .waiting, listener == nil else { return }
        do {
            let id = try ReceiveSession.current()
            session = id
            recipient = try id.recipient().ageRecipient
        } catch {
            self.error = UserMessage.text(for: error, fallback: String(localized: "Couldn't make a receive key."))
            return
        }
        sessionStamp = UUID()
        startListening()
    }

    /// Listen on the Wi-Fi address the QR code advertises, not every interface (audit AS-3).
    private func startListening() {
        guard let identity = session else { return }
        let found = LocalNetwork.localAddresses()
        addresses = found
        port = nil
        boundHost = nil
        guard !found.isEmpty else { return }
        let newToken = LanTransfer.newToken()
        token = newToken
        let bind = LocalNetwork.bindAddress(found)
        let link = TransferListener(token: newToken, bindHost: bind?.ip) { bytes in
            // On the link's queue. Open before the ACK, so "Sent" on the other phone means
            // the transfer arrived and opened here.
            let bundle: KeyTransfer.Bundle
            do {
                bundle = try KeyTransfer.open(bytes, with: identity)
            } catch {
                let message = Self.describe(error)
                DispatchQueue.main.async {
                    MainActor.assumeIsolated { self.error = String(localized: "A transfer arrived but couldn't be opened. \(message)") }
                }
                return false
            }
            let received = TransferCode.of(sealed: bytes)
            return DispatchQueue.main.sync {
                MainActor.assumeIsolated {
                    guard stage == .waiting || stage == .opening else { return false }
                    // The listener shuts itself down once its ACK is out.
                    showPreview(KeyPortability.readBundle(bundle), code: received, fromLink: true)
                    return true
                }
            }
        }
        link.onReady = { readyPort, bound in
            port = readyPort
            boundHost = bound ? bind?.ip : nil
            if error == LanLinkError.localNetworkDenied.errorDescription { error = nil }
        }
        link.onFailed = { failure in
            port = nil
            if let e = failure as? LanLinkError { error = e.errorDescription }
        }
        listener = link
        link.start()
    }

    private func stopListening() {
        listener?.stop()
        listener = nil
    }

    /// Show a transfer for review. Everything starts from "not confirmed": a transfer that
    /// replaces another (a second route finishing) must be checked again. New identities and
    /// recipients start ticked; signers start unticked, since trusting one is a decision of
    /// its own.
    private func showPreview(_ inc: KeyPortability.Incoming, code: String, fromLink: Bool = false) {
        incoming = inc
        transferCode = code
        codeConfirmed = false
        pickedIdentities = Set(inc.identities.indices.filter { !KeyPortability.isKnown(vault, inc.identities[$0]) })
        pickedRecipients = Set(inc.recipients.indices.filter { !KeyPortability.isKnown(vault, inc.recipients[$0]) })
        pickedSigners = []
        error = nil
        stage = .preview
        if !fromLink { stopListening() }
    }

    private func openBytes(_ bytes: Data) {
        guard let identity = session else { return }
        error = nil
        stage = .opening
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let bundle = try KeyTransfer.open(bytes, with: identity)
                let received = TransferCode.of(sealed: bytes)
                DispatchQueue.main.async {
                    showPreview(KeyPortability.readBundle(bundle), code: received)
                }
            } catch {
                let message = Self.describe(error)
                DispatchQueue.main.async {
                    self.error = message
                    stage = .waiting
                }
            }
        }
    }

    private func openFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
        guard size <= LanTransfer.maxBytes, let bytes = try? Data(contentsOf: url) else {
            error = String(localized: "Couldn't read that file.")
            return
        }
        openBytes(bytes)
    }

    private func runImport(_ inc: KeyPortability.Incoming) {
        let chosen = KeyPortability.Incoming(
            identities: inc.identities.indices.filter { pickedIdentities.contains($0) }.map { inc.identities[$0] },
            recipients: inc.recipients.indices.filter { pickedRecipients.contains($0) }.map { inc.recipients[$0] },
            signers: inc.signers.indices.filter { pickedSigners.contains($0) }.map { inc.signers[$0] }
        )
        leftOut = inc.identities.count + inc.recipients.count + inc.signers.count
            - (chosen.identities.count + chosen.recipients.count + chosen.signers.count)
        do {
            summary = try KeyPortability.importInto(vault, chosen)
            ReceiveSession.end()
            stage = .done
        } catch {
            self.error = UserMessage.text(for: error, fallback: String(localized: "Couldn't save the received keys to the vault."))
        }
    }

    /// Cancelling also retires this receive key: whoever photographed its QR code can't
    /// try again with it.
    private func cancel() {
        ReceiveSession.end()
        stopListening()
        stage = .done
        dismiss()
    }

    nonisolated static func describe(_ error: Error) -> String {
        if error is AgeArmorError { return String(localized: "The transfer text is damaged or incomplete.") }
        guard let e = error as? KeyTransferError else { return String(localized: "Couldn't open that transfer.") }
        switch e {
        case .wrongSession:
            return String(localized: "It was made for a different receive session. On the sending phone, scan the code on this screen and send again.")
        case .notATransfer, .unsupportedFormat:
            return String(localized: "That isn't an AgePony key transfer.")
        case .tooManyEntries:
            return String(localized: "That transfer holds too many entries.")
        case .notARecipient:
            return String(localized: "Couldn't open that transfer.")
        }
    }
}
