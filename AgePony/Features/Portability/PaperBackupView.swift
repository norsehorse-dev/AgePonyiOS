//
//  PaperBackupView.swift
//  AgePony
//
//  Identity detail › Paper backup (5.0.1, parity with Android 5.0.0).
//
//  One age identity on an A4 page: a QR code and the same thing as text, with the name,
//  the date and how to restore. Protected with a passphrase by default, so the page is an
//  ordinary age scrypt file that AgePony or plain `age -d` can open. The plain form, the
//  bare secret key, sits behind a warning. The PDF is built in memory and written once to
//  a private temp folder for the share sheet, then deleted when the screen goes away or
//  the vault locks.
//
//  X25519 and post-quantum identities only: their secret is a short string. Hardware keys
//  can't be backed up at all.
//
//  Mirrors Android `ui/portability/PaperScreens.kt` (PaperBackupScreen).
//

import SwiftUI
import UIKit
import CoreImage
import AgePonyCore

struct PaperBackupView: View {

    let vault: Vault
    let identity: StoredIdentity

    @State private var protect = true
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var suggested: String?
    @State private var acceptedWeak = false
    @State private var busy = false
    @State private var error: String?
    @State private var pdfURL: URL?
    @State private var builtProtected = true
    @State private var owner = OwnerCheck()

    private var wordlist: [String] { Wordlist.effLong() }

    private var weakness: String? {
        guard protect, !passphrase.isEmpty else { return nil }
        return Self.passphraseWeakness(passphrase)
    }

    private var ready: Bool {
        !busy && (!protect || (!passphrase.isEmpty && passphrase == confirm && (weakness == nil || acceptedWeak)))
    }

    var body: some View {
        Form {
            Section {
                Text(identity.name).font(AgePonyTypography.headline)
            }
            if let pdfURL {
                readySections(pdfURL)
            } else {
                optionSections
            }
            if let error {
                Section { Text(error).foregroundStyle(.red).font(AgePonyTypography.footnote) }
            }
        }
        .navigationTitle("Paper backup")
        .navigationBarTitleDisplayMode(.inline)
        .ownerCheck(owner, vault: vault)
        .onDisappear {
            PortabilityTemp.remove(pdfURL)
            pdfURL = nil
        }
    }

    // MARK: Options

    @ViewBuilder private var optionSections: some View {
        Section {
            Picker("Page", selection: $protect) {
                Text("Protect with a passphrase (recommended)").tag(true)
                Text("Plain key: whoever reads the page has the key").tag(false)
            }
            .pickerStyle(.inline)
            .labelsHidden()
        }

        if protect {
            Section {
                SecureField("Passphrase", text: $passphrase)
                    .textContentType(.newPassword)
                    .onChange(of: passphrase) { _, new in
                        // suggest() sets the field too; only a hand edit drops the suggestion.
                        if new != suggested { suggested = nil; acceptedWeak = false }
                        error = nil
                    }
                SecureField("Confirm passphrase", text: $confirm)
                    .textContentType(.newPassword)
                    .onChange(of: confirm) { _, new in
                        if new != suggested { suggested = nil }
                    }
                if !wordlist.isEmpty {
                    Button("Suggest a \(Diceware.defaultWordCount)-word passphrase") { suggest() }
                        .foregroundStyle(AgePonyColors.tealCore)
                }
                if let suggested {
                    Text("Write this down now, apart from the page: \(suggested)")
                        .font(AgePonyTypography.monoSmall)
                        .textSelection(.disabled)
                }
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    if !confirm.isEmpty && passphrase != confirm {
                        Text("The passphrases don't match.").foregroundStyle(.red)
                    }
                    Text("The page is an ordinary age file: restore it in AgePony, or with `age -d` on a computer.")
                }
            }
        } else {
            Section {
                Text("Only choose this for a page that will live somewhere locked, like a safe.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.red)
            }
        }

        // A paper page can be photographed or found, and then the passphrase is all that
        // stands between it and the key, offline and at the finder's leisure. Warn on a weak
        // one and make the user say so before building the page.
        if let weakness {
            Section {
                Text("This passphrase is weak: \(weakness). Anyone who finds the page can try guesses offline for as long as they like. Use the suggested passphrase, or a longer one of your own.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.red)
                if acceptedWeak {
                    Text("Using the weak passphrase anyway.")
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    Button("Use it anyway") { acceptedWeak = true }
                }
            }
        }

        Section {
            Button(busy ? "Preparing…" : "Create PDF") {
                owner.confirm(vault, title: "Create paper backup") { build() }
            }
            .buttonStyle(.agePonyPrimary)
            .disabled(!ready)
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            if busy {
                HStack { Spacer(); ProgressView(); Spacer() }
            }
        } footer: {
            if protect {
                Text("Protecting the page takes up to a minute: the passphrase is stretched with scrypt so a found page resists guessing.")
            }
        }
    }

    // MARK: Ready

    @ViewBuilder private func readySections(_ url: URL) -> some View {
        Section {
            Label("PDF ready", systemImage: "checkmark.circle.fill")
                .foregroundStyle(AgePonyColors.tealCore)
                .font(AgePonyTypography.headline)
            ShareLink(item: url) {
                Label("Save, print or share the PDF…", systemImage: "square.and.arrow.up")
            }
        } footer: {
            Text("Print it on a printer you trust, then delete the PDF. Store the page somewhere safe"
                 + (builtProtected ? ", and keep the passphrase somewhere else." : ". Anyone who sees it has the key."))
        }
        Section {
            Label("Printing over AirPrint sends the page through the printer and any print server or service between, and some keep or forward a copy. A printer cabled or on a network you control is safer.", systemImage: "printer")
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.orange)
        }
    }

    // MARK: Actions

    private func suggest() {
        guard let p = try? Diceware.generate(words: wordlist, wordCount: Diceware.defaultWordCount) else { return }
        passphrase = p
        confirm = p
        suggested = p
        acceptedWeak = false
    }

    private func build() {
        guard let line = KeyPortability.identityLine(identity), KeyPortability.isPaperBackable(identity) else {
            error = "Only age identities can be backed up on paper."
            return
        }
        if protect, !ScryptMemory.fits(workFactor: PaperBackup.defaultWorkFactor) {
            error = "There isn't enough free memory to protect the page right now (it needs \(ScryptMemory.memoryLabel(workFactor: PaperBackup.defaultWorkFactor))). Close other apps and try again."
            return
        }
        busy = true
        error = nil
        let pass: String? = protect ? passphrase : nil
        let name = identity.name
        let fileName = "agepony-backup-\(portabilitySafeFileName(name))-\(portabilityDateStamp()).pdf"
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let pdf = try PaperPage.render(line: line, name: name, passphrase: pass)
                let url = try PortabilityTemp.write(pdf, named: fileName)
                DispatchQueue.main.async {
                    PortabilityTemp.remove(pdfURL)
                    pdfURL = url
                    builtProtected = pass != nil
                    passphrase = ""
                    confirm = ""
                    suggested = nil
                    busy = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = "Couldn't build the backup: \(error.localizedDescription)"
                    busy = false
                }
            }
        }
    }

    /// Why `passphrase` is too weak to protect a paper backup, or nil when it is fine. Under
    /// 12 characters is weak; so is a passphrase made of words (diceware style) with fewer
    /// than `Diceware.minWordCount` of them, whatever its length.
    static func passphraseWeakness(_ passphrase: String) -> String? {
        if passphrase.count < 12 { return "it is shorter than 12 characters" }
        let words = passphrase.trimmingCharacters(in: .whitespaces)
            .components(separatedBy: CharacterSet(charactersIn: " \t._-"))
            .filter { !$0.isEmpty }
        let looksLikeWords = words.count >= 2 && words.allSatisfy { $0.allSatisfy(\.isLetter) }
        if looksLikeWords && words.count < Diceware.minWordCount {
            return "it has only \(words.count) words, and at least \(Diceware.minWordCount) are needed"
        }
        return nil
    }
}

// MARK: - The page

nonisolated enum PaperPage {

    /// Lay out the A4 page: what it is, which key, the QR, the text, how to restore.
    static func render(line: KeyTransfer.IdentityLine, name: String, passphrase: String?) throws -> Data {
        let identityFile = KeyTransfer.identityFile([line], includePublicKey: false)
        let payload = try passphrase.map { try PaperBackup.seal(identityFile: identityFile, passphrase: $0) } ?? line.secretKey

        let page = CGRect(x: 0, y: 0, width: 595, height: 842)
        let renderer = UIGraphicsPDFRenderer(bounds: page)
        let qr = qrImage(payload)

        return renderer.pdfData { ctx in
            ctx.beginPage()
            var y: CGFloat = 48
            let left: CGFloat = 48
            let width = page.width - 2 * left

            func text(_ s: String, _ font: UIFont, gap: CGFloat = 4) {
                let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: UIColor.black]
                let bounds = (s as NSString).boundingRect(with: CGSize(width: width, height: .greatestFiniteMagnitude),
                                                          options: [.usesLineFragmentOrigin], attributes: attrs, context: nil)
                (s as NSString).draw(with: CGRect(x: left, y: y, width: width, height: ceil(bounds.height)),
                                     options: [.usesLineFragmentOrigin], attributes: attrs, context: nil)
                y += ceil(bounds.height) + gap
            }

            let title = UIFont.boldSystemFont(ofSize: 20)
            let body = UIFont.systemFont(ofSize: 10)
            let mono = UIFont.monospacedSystemFont(ofSize: 8.5, weight: .regular)

            text("AgePony paper backup", title, gap: 10)
            text("Name: \(name)", body)
            text("Created: \(portabilityStamp())", body)
            text(passphrase != nil
                 ? "Protected with a passphrase (age scrypt). The passphrase is not on this page."
                 : "UNPROTECTED: this page is the private key.", body)
            text("Public key (to check which key this is):", body)
            let pub = line.publicKey
            text(pub.count <= 88 ? pub : "\(pub.prefix(40)) … \(pub.suffix(24))", mono, gap: 12)

            if let qr {
                let side: CGFloat = 300
                qr.draw(in: CGRect(x: left, y: y, width: side, height: side))
                y += side + 16
            }

            text(passphrase != nil ? "Backup text (an armored age file):" : "Secret key:", body)
            let lines = passphrase != nil
                ? payload.components(separatedBy: "\n").filter { !$0.isEmpty }
                : PaperBackup.transcriptionGroups(payload, perLine: 12)
            for l in lines { text(l, mono, gap: 1.5) }
            y += 10
            text("To restore: AgePony › Settings › Restore from a paper backup, then scan the code.", body)
            if passphrase != nil {
                text("Or on a computer: save the text as backup.age and run  age -d -o key.txt backup.age", body)
            }
        }
    }

    /// The QR at correction level M, drawn without smoothing so the modules stay sharp.
    private static func qrImage(_ payload: String) -> UIImage? {
        let filter = CIFilter(name: "CIQRCodeGenerator")
        filter?.setValue(Data(payload.utf8), forKey: "inputMessage")
        filter?.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter?.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        guard let cg = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }

    private static func portabilityStamp() -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return f.string(from: Date())
    }
}
