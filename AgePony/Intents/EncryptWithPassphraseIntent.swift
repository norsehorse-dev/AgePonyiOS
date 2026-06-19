//
//  EncryptWithPassphraseIntent.swift
//  AgePony — App Intents
//
//  Exposes passphrase-based age encryption to Shortcuts, Siri, and Spotlight.
//  This is the vault-free intent: it needs no identity or recipient and never
//  unlocks the vault, so it runs headlessly. Recipient-based encryption and
//  decrypt / sign (which need the vault and a biometric unlock) are separate
//  intents added later.
//
//  Output is an .age file you can drop into any subsequent Shortcuts action
//  (Save File, Send Message, etc.). It decrypts with the same passphrase in
//  AgePony, or with `age -d` on macOS / Linux.
//

import Foundation
import AppIntents
import AgePonyCore

@available(iOS 16.0, *)
struct EncryptWithPassphraseIntent: AppIntent {

    static var title: LocalizedStringResource = "Encrypt File with Passphrase"

    static var description = IntentDescription(
        "Encrypt a file with a passphrase using age. The result is an .age file that anyone with the passphrase can decrypt.",
        categoryName: "Encryption"
    )

    @Parameter(title: "File", description: "The file to encrypt.")
    var file: IntentFile

    @Parameter(title: "Passphrase", description: "The passphrase used to encrypt the file.")
    var passphrase: String

    @Parameter(title: "ASCII Armor", description: "Produce a text-safe (PEM-like) .age file instead of binary.", default: false)
    var armor: Bool

    static var parameterSummary: some ParameterSummary {
        Summary("Encrypt \(\.$file) with a passphrase") {
            \.$passphrase
            \.$armor
        }
    }

    func perform() async throws -> some IntentResult & ReturnsValue<IntentFile> {
        let trimmed = passphrase.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw AgePonyIntentError.emptyPassphrase
        }

        // Stage the incoming bytes to a temp file FileEncryptor can read.
        let inputURL = try AgePonyIntentSupport.stageInput(file)
        defer { AgePonyIntentSupport.cleanup(inputURL) }

        let outURL: URL
        do {
            outURL = try FileEncryptor.encrypt(
                inputURL: inputURL,
                recipients: [],
                passphrase: trimmed,
                armor: armor
            )
        } catch {
            throw AgePonyIntentError.operationFailed(
                (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            )
        }

        let outData: Data
        do {
            outData = try Data(contentsOf: outURL)
        } catch {
            throw AgePonyIntentError.operationFailed(error.localizedDescription)
        }

        let result = IntentFile(data: outData, filename: outURL.lastPathComponent)
        return .result(value: result)
    }
}
