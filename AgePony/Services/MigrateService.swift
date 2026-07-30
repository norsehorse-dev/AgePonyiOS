//
//  MigrateService.swift
//  AgePony
//
//  Re-encrypt an existing age file to different recipients — chiefly to move a
//  file you already hold onto a post-quantum recipient.
//
//  This is decrypt-then-encrypt, which means the plaintext exists somewhere in
//  between. There is no way around that: age files are not re-keyable in place,
//  and the payload key is bound to the payload, so producing a file for new
//  recipients means producing new ciphertext from the plaintext.
//
//  Where that plaintext lives is the decision. Holding it in memory would
//  reinstate exactly the ceiling this release removed — a 1 GB file would need
//  a gigabyte of RAM — so it goes to a temp file instead, with the same
//  complete-unless-open protection every other output gets, and is deleted as
//  soon as the re-encrypt finishes or fails. The window is real and worth
//  naming rather than hiding: for the duration of the operation, a decrypted
//  copy is on disk.
//

import Foundation
import AgePonyCore

public enum MigrateError: Error, Equatable {
    case noRecipients
    case sameRecipients
}

public enum MigrateService {

    public struct Output {
        public let url: URL
        /// Bytes of the original, for a before/after line in the UI.
        public let originalSize: Int64
        public let newSize: Int64
    }

    /// Decrypt `inputURL` with `identities` (or `passphrase`) and re-encrypt it
    /// to `recipients`.
    ///
    /// `progress` runs 0…0.5 across the decrypt and 0.5…1 across the encrypt, so
    /// a single bar covers the whole operation.
    public static func migrate(
        inputURL: URL,
        identities: [any AgeIdentity],
        passphrase: String?,
        to recipients: [any AgeRecipient],
        armor: Bool,
        workFactor: Int = FileEncryptor.mobileWorkFactor,
        progress: (@Sendable (Double) -> Void)? = nil
    ) throws -> Output {
        guard !recipients.isEmpty else { throw MigrateError.noRecipients }

        let originalSize = (try? FileManager.default
            .attributesOfItem(atPath: inputURL.path)[.size] as? NSNumber)??.int64Value ?? 0

        // Step 1: decrypt to a temp file.
        //
        // A signed bundle stays wrapped. Its signature is over the payload, so
        // re-encrypting the bundle whole carries the signature into the new file
        // still valid -- unwrapping here would silently strip it, and a migration
        // that quietly discards provenance is worse than one that fails.
        let plaintextURL = try FileEncryptor.decrypt(
            inputURL: inputURL,
            identities: identities,
            passphrase: passphrase,
            unwrapSignedBundle: false,
            progress: { done, total in
                guard total > 0 else { return }
                progress?(0.5 * Double(done) / Double(total))
            }
        ).url
        // Whatever happens next, the decrypted copy does not outlive this call.
        defer { FileEncryptor.cleanupTempFile(at: plaintextURL) }

        // Step 2: re-encrypt to the new recipients.
        let outURL = try FileEncryptor.encrypt(
            inputURL: plaintextURL,
            recipients: recipients,
            passphrase: nil,
            armor: armor,
            workFactor: workFactor,
            progress: { done, total in
                guard total > 0 else { return }
                progress?(0.5 + 0.5 * Double(done) / Double(total))
            }
        )

        // FileEncryptor names its output after the input, which here is the
        // stripped plaintext temp file. Restore the original name.
        let desired = outURL.deletingLastPathComponent()
            .appendingPathComponent(inputURL.lastPathComponent)
        let finalURL: URL
        if desired != outURL, !FileManager.default.fileExists(atPath: desired.path) {
            do {
                try FileManager.default.moveItem(at: outURL, to: desired)
                finalURL = desired
            } catch {
                finalURL = outURL
            }
        } else {
            finalURL = outURL
        }

        let newSize = (try? FileManager.default
            .attributesOfItem(atPath: finalURL.path)[.size] as? NSNumber)??.int64Value ?? 0

        return Output(url: finalURL, originalSize: originalSize, newSize: newSize)
    }
}
