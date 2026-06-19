//
//  SignEncryptService.swift
//  AgePony
//
//  Combined encrypt-then-sign. age has no signatures of its own, so signing
//  rides on SSHSIG over the *ciphertext*: we encrypt the file to `.age`, then
//  produce a detached `.age.sig` over those encrypted bytes. Signing the
//  ciphertext (not the plaintext) means a verifier checks the exact bytes they
//  received, and the signature reveals nothing about the contents.
//
//  This is pure orchestration over the existing FileEncryptor and FileSigner —
//  it adds no new crypto. Its one job beyond calling them is to place both
//  outputs in the same temporary directory so they share together as a pair.
//

import Foundation
import AgePonyCore

public enum SignEncryptError: Error, Equatable {
    case signingIdentityCannotSign
    case relocateFailed(String)
}

public enum SignEncryptService {

    public struct Output: Equatable {
        public let encryptedURL: URL
        public let signatureURL: URL
    }

    /// Encrypt `inputURL`, then sign the resulting `.age` ciphertext with
    /// `signingIdentity`. Returns both files, co-located so a single share
    /// sends the pair.
    public static func signEncrypt(
        inputURL: URL,
        recipients: [any AgeRecipient],
        passphrase: String?,
        armor: Bool,
        signingIdentity: StoredIdentity,
        namespace: String = SSHSig.defaultNamespace
    ) throws -> Output {
        guard signingIdentity.canSign else {
            throw SignEncryptError.signingIdentityCannotSign
        }

        // 1. Encrypt → `<name>.age` in temp dir A.
        let encryptedURL = try FileEncryptor.encrypt(
            inputURL: inputURL,
            recipients: recipients,
            passphrase: passphrase,
            armor: armor
        )

        // 2. Sign the ciphertext → `<name>.age.sig` in its own temp dir B.
        let signatureTempURL: URL
        do {
            signatureTempURL = try FileSigner.sign(
                inputURL: encryptedURL,
                identity: signingIdentity,
                namespace: namespace
            )
        } catch {
            // Don't leak the encrypted file if signing fails.
            FileEncryptor.cleanupTempFile(at: encryptedURL)
            throw error
        }

        // 3. Move the signature next to the encrypted file (dir A) so the two
        //    share as a pair, then drop the now-empty signature temp dir.
        let destSignatureURL = encryptedURL
            .deletingLastPathComponent()
            .appendingPathComponent(signatureTempURL.lastPathComponent)
        do {
            if FileManager.default.fileExists(atPath: destSignatureURL.path) {
                try FileManager.default.removeItem(at: destSignatureURL)
            }
            try FileManager.default.moveItem(at: signatureTempURL, to: destSignatureURL)
            FileSigner.cleanupTempFile(at: signatureTempURL)
        } catch {
            FileEncryptor.cleanupTempFile(at: encryptedURL)
            FileSigner.cleanupTempFile(at: signatureTempURL)
            throw SignEncryptError.relocateFailed(error.localizedDescription)
        }

        return Output(encryptedURL: encryptedURL, signatureURL: destSignatureURL)
    }
}
