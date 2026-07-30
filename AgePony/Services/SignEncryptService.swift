//
//  SignEncryptService.swift
//  AgePony
//
//  Sign-then-encrypt, producing one file.
//
//  age has no signatures of its own, so signing rides on SSHSIG. The question is
//  which bytes get signed and where the signature lives. Through 2.0 this was
//  encrypt-then-sign: a `.age` plus a detached `.age.sig` sitting beside it. That
//  works, but the signature is in the clear — anyone who intercepts the pair can
//  read the signer's public key off it and learn who sent the file, without
//  decrypting anything.
//
//  3.0 moves to sign-then-encrypt, matching Android. The plaintext is signed, the
//  payload and its signature are packed into a small tar (a "signed bundle"), and
//  the whole bundle is encrypted. One file goes out, and the ciphertext reveals
//  nothing: the recipient learns who signed it only once they can already read it.
//
//  Neither pass holds the file. The plaintext is streamed past a hasher to get the
//  digest SSHSIG needs, then streamed again as the bundle's payload while the
//  encryptor pulls. A 1 GB file costs two reads and a 64 KiB buffer.
//
//  Reading the old pair still works — see the decrypt path — but nothing produces
//  one any more.
//

import Foundation
import AgePonyCore

public enum SignEncryptError: Error, Equatable {
    case signingIdentityCannotSign
    /// The identity signs over NFC, which the sign-and-encrypt UI does not
    /// offer -- the picker filters security keys out. Guarded here anyway so a
    /// future caller gets an error rather than a confusing `canSign` failure.
    case requiresSecurityKey
    case cannotOpenInput(String)
}

public enum SignEncryptService {

    public struct Output: Equatable {
        /// The single `.age` file: a signed bundle, encrypted.
        public let encryptedURL: URL
        /// Bytes of the plaintext that was signed, for the UI's before/after line.
        public let payloadSize: Int64
    }

    /// Sign `inputURL` with `signingIdentity`, then encrypt the signed bundle.
    ///
    /// `progress` covers the encrypt pass. The digest pass runs first and is not
    /// reported: it is a plain sequential read, several times faster than the
    /// encryption that follows.
    public static func signEncrypt(
        inputURL: URL,
        recipients: [any AgeRecipient],
        passphrase: String?,
        armor: Bool,
        signingIdentity: StoredIdentity,
        workFactor: Int = FileEncryptor.mobileWorkFactor,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512,
        progress: FileProgressHandler? = nil
    ) throws -> Output {
        guard signingIdentity.canSign else {
            throw SignEncryptError.signingIdentityCannotSign
        }
        guard !signingIdentity.isSecurityKey else {
            throw SignEncryptError.requiresSecurityKey
        }

        let scoped = inputURL.startAccessingSecurityScopedResource()
        defer { if scoped { inputURL.stopAccessingSecurityScopedResource() } }

        // Pass 1: hash the plaintext, and sign the digest.
        let armoredSignature = try FileSigner.armoredSignature(
            messageHash: try FileSigner.digest(ofFileAt: inputURL, hash: hash),
            identity: signingIdentity,
            namespace: namespace,
            hash: hash
        )

        // Pass 2: stream the plaintext through the bundle and into the encryptor.
        return try encryptBundle(
            inputURL: inputURL,
            signatureArmored: armoredSignature,
            recipients: recipients,
            passphrase: passphrase,
            armor: armor,
            workFactor: workFactor,
            progress: progress
        )
    }

    // MARK: - Second pass

    /// Wrap `inputURL` and its signature into a bundle and encrypt it, streaming.
    ///
    /// The bundle is never built anywhere: `SignedBundle.bundleSource` produces it
    /// lazily as the encryptor reads, exactly as `encryptArchive` does for a tar.
    /// `sizeOf` supplies the byte total up front so progress is real.
    private static func encryptBundle(
        inputURL: URL,
        signatureArmored: String,
        recipients: [any AgeRecipient],
        passphrase: String?,
        armor: Bool,
        workFactor: Int,
        progress: FileProgressHandler?
    ) throws -> Output {
        let originalName = inputURL.lastPathComponent
        let payloadSize = fileSize(of: inputURL)

        guard let payload = InputStream(url: inputURL) else {
            throw SignEncryptError.cannotOpenInput(originalName)
        }

        let bundle = try SignedBundle.bundleSource(
            originalName: originalName,
            payloadSize: payloadSize,
            payload: payload,
            signatureArmored: signatureArmored
        )
        let bundleSize = SignedBundle.sizeOf(
            originalName: originalName,
            payloadSize: payloadSize,
            signatureArmored: signatureArmored
        )

        let outURL = try FileEncryptor.encrypt(
            source: bundle,
            totalBytes: bundleSize,
            outputName: originalName + ".age",
            recipients: recipients,
            passphrase: passphrase,
            armor: armor,
            workFactor: workFactor,
            progress: progress
        )

        return Output(encryptedURL: outURL, payloadSize: payloadSize)
    }

    private static func fileSize(of url: URL) -> Int64 {
        (try? FileManager.default
            .attributesOfItem(atPath: url.path)[.size] as? NSNumber)??.int64Value ?? 0
    }
}
