//
//  FileSigner.swift
//  AgePony
//
//  Signs the bytes of a file with a vault identity, producing a detached
//  SSHSIG `.sig` (the `ssh-keygen -Y sign` format). Mirrors FileEncryptor's
//  shape: read the source, run the crypto from AgePonyCore, write the result
//  to a fresh temp dir, and return the URL for a ShareLink.
//
//  Supports SSH Ed25519 (C0), SSH RSA / rsa-sha2-512 (D0), Secure Enclave
//  ecdsa-sha2-nistp256 (E0), and FIDO security keys over NFC. X25519 and
//  post-quantum keys are encryption-only and can't sign.
//
//  The file is never held in memory. SSHSIG covers only the message *digest*,
//  so signing streams the file past a hasher and signs the digest — the same
//  bounded-memory rule the rest of 3.1 follows. `armoredSignature(messageHash:)`
//  is the seam: it takes a digest from anywhere, which is what lets sign-and-
//  encrypt sign a plaintext it is about to stream into a signed bundle rather
//  than reading it twice into RAM.
//

import Foundation
import AgePonyCore

public enum FileSignerError: Error, Equatable {
    case identityCannotSign
    case requiresSecurityKey
    case keyTypeNotYetSupported(StoredIdentityType)
    case malformedIdentityMaterial
    case readFailed(String)
    case writeFailed(String)
    case signError(String)
}

public enum FileSigner {

    // MARK: - Digest

    /// SSHSIG digest of a file, streamed 64 KiB at a time.
    ///
    /// Takes security-scoped access for the duration, so callers that already hold
    /// it pay nothing and callers that don't are still correct.
    public static func digest(
        ofFileAt url: URL,
        hash: SSHSigHash = .sha512
    ) throws -> Data {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        guard let stream = InputStream(url: url) else {
            throw FileSignerError.readFailed(url.lastPathComponent)
        }
        stream.open()
        defer { stream.close() }
        do {
            return try hash.digest(streaming: stream)
        } catch {
            throw FileSignerError.readFailed(error.localizedDescription)
        }
    }

    // MARK: - Signing a digest

    /// Produce an armored SSHSIG over `messageHash` with `identity`.
    ///
    /// The signing seam. Everything that signs in-process goes through here, and
    /// nothing here knows or cares where the digest came from — a file streamed
    /// past a hasher, a payload about to be sealed into a bundle, or a short
    /// string held in memory.
    ///
    /// Security-key identities are rejected: they sign over NFC, which is async.
    /// Use `armoredSignatureWithSecurityKey(messageHash:...)`.
    public static func armoredSignature(
        messageHash: Data,
        identity: StoredIdentity,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        guard identity.canSign else { throw FileSignerError.identityCannotSign }

        switch identity.type {
        case .sshEd25519:
            guard identity.privateKeyMaterial.count == 64 else {
                throw FileSignerError.malformedIdentityMaterial
            }
            do {
                return try SSHSigner.signEd25519(
                    messageHash: messageHash,
                    privateMaterial: identity.privateKeyMaterial,
                    namespace: namespace,
                    hash: hash
                )
            } catch {
                throw FileSignerError.signError(String(describing: error))
            }

        case .sshRSA:
            guard let pem = String(data: identity.privateKeyMaterial, encoding: .utf8) else {
                throw FileSignerError.malformedIdentityMaterial
            }
            do {
                let rsaIdentity = try SSHRSAIdentity(openSSHPrivateKey: pem)
                return try SSHSigner.signRSA(
                    messageHash: messageHash,
                    privateSecKey: rsaIdentity.privateSecKey,
                    publicKeyWire: rsaIdentity.wireBlob,
                    namespace: namespace,
                    hash: hash
                )
            } catch {
                throw FileSignerError.signError(String(describing: error))
            }

        case .secureEnclaveP256:
            do {
                return try SecureEnclaveSigner.sign(
                    messageHash: messageHash,
                    identity: identity,
                    namespace: namespace,
                    hash: hash
                )
            } catch {
                throw FileSignerError.signError(String(describing: error))
            }

        case .skEd25519, .skEcdsaP256:
            // Security keys sign over NFC, which is async. Callers must route
            // these through the security-key entry points instead.
            throw FileSignerError.requiresSecurityKey

        case .x25519, .postQuantum:
            // Both are encryption-only. ML-KEM is a KEM, not a signature scheme.
            throw FileSignerError.identityCannotSign
        }
    }

    // MARK: - Signing a file

    /// Sign the bytes of `inputURL` with `identity`, writing an armored
    /// detached signature named `<original>.sig`.
    public static func sign(
        inputURL: URL,
        identity: StoredIdentity,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> URL {
        guard identity.canSign else { throw FileSignerError.identityCannotSign }

        let armored = try armoredSignature(
            messageHash: try digest(ofFileAt: inputURL, hash: hash),
            identity: identity,
            namespace: namespace,
            hash: hash
        )

        let outName = inputURL.lastPathComponent + ".sig"
        return try writeToFreshTempDir(name: outName, bytes: Data(armored.utf8))
    }

#if canImport(CoreNFC)

    /// Produce an armored SSHSIG over `messageHash` with an external FIDO
    /// security-key identity (sk-ssh-ed25519 / sk-ecdsa-sha2-nistp256), tapping
    /// the key over NFC. Separate from `armoredSignature(messageHash:...)`
    /// because the NFC round-trip is asynchronous.
    ///
    /// PIN-related `SecurityKeyError`s are rethrown untouched so the UI can
    /// prompt and retry rather than showing a dead end.
    @available(iOS 13.0, *)
    public static func armoredSignatureWithSecurityKey(
        messageHash: Data,
        identity: StoredIdentity,
        pin: String? = nil,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) async throws -> String {
        guard identity.isSecurityKey else { throw FileSignerError.identityCannotSign }

        // Recover (algorithm, public key, application) from the stored sk wire
        // blob; the credentialId is held in privateKeyMaterial.
        let credentialId = identity.privateKeyMaterial
        let algorithm: SecurityKeyAlgorithm
        let publicKey: Data
        let application: Data
        do {
            switch identity.type {
            case .skEd25519:
                let parts = try SSHSig.skEd25519Components(fromWire: identity.publicKeyMaterial)
                algorithm = .ed25519
                publicKey = parts.publicKey
                application = parts.application
            case .skEcdsaP256:
                let parts = try SSHSig.skEcdsaP256Components(fromWire: identity.publicKeyMaterial)
                algorithm = .ecdsaP256
                publicKey = parts.q
                application = parts.application
            default:
                throw FileSignerError.identityCannotSign
            }
        } catch let e as FileSignerError {
            throw e
        } catch {
            throw FileSignerError.malformedIdentityMaterial
        }

        do {
            return try await SecurityKeyService.signSSHSIG(
                messageHash: messageHash,
                credentialId: credentialId,
                algorithm: algorithm,
                publicKey: publicKey,
                application: application,
                namespace: namespace,
                hash: hash,
                pin: pin
            )
        } catch let e as SecurityKeyError where e.indicatesPinRequired || e.indicatesWrongPin {
            // Surface the PIN signal untouched so the UI can prompt and retry.
            throw e
        } catch {
            throw FileSignerError.signError(
                (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            )
        }
    }

    /// Sign the bytes of `inputURL` with an external FIDO security-key identity,
    /// tapping the key over NFC.
    @available(iOS 13.0, *)
    public static func signWithSecurityKey(
        inputURL: URL,
        identity: StoredIdentity,
        pin: String? = nil,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) async throws -> URL {
        guard identity.isSecurityKey else { throw FileSignerError.identityCannotSign }

        // Hash before the tap, so the user isn't holding a key to the phone
        // while a large file is read.
        let messageHash = try digest(ofFileAt: inputURL, hash: hash)

        let armored = try await armoredSignatureWithSecurityKey(
            messageHash: messageHash,
            identity: identity,
            pin: pin,
            namespace: namespace,
            hash: hash
        )

        let outName = inputURL.lastPathComponent + ".sig"
        return try writeToFreshTempDir(name: outName, bytes: Data(armored.utf8))
    }
#endif

    // MARK: - Temp output (mirrors FileEncryptor)

    private static func writeToFreshTempDir(name: String, bytes: Data) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgePonyShare-\(UUID().uuidString.prefix(8))", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            throw FileSignerError.writeFailed(error.localizedDescription)
        }
        let url = dir.appendingPathComponent(name)
        do {
            try bytes.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
        } catch {
            throw FileSignerError.writeFailed(error.localizedDescription)
        }
        return url
    }

    public static func cleanupTempFile(at url: URL) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: dir)
    }
}
