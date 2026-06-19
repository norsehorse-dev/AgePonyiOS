//
//  FileSigner.swift
//  AgePony
//
//  Signs the bytes of a file with a vault identity, producing a detached
//  SSHSIG `.sig` (the `ssh-keygen -Y sign` format). Mirrors FileEncryptor's
//  shape: read the source, run the crypto from AgePonyCore, write the result
//  to a fresh temp dir, and return the URL for a ShareLink.
//
//  Supports SSH Ed25519 (C0), SSH RSA / rsa-sha2-512 (D0), and Secure Enclave
//  ecdsa-sha2-nistp256 (E0). X25519 keys are encryption-only and can't sign.
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

    /// Sign the bytes of `inputURL` with `identity`, writing an armored
    /// detached signature named `<original>.sig`.
    public static func sign(
        inputURL: URL,
        identity: StoredIdentity,
        namespace: String = SSHSig.defaultNamespace
    ) throws -> URL {
        guard identity.canSign else { throw FileSignerError.identityCannotSign }

        let scoped = inputURL.startAccessingSecurityScopedResource()
        defer { if scoped { inputURL.stopAccessingSecurityScopedResource() } }

        let message: Data
        do {
            message = try Data(contentsOf: inputURL)
        } catch {
            throw FileSignerError.readFailed(error.localizedDescription)
        }

        let armored: String
        switch identity.type {
        case .sshEd25519:
            guard identity.privateKeyMaterial.count == 64 else {
                throw FileSignerError.malformedIdentityMaterial
            }
            do {
                armored = try SSHSigner.signEd25519(
                    message: message,
                    privateMaterial: identity.privateKeyMaterial,
                    namespace: namespace
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
                armored = try SSHSigner.signRSA(
                    message: message,
                    privateSecKey: rsaIdentity.privateSecKey,
                    publicKeyWire: rsaIdentity.wireBlob,
                    namespace: namespace
                )
            } catch {
                throw FileSignerError.signError(String(describing: error))
            }
        case .secureEnclaveP256:
            do {
                armored = try SecureEnclaveSigner.sign(
                    message: message,
                    identity: identity,
                    namespace: namespace
                )
            } catch {
                throw FileSignerError.signError(String(describing: error))
            }
        case .skEd25519, .skEcdsaP256:
            // Security keys sign over NFC, which is async. Callers must route
            // these through signWithSecurityKey(...) instead.
            throw FileSignerError.requiresSecurityKey
        case .x25519:
            throw FileSignerError.identityCannotSign
        }

        let outName = inputURL.lastPathComponent + ".sig"
        return try writeToFreshTempDir(name: outName, bytes: Data(armored.utf8))
    }

#if canImport(CoreNFC)
    /// Sign the bytes of `inputURL` with an external FIDO security-key identity
    /// (sk-ssh-ed25519 / sk-ecdsa-sha2-nistp256), tapping the key over NFC.
    /// Separate from `sign(...)` because the NFC round-trip is asynchronous.
    @available(iOS 13.0, *)
    public static func signWithSecurityKey(
        inputURL: URL,
        identity: StoredIdentity,
        pin: String? = nil,
        namespace: String = SSHSig.defaultNamespace
    ) async throws -> URL {
        guard identity.isSecurityKey else { throw FileSignerError.identityCannotSign }

        let scoped = inputURL.startAccessingSecurityScopedResource()
        defer { if scoped { inputURL.stopAccessingSecurityScopedResource() } }

        let message: Data
        do {
            message = try Data(contentsOf: inputURL)
        } catch {
            throw FileSignerError.readFailed(error.localizedDescription)
        }

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

        let armored: String
        do {
            armored = try await SecurityKeyService.signSSHSIG(
                message: message,
                credentialId: credentialId,
                algorithm: algorithm,
                publicKey: publicKey,
                application: application,
                namespace: namespace,
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
