//
//  SSHIdentityImporter.swift
//  AgePony
//
//  Type-sniffing wrapper around the crypto-layer SSH identity initializers.
//  The UI doesn't know whether a pasted / picked OpenSSH key is Ed25519 or
//  RSA, and shouldn't have to ask the user. This helper tries both and
//  surfaces a single result + a normalized passphrase-state enum.
//

import Foundation
import AgePonyCore

public enum SSHImportError: Error, Equatable {
    case passphraseRequired
    case wrongPassphrase
    case unsupportedKeyType
    case malformedPEM
}

public enum SSHImportResult {
    case ed25519(seed: Data, edPub: Data, wireBlob: Data, comment: String?)
    case rsa(pemBytes: Data, wireBlob: Data, comment: String?)
}

public enum SSHIdentityImporter {

    /// Import an OpenSSH private key PEM. Returns a `StoredIdentity` ready
    /// to be added to the vault. Throws `passphraseRequired` if the PEM is
    /// encrypted and `passphrase` is nil, `wrongPassphrase` if given but
    /// incorrect.
    ///
    /// `name` is the user-given label for the resulting identity.
    public static func makeStoredIdentity(
        fromOpenSSHPEM pem: String,
        passphrase: String?,
        name: String
    ) throws -> StoredIdentity {
        let result = try importPEM(pem: pem, passphrase: passphrase)
        switch result {
        case .ed25519(let seed, let edPub, let wireBlob, let comment):
            var privateMaterial = Data(capacity: 64)
            privateMaterial.append(seed)
            privateMaterial.append(edPub)
            return StoredIdentity(
                name: name,
                type: .sshEd25519,
                publicKeyMaterial: wireBlob,
                privateKeyMaterial: privateMaterial,
                sshComment: comment
            )
        case .rsa(let pemBytes, let wireBlob, let comment):
            return StoredIdentity(
                name: name,
                type: .sshRSA,
                publicKeyMaterial: wireBlob,
                privateKeyMaterial: pemBytes,
                sshComment: comment
            )
        }
    }

    /// Internal: parse + classify a PEM into one of our two SSH types.
    private static func importPEM(pem: String, passphrase: String?) throws -> SSHImportResult {
        // Try Ed25519 first. The crypto core's `init(openSSHPrivateKey:passphrase:)`
        // will surface a passphrase-required / wrong-passphrase error before it
        // figures out the key type, so we use those signals to short-circuit.
        do {
            let id = try SSHEd25519Identity(openSSHPrivateKey: pem, passphrase: passphrase)
            // Comment is stored on the Identity's wireBlob via the parser but
            // not directly surfaced; for 1c we extract it from the PEM body
            // lazily and stuff it into a String? — leaving nil here is fine.
            return .ed25519(
                seed: id.edSeed,
                edPub: id.edPublicKey,
                wireBlob: id.wireBlob,
                comment: nil
            )
        } catch let e as OpenSSHEncryptedKeyError {
            // Envelope-level errors apply regardless of key type — surface them.
            try mapEnvelopeError(e)
        } catch {
            // Not an envelope error and not ed25519. Fall through to RSA.
        }

        do {
            let id = try SSHRSAIdentity(openSSHPrivateKey: pem, passphrase: passphrase)
            // Store the (possibly-decrypted) PEM as the private material so
            // we can re-parse on demand. If the input was encrypted we want
            // the DECRYPTED form for storage — synthesize it.
            let storedPEM: String
            if let pphr = passphrase, !pphr.isEmpty {
                storedPEM = (try? OpenSSHEncryptedKey.decryptedPEM(pem: pem, passphrase: pphr)) ?? pem
            } else {
                storedPEM = pem
            }
            let pemBytes = Data(storedPEM.utf8)
            return .rsa(pemBytes: pemBytes, wireBlob: id.wireBlob, comment: nil)
        } catch let e as OpenSSHEncryptedKeyError {
            try mapEnvelopeError(e)
            throw SSHImportError.malformedPEM  // unreachable after mapEnvelopeError
        } catch {
            throw SSHImportError.unsupportedKeyType
        }
    }

    private static func mapEnvelopeError(_ e: OpenSSHEncryptedKeyError) throws {
        switch e {
        case .passphraseRequired:
            throw SSHImportError.passphraseRequired
        case .wrongPassphrase:
            throw SSHImportError.wrongPassphrase
        case .malformedPEM:
            throw SSHImportError.malformedPEM
        case .unsupportedCipher, .unsupportedKDF, .malformedKDFOpts, .checkIntsMismatch:
            throw SSHImportError.malformedPEM
        }
    }
}
