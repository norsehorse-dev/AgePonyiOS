//
//  FileVerifier.swift
//  AgePony
//
//  Verifies a detached SSHSIG signature against a file, then attributes the
//  signer. Two questions, kept separate on purpose:
//
//    1. Is the signature cryptographically valid for the key it carries?
//       (AgePonyCore's SSHSigVerifier answers this.)
//    2. Do we trust that key — is it one of the user's identities, trusted
//       signers, or saved recipients? (FileVerifier answers this by matching
//       the signer's wire blob against the vault.)
//
//  A valid signature from an unknown key is a real, distinct state: the math
//  checks out, but AgePony has no name to put on it. C2 lets the user promote
//  such a key into the trusted-signers list straight from the verify badge.
//

import Foundation
import CryptoKit
import AgePonyCore

/// The trust outcome shown to the user.
public enum SignatureTrust: Equatable {
    /// Valid, and the signing key matches a known identity, signer, or recipient.
    case trusted(signerName: String, isOwnIdentity: Bool)
    /// Cryptographically valid, but the signing key isn't in the vault.
    case validUnknownKey
    /// Not valid: wrong file, tampered, wrong namespace, or not a signature.
    case invalid(reason: String)
}

public struct FileVerificationResult: Equatable {
    public let trust: SignatureTrust
    public let signerKeyType: String?
    /// OpenSSH-style fingerprint (`SHA256:...`) of the signing key, when known.
    public let signerFingerprint: String?
    /// The signer's SSH public-key wire blob, when the signature parsed. Lets
    /// the UI offer "add this key as a trusted signer" for unknown signers.
    public let signerPublicKeyWire: Data?
    public let namespace: String?

    public init(
        trust: SignatureTrust,
        signerKeyType: String?,
        signerFingerprint: String?,
        signerPublicKeyWire: Data?,
        namespace: String?
    ) {
        self.trust = trust
        self.signerKeyType = signerKeyType
        self.signerFingerprint = signerFingerprint
        self.signerPublicKeyWire = signerPublicKeyWire
        self.namespace = namespace
    }
}

public enum FileVerifier {

    /// Verify `signatureURL` against `fileURL`, attributing the signer against
    /// the supplied identities, trusted signers, and recipients.
    public static func verify(
        fileURL: URL,
        signatureURL: URL,
        identities: [StoredIdentity],
        recipients: [StoredRecipient],
        signers: [StoredSigner] = []
    ) -> FileVerificationResult {
        // Access is held across the whole call: the file is hashed lazily, once
        // the signature has been parsed and its algorithm is known.
        let scoped = fileURL.startAccessingSecurityScopedResource()
        defer { if scoped { fileURL.stopAccessingSecurityScopedResource() } }

        // Read the signature text.
        let signatureText: String
        do {
            let scoped = signatureURL.startAccessingSecurityScopedResource()
            defer { if scoped { signatureURL.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: signatureURL)
            guard let text = String(data: data, encoding: .utf8) else {
                return FileVerificationResult(
                    trust: .invalid(reason: "That doesn't look like an SSH signature."),
                    signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
                )
            }
            signatureText = text
        } catch {
            return FileVerificationResult(
                trust: .invalid(reason: "Couldn't read the signature: \(error.localizedDescription)"),
                signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
            )
        }

        // The file itself is never held: SSHSIG covers only the digest, so it is
        // streamed past a hasher when the verifier asks for it. A 1 GB file costs
        // 64 KiB of buffer.
        return verify(
            signatureText: signatureText,
            identities: identities,
            recipients: recipients,
            signers: signers,
            messageHash: { try FileSigner.digest(ofFileAt: fileURL, hash: $0) }
        )
    }

    /// Verify the signature a decrypted signed bundle carried.
    ///
    /// The payload was written out and discarded while the bundle streamed past, so
    /// there is nothing left to hash -- verification runs entirely on the digests
    /// the unwrapping sink took on the way through.
    public static func verify(
        bundle: SignedBundle.StreamParsed,
        identities: [StoredIdentity],
        recipients: [StoredRecipient],
        signers: [StoredSigner] = []
    ) -> FileVerificationResult {
        verify(
            signatureText: bundle.signatureArmored,
            identities: identities,
            recipients: recipients,
            signers: signers,
            messageHash: { bundle.hash($0) }
        )
    }

    /// Core attribution logic, separated for testability.
    public static func verify(
        message: Data,
        signatureText: String,
        identities: [StoredIdentity],
        recipients: [StoredRecipient],
        signers: [StoredSigner] = []
    ) -> FileVerificationResult {
        verify(
            signatureText: signatureText,
            identities: identities,
            recipients: recipients,
            signers: signers,
            messageHash: { $0.digest(message) }
        )
    }

    /// Verify against a digest supplied on demand rather than the message.
    ///
    /// `messageHash` is asked for whichever algorithm the signature names, which
    /// isn't known until the signature has been parsed. That indirection is what
    /// lets a file be verified without being held, and lets a signed bundle be
    /// verified from the digests taken while its payload streamed past.
    public static func verify(
        signatureText: String,
        identities: [StoredIdentity],
        recipients: [StoredRecipient],
        signers: [StoredSigner] = [],
        messageHash: (SSHSigHash) throws -> Data
    ) -> FileVerificationResult {
        let result: SSHSigVerification
        do {
            result = try SSHSigVerifier.verify(
                armoredSignature: signatureText,
                expectedNamespace: SSHSig.defaultNamespace,
                messageHash: messageHash
            )
        } catch let e as FileSignerError {
            if case .readFailed(let m) = e {
                return FileVerificationResult(
                    trust: .invalid(reason: "Couldn't read the file: \(m)"),
                    signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
                )
            }
            return FileVerificationResult(
                trust: .invalid(reason: "Couldn't verify the signature."),
                signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
            )
        } catch let e as SSHSigError {
            return FileVerificationResult(
                trust: .invalid(reason: reason(for: e)),
                signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
            )
        } catch {
            return FileVerificationResult(
                trust: .invalid(reason: "Couldn't verify the signature."),
                signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
            )
        }

        let wire = result.publicKeyWire
        let fingerprint = sshFingerprint(wireBlob: wire)

        // Attribute the signer by matching the wire blob against the vault.
        // Order: own identities, then the dedicated trusted-signers store,
        // then incidental recipient matches.
        if let id = identities.first(where: { keyMatches($0, wire) }) {
            return outcome(.trusted(signerName: id.name, isOwnIdentity: true), result, fingerprint)
        }
        if let s = signers.first(where: { $0.publicKeyWire == wire }) {
            return outcome(.trusted(signerName: s.name, isOwnIdentity: false), result, fingerprint)
        }
        if let r = recipients.first(where: { keyMatches($0, wire) }) {
            return outcome(.trusted(signerName: r.name, isOwnIdentity: false), result, fingerprint)
        }

        return outcome(.validUnknownKey, result, fingerprint)
    }

    // MARK: - Helpers

    private static func outcome(
        _ trust: SignatureTrust,
        _ v: SSHSigVerification,
        _ fingerprint: String
    ) -> FileVerificationResult {
        FileVerificationResult(
            trust: trust,
            signerKeyType: v.keyType,
            signerFingerprint: fingerprint,
            signerPublicKeyWire: v.publicKeyWire,
            namespace: v.namespace
        )
    }

    private static func keyMatches(_ identity: StoredIdentity, _ wire: Data) -> Bool {
        switch identity.type {
        case .sshEd25519, .sshRSA, .secureEnclaveP256, .skEd25519, .skEcdsaP256:
            return identity.publicKeyMaterial == wire
        case .x25519, .postQuantum:
            return false
        }
    }

    private static func keyMatches(_ recipient: StoredRecipient, _ wire: Data) -> Bool {
        switch recipient.type {
        case .sshEd25519, .sshRSA: return recipient.publicKeyMaterial == wire
        case .x25519, .postQuantum: return false
        }
    }

    /// OpenSSH-style fingerprint: `SHA256:` + base64(sha256(wireBlob)) without padding.
    public static func sshFingerprint(wireBlob: Data) -> String {
        let digest = SHA256.hash(data: wireBlob)
        let b64 = Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:\(b64)"
    }

    private static func reason(for error: SSHSigError) -> String {
        switch error {
        case .namespaceMismatch(_, let found):
            return "This signature is for the \"\(found)\" namespace, not AgePony's. AgePony only verifies signatures made in its own namespace."
        case .signatureInvalid:
            return "The signature doesn't match this file. The file may have changed, or the file and signature don't go together."
        case .unsupportedKeyType:
            return "This signature uses a key type AgePony can't verify yet."
        case .missingBeginMarker, .missingEndMarker, .invalidBase64, .badMagic, .malformedBlob, .extraDataOutsideArmor:
            return "That doesn't look like an SSH signature."
        default:
            return "Couldn't verify the signature."
        }
    }
}
