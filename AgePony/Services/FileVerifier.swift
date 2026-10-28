//
//  FileVerifier.swift
//  AgePony
//
//  Verifies a detached SSHSIG signature against a file, then attributes the
//  signer. Two questions, kept separate on purpose:
//
//    1. Is the signature cryptographically valid for the key it carries?
//       (AgePonyCore's SSHSigVerifier answers this.)
//    2. Do we trust that key: is it one of the user's identities or trusted
//       signers? (FileVerifier answers this by matching the signer's wire blob
//       against the vault. Saved recipients stopped counting in 5.0.1, M-9.)
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
    /// Set when the key is on the trusted-signers list but the signature doesn't
    /// meet that entry (a security key that signed without a touch, say); `trust`
    /// is then `.validUnknownKey`. The entry's name, for display (audit L-7).
    public let untrustedSignerName: String?
    /// Why the matching trusted signer didn't accept the signature.
    public let untrustedReason: String?
    /// What an older (v1) signature doesn't cover, shown under the verdict (5.0.1).
    public let note: String?

    public init(
        trust: SignatureTrust,
        signerKeyType: String?,
        signerFingerprint: String?,
        signerPublicKeyWire: Data?,
        namespace: String?,
        untrustedSignerName: String? = nil,
        untrustedReason: String? = nil,
        note: String? = nil
    ) {
        self.trust = trust
        self.signerKeyType = signerKeyType
        self.signerFingerprint = signerFingerprint
        self.signerPublicKeyWire = signerPublicKeyWire
        self.namespace = namespace
        self.untrustedSignerName = untrustedSignerName
        self.untrustedReason = untrustedReason
        self.note = note
    }

    /// The same verdict with `note` set.
    func with(note: String?) -> FileVerificationResult {
        FileVerificationResult(trust: trust, signerKeyType: signerKeyType, signerFingerprint: signerFingerprint,
                               signerPublicKeyWire: signerPublicKeyWire, namespace: namespace,
                               untrustedSignerName: untrustedSignerName, untrustedReason: untrustedReason,
                               note: note)
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
                    trust: .invalid(reason: String(localized: "That doesn't look like an SSH signature.")),
                    signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
                )
            }
            signatureText = text
        } catch {
            return FileVerificationResult(
                trust: .invalid(reason: UserMessage.text(for: error, fallback: String(localized: "Couldn't read the signature file."))),
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
        // Under the namespace and message the bundle's version defines: v1 signs the
        // payload under "agepony", v2 the manifest and payload hash under its own.
        verify(
            signatureText: bundle.signatureArmored,
            identities: identities,
            recipients: recipients,
            signers: signers,
            namespace: bundle.namespace,
            messageHash: { bundle.messageDigest($0) }
        ).with(note: bundle.nameCovered ? nil : v1BundleNote)
    }

    static let v1BundleNote = String(localized: "Older signature format (v1): it covers the contents but not the file name.")
    static let v1StanzaNote = String(localized: "Older signature format (v1): it covers the contents but not who the file was encrypted to.")

    /// Verify a file's `agepony.com/sig` stanza (5.0.1) against the plaintext already
    /// written to `plaintextURL`, which is read again to hash it. Nil when the file
    /// carries no stanza. A stanza that is there but can't be read is a failed
    /// signature, never "unsigned" (audit L-9).
    public static func verify(
        stanza: SignatureStanza.Opening,
        plaintextURL: URL,
        identities: [StoredIdentity],
        recipients: [StoredRecipient],
        signers: [StoredSigner] = []
    ) -> FileVerificationResult? {
        switch stanza {
        case .absent:
            return nil
        case .unreadable(let why):
            // `why` is AgePonyCore's English detail; the screen gets a plain sentence.
            _ = why
            return FileVerificationResult(
                trust: .invalid(reason: String(localized: "The file carries a signature that can't be read. It may be damaged, or made by a newer version of AgePony.")),
                signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
            )
        case .opened(let opened):
            return verify(
                signatureText: opened.signatureArmored,
                identities: identities,
                recipients: recipients,
                signers: signers,
                namespace: opened.namespace,
                messageHash: { alg in
                    try opened.messageDigest(alg) { try FileSigner.digest(ofFileAt: plaintextURL, hash: $0) }
                }
            ).with(note: opened.coversRecipients ? nil : v1StanzaNote)
        }
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
        namespace: String = SSHSig.defaultNamespace,
        messageHash: (SSHSigHash) throws -> Data
    ) -> FileVerificationResult {
        let result: SSHSigVerification
        do {
            result = try SSHSigVerifier.verify(
                armoredSignature: signatureText,
                expectedNamespace: namespace,
                messageHash: messageHash
            )
        } catch let e as FileSignerError {
            if case .readFailed(let m) = e {
                return FileVerificationResult(
                    trust: .invalid(reason: m),
                    signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
                )
            }
            return FileVerificationResult(
                trust: .invalid(reason: UserMessage.text(for: e, fallback: String(localized: "Couldn't verify the signature."))),
                signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
            )
        } catch let e as SSHSigError {
            return FileVerificationResult(
                trust: .invalid(reason: reason(for: e)),
                signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
            )
        } catch {
            return FileVerificationResult(
                trust: .invalid(reason: UserMessage.text(for: error, fallback: String(localized: "Couldn't verify the signature."))),
                signerKeyType: nil, signerFingerprint: nil, signerPublicKeyWire: nil, namespace: nil
            )
        }

        let wire = result.publicKeyWire
        let fingerprint = sshFingerprint(wireBlob: wire)

        // Attribute the signer by matching the wire blob against the vault: own
        // identities first, then the trusted-signers list. Saved recipients are
        // never trusted as signers (5.0.1, audit M-9): a key you encrypt to is not
        // a key you've decided to trust for signatures. `recipients` stays in the
        // signature so callers don't change.
        _ = recipients
        if let id = identities.first(where: { keyMatches($0, wire) }) {
            return outcome(.trusted(signerName: id.name, isOwnIdentity: true), result, fingerprint)
        }
        if let s = signers.first(where: { $0.publicKeyWire == wire }) {
            // The entry's rules apply as ssh-keygen -Y verify applies them (L-6 / L-7):
            // with no stored options that is the security-key touch requirement.
            let entry = AllowedSigner(principals: [s.name], options: nil, keyType: s.keyType,
                                      keyBase64: s.publicKeyWire.base64EncodedString(), comment: s.comment)
            if entry.accepts(result) {
                return outcome(.trusted(signerName: s.name, isOwnIdentity: false), result, fingerprint)
            }
            let reason = result.userPresent == false
                ? String(localized: "The security key signed without a touch, and this signer requires one.")
                : String(localized: "The signature doesn't meet this signer's rules.")
            return outcome(.validUnknownKey, result, fingerprint, untrustedSignerName: s.name, untrustedReason: reason)
        }

        return outcome(.validUnknownKey, result, fingerprint)
    }

    // MARK: - Helpers

    private static func outcome(
        _ trust: SignatureTrust,
        _ v: SSHSigVerification,
        _ fingerprint: String,
        untrustedSignerName: String? = nil,
        untrustedReason: String? = nil
    ) -> FileVerificationResult {
        FileVerificationResult(
            trust: trust,
            signerKeyType: v.keyType,
            signerFingerprint: fingerprint,
            signerPublicKeyWire: v.publicKeyWire,
            namespace: v.namespace,
            untrustedSignerName: untrustedSignerName,
            untrustedReason: untrustedReason
        )
    }

    private static func keyMatches(_ identity: StoredIdentity, _ wire: Data) -> Bool {
        switch identity.type {
        case .sshEd25519, .sshRSA, .secureEnclaveP256, .skEd25519, .skEcdsaP256:
            return identity.publicKeyMaterial == wire
        case .x25519, .postQuantum, .secureEnclaveTag, .secureEnclaveTagPQ, .yubikey:
            return false
        }
    }

    private static func keyMatches(_ recipient: StoredRecipient, _ wire: Data) -> Bool {
        switch recipient.type {
        case .sshEd25519, .sshRSA: return recipient.publicKeyMaterial == wire
        case .x25519, .postQuantum, .yubikey, .tag, .tagPQ: return false
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
            return String(localized: "This signature is for the \"\(found)\" namespace, not AgePony's. AgePony only verifies signatures made in its own namespace.")
        case .signatureInvalid:
            return String(localized: "The signature doesn't match this file. The file may have changed, or the file and signature don't go together.")
        case .unsupportedKeyType:
            return String(localized: "This signature uses a key type AgePony can't verify yet.")
        case .missingBeginMarker, .missingEndMarker, .invalidBase64, .badMagic, .malformedBlob, .extraDataOutsideArmor:
            return String(localized: "That doesn't look like an SSH signature.")
        default:
            return UserMessage.text(for: error, fallback: String(localized: "Couldn't verify the signature."))
        }
    }
}
