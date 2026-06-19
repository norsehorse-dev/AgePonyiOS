//
//  StoredSigner.swift
//  AgePony
//
//  A trusted signer: an SSH public key the user recognizes, with a name
//  (principal). When verifying a detached signature, FileVerifier matches the
//  signature's key against this list to put a name on the signer. The list
//  round-trips to and from the OpenSSH `allowed_signers` file format
//  (AgePonyCore's AllowedSigners), so it drops straight onto a machine's
//  command line and back.
//
//  Kept in its own file (like StoredRecipient+Hydration) so VaultModels.swift
//  stays untouched.
//

import Foundation
import AgePonyCore

public struct StoredSigner: Codable, Identifiable, Hashable {

    public enum Source: String, Codable, Hashable {
        case pasteKey
        case importAllowedSigners
        case fromRecipient
        case fromVerification   // "add this unknown signer" from the verify badge
    }

    public let id: UUID
    /// Principal / display name (e.g. "alice@example.com").
    public var name: String
    /// Key algorithm, e.g. "ssh-ed25519".
    public let keyType: String
    /// The SSH public-key wire blob — the exact bytes carried in a signature,
    /// so matching is a direct equality check.
    public let publicKeyWire: Data
    public var comment: String?
    public let source: Source
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        name: String,
        keyType: String,
        publicKeyWire: Data,
        comment: String? = nil,
        source: Source,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.keyType = keyType
        self.publicKeyWire = publicKeyWire
        self.comment = comment
        self.source = source
        self.createdAt = createdAt
    }

    /// OpenSSH-style fingerprint (`SHA256:...`) for display.
    public var fingerprint: String {
        FileVerifier.sshFingerprint(wireBlob: publicKeyWire)
    }

    /// The `ssh-<type> BASE64 [comment]` one-liner.
    public var publicKeyLine: String {
        let b64 = publicKeyWire.base64EncodedString()
        return "\(keyType) \(b64)" + (comment.map { " \($0)" } ?? "")
    }

    // MARK: - allowed_signers bridge

    /// Build the allowed_signers entry for this signer, scoped to AgePony's
    /// namespace so it only authorizes AgePony-namespace signatures.
    public func toAllowedSigner() -> AllowedSigner {
        AllowedSigner(
            principals: [name],
            options: "namespaces=\"\(SSHSig.defaultNamespace)\"",
            keyType: keyType,
            keyBase64: publicKeyWire.base64EncodedString(),
            comment: comment
        )
    }

    /// Build a StoredSigner from a parsed allowed_signers entry. Returns nil if
    /// the key base64 doesn't decode.
    public static func from(allowedSigner a: AllowedSigner, source: Source) -> StoredSigner? {
        guard let wire = a.publicKeyWire else { return nil }
        return StoredSigner(
            name: a.principals.first ?? a.principals.joined(separator: ","),
            keyType: a.keyType,
            publicKeyWire: wire,
            comment: a.comment,
            source: source
        )
    }
}
