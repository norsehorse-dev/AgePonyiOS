//
//  VaultModels.swift
//  AgePony
//
//  Persisted records held by the Vault. These are Codable wrappers around
//  the raw key material — the actual crypto-layer concrete types
//  (X25519Identity, SSHEd25519Identity, SSHRSAIdentity, etc.) are
//  re-instantiated on demand via the `toAgeIdentity()` / `toAgeRecipient()`
//  helpers. This keeps the Vault layer entirely above the crypto layer and
//  avoids leaking SecKey / opaque crypto state into the persistence layer.
//

import Foundation
import Security
import AgePonyCore

// MARK: - Identity

public enum StoredIdentityType: String, Codable, Hashable {
    case x25519
    case sshEd25519
    case sshRSA
    case secureEnclaveP256
    case skEd25519
    case skEcdsaP256
}

public struct StoredIdentity: Codable, Identifiable, Hashable {
    public let id: UUID
    public var name: String
    public let type: StoredIdentityType

    /// Public key bytes in a type-appropriate form:
    ///   x25519:    32-byte raw X25519 public key
    ///   sshEd25519: SSH wire blob (`<len=11>"ssh-ed25519"<len=32><pubkey>`)
    ///   sshRSA:    SSH wire blob for ssh-rsa
    ///   secureEnclaveP256: SSH wire blob for ecdsa-sha2-nistp256
    public let publicKeyMaterial: Data

    /// Private material in a type-appropriate form:
    ///   x25519:    32-byte raw X25519 private scalar
    ///   sshEd25519: 64 bytes = seed(32) || pub(32)
    ///   sshRSA:    UTF-8 bytes of the decrypted OpenSSH PEM string
    ///   secureEnclaveP256: the SE key's opaque dataRepresentation
    public let privateKeyMaterial: Data

    /// Optional SSH comment ("user@host"), GitHub username, etc.
    public var sshComment: String?

    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        name: String,
        type: StoredIdentityType,
        publicKeyMaterial: Data,
        privateKeyMaterial: Data,
        sshComment: String? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.publicKeyMaterial = publicKeyMaterial
        self.privateKeyMaterial = privateKeyMaterial
        self.sshComment = sshComment
        self.createdAt = createdAt
    }

    // MARK: - Hydration

    /// Construct the concrete crypto-layer identity type for use with
    /// `Age.decrypt(ciphertext:identities:)`.
    public func toAgeIdentity() throws -> any AgeIdentity {
        switch type {
        case .x25519:
            return try X25519Identity(privateKey: privateKeyMaterial)
        case .sshEd25519:
            guard privateKeyMaterial.count == 64 else {
                throw VaultModelError.malformedPrivateMaterial(type)
            }
            let seed = privateKeyMaterial.prefix(32)
            let pub  = privateKeyMaterial.suffix(32)
            return try SSHEd25519Identity(edSeed: Data(seed), edPublicKey: Data(pub))
        case .sshRSA:
            guard let pem = String(data: privateKeyMaterial, encoding: .utf8) else {
                throw VaultModelError.malformedPrivateMaterial(type)
            }
            return try SSHRSAIdentity(openSSHPrivateKey: pem)
        case .secureEnclaveP256:
            // Signing-only. Secure Enclave P-256 keys have no age stanza, so
            // they cannot decrypt. Decrypt paths use `try?` and skip these.
            throw VaultModelError.signingOnlyIdentity(type)
        case .skEd25519, .skEcdsaP256:
            // Signing-only. External FIDO security keys sign over NFC and have
            // no age stanza, so they cannot decrypt either.
            throw VaultModelError.signingOnlyIdentity(type)
        }
    }

    /// Construct the concrete crypto-layer recipient type matching this
    /// identity's public half. Used for "encrypt to self" flows.
    public func toAgeRecipient() throws -> any AgeRecipient {
        switch type {
        case .x25519:
            return try X25519Recipient(publicKey: publicKeyMaterial)
        case .sshEd25519:
            // publicKeyMaterial is the SSH wire blob; extract the 32-byte
            // ed25519 public key from inside it. SSHEd25519Recipient takes
            // the raw 32-byte ed25519 public key.
            let edPub = try Self.extractEd25519PublicKey(fromWireBlob: publicKeyMaterial)
            return try SSHEd25519Recipient(edPublicKey: edPub)
        case .sshRSA:
            // Reconstruct an `ssh-rsa <base64> [comment]` line and re-parse.
            let b64 = publicKeyMaterial.base64EncodedString()
            let line = "ssh-rsa \(b64)" + (sshComment.map { " \($0)" } ?? "")
            return try SSHRSARecipient(sshPublicKeyLine: line)
        case .secureEnclaveP256:
            // Signing-only — not usable as an age recipient.
            throw VaultModelError.signingOnlyIdentity(type)
        case .skEd25519, .skEcdsaP256:
            // Signing-only — security keys can't be age recipients.
            throw VaultModelError.signingOnlyIdentity(type)
        }
    }

    /// Whether this identity can produce detached signatures (SSHSIG).
    /// X25519 keys are encryption-only and cannot sign; SSH keys can.
    public var canSign: Bool {
        switch type {
        case .x25519:                 return false
        case .sshEd25519, .sshRSA:    return true
        case .secureEnclaveP256:      return true
        case .skEd25519, .skEcdsaP256: return true
        }
    }

    /// Whether this identity can act as an age recipient (encrypt-to-self) and
    /// can decrypt. Secure Enclave P-256 keys are signing-only — they have no
    /// age stanza — so they cannot.
    public var canBeRecipient: Bool {
        switch type {
        case .x25519, .sshEd25519, .sshRSA: return true
        case .secureEnclaveP256:            return false
        case .skEd25519, .skEcdsaP256:      return false
        }
    }

    /// Whether this identity signs on an external hardware security key (FIDO
    /// sk-*), which requires the async NFC signing path rather than FileSigner.
    public var isSecurityKey: Bool {
        type == .skEd25519 || type == .skEcdsaP256
    }

    /// Public-key display form, suitable for an AgePonyKeyBlock.
    ///   x25519:    `age1...`
    ///   sshEd25519: `ssh-ed25519 BASE64 [comment]`
    ///   sshRSA:    `ssh-rsa BASE64 [comment]`
    public func publicDisplayString() -> String {
        switch type {
        case .x25519:
            // Re-derive via Bech32. Cheap.
            if let id = try? X25519Identity(privateKey: privateKeyMaterial) {
                return id.ageRecipient
            }
            return "(invalid x25519 identity)"
        case .sshEd25519:
            let b64 = publicKeyMaterial.base64EncodedString()
            return "ssh-ed25519 \(b64)" + (sshComment.map { " \($0)" } ?? "")
        case .sshRSA:
            let b64 = publicKeyMaterial.base64EncodedString()
            return "ssh-rsa \(b64)" + (sshComment.map { " \($0)" } ?? "")
        case .secureEnclaveP256:
            let b64 = publicKeyMaterial.base64EncodedString()
            return "ecdsa-sha2-nistp256 \(b64)" + (sshComment.map { " \($0)" } ?? "")
        case .skEd25519:
            let b64 = publicKeyMaterial.base64EncodedString()
            return "sk-ssh-ed25519@openssh.com \(b64)" + (sshComment.map { " \($0)" } ?? "")
        case .skEcdsaP256:
            let b64 = publicKeyMaterial.base64EncodedString()
            return "sk-ecdsa-sha2-nistp256@openssh.com \(b64)" + (sshComment.map { " \($0)" } ?? "")
        }
    }

    /// Private-key display form for the "reveal" path on IdentityDetailView.
    ///   x25519:     the AGE-SECRET-KEY-1... string.
    ///   sshEd25519: an unencrypted OpenSSH private-key PEM, exportable to
    ///               ssh-keygen / ssh-agent / git (added in AgePony 2.0; the
    ///               seed is serialized into the standard OpenSSH container).
    ///   sshRSA:     the stored OpenSSH PEM.
    public func privateDisplayString() -> String {
        switch type {
        case .x25519:
            if let id = try? X25519Identity(privateKey: privateKeyMaterial) {
                return id.ageIdentityString
            }
            return "(invalid x25519 identity)"
        case .sshEd25519:
            guard privateKeyMaterial.count == 64 else {
                return "(invalid ed25519 private material)"
            }
            if let pem = try? OpenSSHEd25519Export.privateKeyPEM(
                privateMaterial: privateKeyMaterial,
                comment: sshComment ?? ""
            ) {
                return pem
            }
            return "(could not serialize ed25519 private key)"
        case .sshRSA:
            return String(data: privateKeyMaterial, encoding: .utf8) ?? "(non-UTF8 PEM)"
        case .secureEnclaveP256:
            return "(Secure Enclave — the private key is generated in hardware and never leaves this device)"
        case .skEd25519, .skEcdsaP256:
            return "(Security key — the private key lives on your hardware security key and never leaves it)"
        }
    }

    private static func extractEd25519PublicKey(fromWireBlob blob: Data) throws -> Data {
        // Layout: <len=11>"ssh-ed25519"<len=32><pubkey>
        guard blob.count >= 4 else { throw VaultModelError.malformedPublicMaterial(.sshEd25519) }
        let len1 = UInt32(blob[blob.startIndex])     << 24
                 | UInt32(blob[blob.startIndex + 1]) << 16
                 | UInt32(blob[blob.startIndex + 2]) << 8
                 | UInt32(blob[blob.startIndex + 3])
        let typeStart = blob.startIndex + 4
        let typeEnd   = typeStart + Int(len1)
        guard typeEnd <= blob.endIndex else { throw VaultModelError.malformedPublicMaterial(.sshEd25519) }
        let typeBytes = blob[typeStart..<typeEnd]
        guard String(data: typeBytes, encoding: .utf8) == "ssh-ed25519" else {
            throw VaultModelError.malformedPublicMaterial(.sshEd25519)
        }
        let lenIdx = typeEnd
        guard lenIdx + 4 <= blob.endIndex else { throw VaultModelError.malformedPublicMaterial(.sshEd25519) }
        let len2 = UInt32(blob[lenIdx])     << 24
                 | UInt32(blob[lenIdx + 1]) << 16
                 | UInt32(blob[lenIdx + 2]) << 8
                 | UInt32(blob[lenIdx + 3])
        let pubStart = lenIdx + 4
        let pubEnd   = pubStart + Int(len2)
        guard pubEnd <= blob.endIndex, len2 == 32 else {
            throw VaultModelError.malformedPublicMaterial(.sshEd25519)
        }
        return Data(blob[pubStart..<pubEnd])
    }
}

// MARK: - Recipient (stubbed for 1c; full surface added in 1e)

public enum StoredRecipientType: String, Codable, Hashable {
    case x25519
    case sshEd25519
    case sshRSA
}

public enum StoredRecipientSource: String, Codable, Hashable {
    case pasteAge
    case pasteSSH
    case qrScan
    case github
    case contacts
    case derivedFromIdentity  // for the "self" entries surfaced when encrypt-to-self is on
}

public struct StoredRecipient: Codable, Identifiable, Hashable {
    public let id: UUID
    public var name: String
    public let type: StoredRecipientType
    public let publicKeyMaterial: Data
    public var sshComment: String?
    public let source: StoredRecipientSource
    public var sourceMetadata: String?
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        name: String,
        type: StoredRecipientType,
        publicKeyMaterial: Data,
        sshComment: String? = nil,
        source: StoredRecipientSource,
        sourceMetadata: String? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.publicKeyMaterial = publicKeyMaterial
        self.sshComment = sshComment
        self.source = source
        self.sourceMetadata = sourceMetadata
        self.createdAt = createdAt
    }
}

// MARK: - Note (stubbed for 1c; full surface added in 1f)

public struct StoredNote: Codable, Identifiable, Hashable {
    public let id: UUID
    public var title: String
    /// scrypt-armored age payload (.age bytes wrapping the note body).
    public var bodyCiphertext: Data
    public let createdAt: Date
    public var updatedAt: Date

    public init(
        id: UUID = UUID(),
        title: String,
        bodyCiphertext: Data,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.bodyCiphertext = bodyCiphertext
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

// MARK: - Errors

public enum VaultModelError: Error, Equatable {
    case malformedPublicMaterial(StoredIdentityType)
    case malformedPrivateMaterial(StoredIdentityType)
    case signingOnlyIdentity(StoredIdentityType)
}
