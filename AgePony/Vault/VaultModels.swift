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
import LocalAuthentication
import AgePonyCore

// MARK: - Identity

/// The kinds of identity the vault can hold.
///
/// `CaseIterable`, and **declaration order is display order**. The identity list
/// used to walk a hand-written array of types instead, which meant adding a case
/// here dropped those identities off the screen entirely -- generated, saved and
/// persisted, but invisible, which reads to a user as "it didn't save". An array
/// literal is a switch the compiler cannot check. Nothing enumerates these by hand
/// any more; add a case and it appears.
public enum StoredIdentityType: String, Codable, Hashable, CaseIterable {
    case x25519
    /// MLKEM768-X25519 hybrid. Private material is the 32-byte seed; the
    /// public half is derived from it deterministically.
    case postQuantum
    /// Secure Enclave P-256 decryption key, an `age1tag1…` recipient (5.0.1).
    case secureEnclaveTag
    /// Secure Enclave P-256 plus an ML-KEM-768 half, an `age1tagpq1…` recipient
    /// (5.0.1). Quantum-safe. The ML-KEM half is a vault seed (5.0.1, and below iOS 26)
    /// or, for keys made on iOS 26 and later, a second Secure Enclave key (5.1.0 RC3).
    /// Deliberately the same case for both: see `SecureEnclaveTagPQMaterial`.
    case secureEnclaveTagPQ
    /// A key on a YubiKey's PIV applet (age-plugin-yubikey), decrypting over NFC
    /// (5.0.1). Opens `piv-p256` and `p256tag` stanzas.
    case yubikey
    case sshEd25519
    case sshRSA
    case secureEnclaveP256
    case skEd25519
    case skEcdsaP256

    /// Section heading for a group of these. A switch, so it cannot go stale.
    public var sectionTitle: String {
        switch self {
        case .x25519:            return String(localized: "age X25519")
        case .postQuantum:       return String(localized: "Post-quantum hybrid")
        case .secureEnclaveTag:  return String(localized: "Secure Enclave (age1tag)")
        case .secureEnclaveTagPQ: return String(localized: "Secure Enclave, quantum-safe (age1tagpq)")
        case .yubikey:           return String(localized: "YubiKey (age1yubikey)")
        case .sshEd25519:        return String(localized: "SSH Ed25519")
        case .sshRSA:            return String(localized: "SSH RSA")
        case .secureEnclaveP256: return String(localized: "Secure Enclave signing (P-256)")
        case .skEd25519:         return String(localized: "Security key (Ed25519)")
        case .skEcdsaP256:       return String(localized: "Security key (P-256)")
        }
    }
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
    ///   secureEnclaveTag: 33-byte compressed P-256 point
    ///   secureEnclaveTagPQ: 1249-byte hybrid public key (ML-KEM ek || P-256 point)
    ///   yubikey:   33-byte compressed P-256 point of the PIV slot's key
    public let publicKeyMaterial: Data

    /// Private material in a type-appropriate form:
    ///   x25519:    32-byte raw X25519 private scalar
    ///   sshEd25519: 64 bytes = seed(32) || pub(32)
    ///   sshRSA:    UTF-8 bytes of the decrypted OpenSSH PEM string
    ///   secureEnclaveP256: the SE key's opaque dataRepresentation
    ///   secureEnclaveTag: the SE key's opaque dataRepresentation
    ///   secureEnclaveTagPQ: one of two layouts (AgePonyCore SecureEnclaveTagPQ.swift):
    ///              5.0.1: ML-KEM seed (64 bytes, d || z) || SE dataRepresentation
    ///              5.1.0 on iOS 26+: "AGPNSE2\0" || UInt32 BE length || ML-KEM SE
    ///              dataRepresentation || P-256 SE dataRepresentation (no seed)
    ///   yubikey:   the 9-byte age-plugin-yubikey stub (serial, slot, tag); not secret
    public let privateKeyMaterial: Data

    /// Optional SSH comment ("user@host"), GitHub username, etc.
    public var sshComment: String?

    public let createdAt: Date

    /// `yubikey` only (5.1.0 item 1): whether the slot wants the PIN, so a decrypt asks
    /// for it before the tap instead of after a failed one. nil (every vault written
    /// before 5.1.0) means `.unknown`. Optional and synthesized, so it decodes as nil
    /// when missing, and a 5.0.1 build reading a 5.1.0 vault ignores the key.
    public var pinPolicy: YubiKeyPINPolicy?

    public init(
        id: UUID = UUID(),
        name: String,
        type: StoredIdentityType,
        publicKeyMaterial: Data,
        privateKeyMaterial: Data,
        sshComment: String? = nil,
        createdAt: Date = Date(),
        pinPolicy: YubiKeyPINPolicy? = nil
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.publicKeyMaterial = publicKeyMaterial
        self.privateKeyMaterial = privateKeyMaterial
        self.sshComment = sshComment
        self.createdAt = createdAt
        self.pinPolicy = pinPolicy
    }

    /// The PIN policy a decrypt goes by: the stored one, `.unknown` when none is stored.
    public var yubiKeyPINPolicy: YubiKeyPINPolicy { pinPolicy ?? .unknown }

    // MARK: - Hydration

    /// Length of the ML-KEM seed at the front of a 5.0.1-layout `secureEnclaveTagPQ` key.
    static let mlkemSeedSize = SecureEnclaveTagPQMaterial.mlkemSeedSize

    /// Construct the concrete crypto-layer identity type for use with
    /// `Age.decrypt(ciphertext:identities:)`. `authenticationContext` is an
    /// LAContext the caller has just evaluated; a Secure Enclave key that wants
    /// presence for each use takes it instead of prompting a second time.
    public func toAgeIdentity(authenticationContext: LAContext? = nil) throws -> any AgeIdentity {
        switch type {
        case .secureEnclaveTag:
            let se = SecureEnclaveKeyAgreement(dataRepresentation: privateKeyMaterial,
                                               authenticationContext: authenticationContext)
            return try TagIdentity.classic(publicKey: publicKeyMaterial, p256: se)
        case .secureEnclaveTagPQ:
            // Either layout (5.1.0 RC3). A key with both halves in the Enclave gets one
            // LAContext for the pair, so Face ID asks once. A 5.0.1 build reading the
            // new layout still opens the vault; only that key fails to decrypt (see
            // SecureEnclaveTagPQMaterial).
            guard privateKeyMaterial.count > Self.mlkemSeedSize,
                  publicKeyMaterial.count == HpkeP256.hybridPublicKeySize else {
                throw VaultModelError.malformedPrivateMaterial(type)
            }
            do {
                return try SecureEnclaveTagPQ.identity(privateKeyMaterial: privateKeyMaterial,
                                                       publicKey: publicKeyMaterial,
                                                       authenticationContext: authenticationContext)
            } catch is SecureEnclaveTagPQMaterialError {
                throw VaultModelError.malformedPrivateMaterial(type)
            }
        case .yubikey:
            // Needs an NFC tap first; the decrypt flows run that and build a
            // YubiKeyIdentity with the recorded results (see YubiKeyDecrypt).
            throw VaultModelError.needsYubiKeyTap
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
        case .postQuantum:
            return try HybridIdentity(seed: privateKeyMaterial)
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
        case .postQuantum:
            return try HybridRecipient(publicKey: publicKeyMaterial)
        case .secureEnclaveTag, .secureEnclaveTagPQ:
            return try TagRecipient(publicKey: publicKeyMaterial)
        case .yubikey:
            return try P256Recipient(compressedPublicKey: publicKeyMaterial)
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
        // ML-KEM is a key encapsulation mechanism, not a signature scheme.
        case .postQuantum:            return false
        case .secureEnclaveTag, .secureEnclaveTagPQ, .yubikey: return false
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
        case .postQuantum:                  return true
        case .secureEnclaveTag, .secureEnclaveTagPQ, .yubikey: return true
        case .secureEnclaveP256:            return false
        case .skEd25519, .skEcdsaP256:      return false
        }
    }

    /// Whether this identity signs on an external hardware security key (FIDO
    /// sk-*), which requires the async NFC signing path rather than FileSigner.
    public var isSecurityKey: Bool {
        type == .skEd25519 || type == .skEcdsaP256
    }

    /// Whether this identity decrypts in hardware (5.0.1): the private key can't
    /// be revealed, exported, transferred or put on paper.
    public var isHardwareDecryptionKey: Bool {
        type == .secureEnclaveTag || type == .secureEnclaveTagPQ || type == .yubikey
    }

    /// `secureEnclaveTagPQ` only: whether the ML-KEM half is in the Secure Enclave too
    /// (made on iOS 26 or later) rather than a seed in the vault.
    public var mlkemInSecureEnclave: Bool {
        guard type == .secureEnclaveTagPQ else { return false }
        return (try? SecureEnclaveTagPQMaterial.decode(privateKeyMaterial))?.mlkemInEnclave ?? false
    }

    /// The age-plugin-yubikey stub of a `yubikey` identity.
    public var yubiKeyStub: YubiKeyStub? {
        guard type == .yubikey else { return nil }
        return try? YubiKeyStub(bytes: privateKeyMaterial)
    }

    /// A stand-in for a hardware identity that can only tell which stanzas are
    /// addressed to it, from public data. Never touches the Enclave or the YubiKey.
    public func hardwareProbe() -> HardwareIdentity? {
        let none = RecordedKeyAgreement(results: [:])
        switch type {
        case .secureEnclaveTag:
            return try? TagIdentity.classic(publicKey: publicKeyMaterial, p256: none)
        case .secureEnclaveTagPQ:
            // From the stored public key alone, for either layout: the tag only depends
            // on the P-256 point, and no ML-KEM work is needed to recognise a stanza.
            guard let recipient = try? TagRecipient(publicKey: publicKeyMaterial), recipient.isHybrid else { return nil }
            return TagIdentity.probe(recipient: recipient)
        case .yubikey:
            guard let stub = yubiKeyStub else { return nil }
            return try? YubiKeyIdentity.probe(stub: stub, publicKey: publicKeyMaterial)
        default:
            return nil
        }
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
        case .postQuantum:
            return Bech32.encodePostQuantumRecipient(Array(publicKeyMaterial))
        case .secureEnclaveTag, .secureEnclaveTagPQ:
            return (try? TagRecipient(publicKey: publicKeyMaterial).toBech32()) ?? String(localized: "(invalid hardware key)")
        case .yubikey:
            return Bech32.encodeYubiKeyRecipient(Array(publicKeyMaterial))
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
            return String(data: privateKeyMaterial, encoding: .utf8) ?? String(localized: "(not a readable PEM file)")
        case .postQuantum:
            if let id = try? HybridIdentity(seed: privateKeyMaterial) {
                return id.ageIdentityString
            }
            return "(invalid post-quantum identity)"
        case .secureEnclaveTag, .secureEnclaveTagPQ:
            return String(localized: "(Secure Enclave: decryption happens inside this iPhone's hardware, and the private key can't be exported)")
        case .yubikey:
            // Not secret: the age-plugin-yubikey identity line, which only points
            // at the key on the YubiKey. Useful for setting the same key up elsewhere.
            return yubiKeyStub?.encode() ?? "(invalid YubiKey stub)"
        case .secureEnclaveP256:
            return String(localized: "(Secure Enclave: the private key is generated in hardware and never leaves this device)")
        case .skEd25519, .skEcdsaP256:
            return String(localized: "(Security key: the private key lives on your hardware security key and never leaves it)")
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

public enum StoredRecipientType: String, Codable, Hashable, CaseIterable {
    case x25519
    /// MLKEM768-X25519 hybrid, an `age1pq1…` recipient.
    case postQuantum
    case sshEd25519
    case sshRSA
    /// piv-p256 (age-plugin-yubikey), an `age1yubikey1…` recipient. Only the
    /// YubiKey can decrypt.
    case yubikey
    /// A hardware P-256 key, an `age1tag1…` recipient (age 1.3; 5.0.1).
    case tag
    /// A hardware P-256 key with an ML-KEM-768 half, an `age1tagpq1…` recipient.
    case tagPQ

    /// Section heading for a group of these. See `StoredIdentityType`.
    public var sectionTitle: String {
        switch self {
        case .x25519:     return String(localized: "age X25519")
        case .postQuantum: return String(localized: "Post-quantum hybrid")
        case .sshEd25519: return String(localized: "SSH Ed25519")
        case .sshRSA:     return String(localized: "SSH RSA")
        case .yubikey:    return String(localized: "YubiKey (piv-p256)")
        case .tag:        return String(localized: "Hardware key (age1tag)")
        case .tagPQ:      return String(localized: "Hardware key, quantum-safe (age1tagpq)")
        }
    }

    /// Where a pasted recipient of this type came from.
    ///
    /// A post-quantum recipient is an age-style bech32 string, not an SSH line, so
    /// `x25519 ? age : ssh` gets it wrong -- which is what the picker was doing.
    /// One switch, used by every paste path.
    public var pastedSource: StoredRecipientSource {
        switch self {
        case .x25519, .postQuantum, .yubikey, .tag, .tagPQ: return .pasteAge
        case .sshEd25519, .sshRSA:  return .pasteSSH
        }
    }
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

// MARK: - Recycle bin (4.0.0)

/// A soft-deleted identity awaiting restore or expiry.
public struct TrashedIdentity: Codable, Identifiable, Hashable {
    public var id: UUID { identity.id }
    public let identity: StoredIdentity
    public let deletedAt: Date

    public init(identity: StoredIdentity, deletedAt: Date) {
        self.identity = identity
        self.deletedAt = deletedAt
    }
}

/// A soft-deleted recipient awaiting restore or expiry.
public struct TrashedRecipient: Codable, Identifiable, Hashable {
    public var id: UUID { recipient.id }
    public let recipient: StoredRecipient
    public let deletedAt: Date

    public init(recipient: StoredRecipient, deletedAt: Date) {
        self.recipient = recipient
        self.deletedAt = deletedAt
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
    /// A YubiKey identity, which decrypts only after an NFC tap.
    case needsYubiKeyTap
}
