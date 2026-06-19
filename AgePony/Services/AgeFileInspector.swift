//
//  AgeFileInspector.swift
//  AgePony
//
//  Pre-flight inspection of a .age file. The Decrypt flow runs this before
//  prompting biometric / asking for a passphrase, so the user sees what
//  they're about to decrypt before the OS authentication popup fires.
//
//  We don't attempt to decrypt here — we just parse the header to enumerate
//  the recipient stanzas. This is cheap (no scrypt KDF, no key agreement)
//  and lets the FileInfoCard show:
//      • size of the file
//      • armor format (binary or PEM)
//      • per-stanza summary ("1 X25519, 2 ssh-ed25519, 1 scrypt passphrase")
//      • for SSH stanzas, a "matches your identity 'X'" hint when the
//        first stanza arg (the 4-byte SHA256-tag of the SSH wire blob)
//        matches one of the user's stored SSH identities.
//

import Foundation
import CryptoKit
import AgePonyCore

public struct AgeFileSummary: Equatable {
    public let binaryByteCount: Int          // size of the underlying binary age payload
    public let armored: Bool                  // true if input was PEM-armored
    public let stanzas: [StanzaSummary]
    public let onlyScrypt: Bool               // true if every stanza is "scrypt"
    public let binaryBytes: Data              // the binary age payload (already unarmored if needed)
}

public struct StanzaSummary: Equatable, Identifiable {
    public let id: UUID = UUID()
    public let kind: Kind
    /// For SSH stanzas, the first 4 bytes of SHA256(wireBlob) in base64.
    /// nil for X25519 (anonymous-recipient stanzas) and scrypt.
    public let sshTag: String?
    /// Set by the inspector when the sshTag matches one of the user's
    /// own identities. Used to render the "matches your X identity" hint.
    public let matchedIdentityName: String?

    public enum Kind: String, Equatable {
        case x25519        = "X25519"
        case sshEd25519    = "ssh-ed25519"
        case sshRSA        = "ssh-rsa"
        case scrypt        = "scrypt"
        case unknown       = "unknown"

        public var displayLabel: String {
            switch self {
            case .x25519:     return "age X25519 recipient"
            case .sshEd25519: return "SSH Ed25519 recipient"
            case .sshRSA:     return "SSH RSA recipient"
            case .scrypt:     return "Passphrase (scrypt)"
            case .unknown:    return "Unknown recipient type"
            }
        }
    }

    public init(kind: Kind, sshTag: String? = nil, matchedIdentityName: String? = nil) {
        self.kind = kind
        self.sshTag = sshTag
        self.matchedIdentityName = matchedIdentityName
    }
}

public enum AgeFileInspectorError: Error, Equatable {
    case notAnAgeFile
    case malformedArmor
    case headerParseFailed(String)
}

public enum AgeFileInspector {

    /// Inspect a buffer of .age file bytes. Auto-detects armor and unwraps
    /// before parsing the header.
    public static func inspect(fileBytes raw: Data, knownIdentities: [StoredIdentity]) throws -> AgeFileSummary {
        // Detect armor by sniffing the first ~64 bytes as UTF-8.
        let armored: Bool
        let binary: Data
        if let text = String(data: raw, encoding: .utf8), AgeArmor.looksArmored(text) {
            armored = true
            do {
                binary = try AgeArmor.decode(text)
            } catch {
                throw AgeFileInspectorError.malformedArmor
            }
        } else {
            armored = false
            binary = raw
        }

        // The binary form must start with the age v1 version line.
        let versionLine = AgeHeaderConstants.versionLine + "\n"
        let versionBytes = Data(versionLine.utf8)
        guard binary.count >= versionBytes.count,
              binary.prefix(versionBytes.count) == versionBytes else {
            throw AgeFileInspectorError.notAnAgeFile
        }

        let header: AgeHeader
        do {
            (header, _) = try AgeHeader.parse(bytes: binary)
        } catch let e as AgeHeaderError {
            throw AgeFileInspectorError.headerParseFailed(String(describing: e))
        } catch {
            throw AgeFileInspectorError.headerParseFailed(error.localizedDescription)
        }

        // Pre-compute the SSH tag for each of the user's SSH identities so
        // we can match stanzas to them and surface the matched identity name.
        let identityTags = sshTagsByIdentityName(knownIdentities)

        var summaries: [StanzaSummary] = []
        summaries.reserveCapacity(header.stanzas.count)
        for stanza in header.stanzas {
            switch stanza.type {
            case "X25519":
                summaries.append(StanzaSummary(kind: .x25519))
            case "ssh-ed25519":
                let tag = stanza.args.first
                summaries.append(StanzaSummary(
                    kind: .sshEd25519,
                    sshTag: tag,
                    matchedIdentityName: tag.flatMap { identityTags[$0] }
                ))
            case "ssh-rsa":
                let tag = stanza.args.first
                summaries.append(StanzaSummary(
                    kind: .sshRSA,
                    sshTag: tag,
                    matchedIdentityName: tag.flatMap { identityTags[$0] }
                ))
            case "scrypt":
                summaries.append(StanzaSummary(kind: .scrypt))
            default:
                summaries.append(StanzaSummary(kind: .unknown))
            }
        }

        let onlyScrypt = !summaries.isEmpty && summaries.allSatisfy { $0.kind == .scrypt }

        return AgeFileSummary(
            binaryByteCount: binary.count,
            armored: armored,
            stanzas: summaries,
            onlyScrypt: onlyScrypt,
            binaryBytes: binary
        )
    }

    /// Compute the SSH stanza tag for each SSH identity in the vault.
    /// Tag = first 4 bytes of SHA-256(wireBlob), base64-encoded (no padding).
    /// This matches age's tagging convention for both ssh-ed25519 and ssh-rsa.
    private static func sshTagsByIdentityName(_ identities: [StoredIdentity]) -> [String: String] {
        var map: [String: String] = [:]
        for identity in identities {
            switch identity.type {
            case .sshEd25519, .sshRSA:
                let digest = SHA256.hash(data: identity.publicKeyMaterial)
                let first4 = Data(digest.prefix(4))
                var b64 = first4.base64EncodedString()
                while b64.hasSuffix("=") { b64.removeLast() }
                map[b64] = identity.name
            case .x25519, .secureEnclaveP256, .skEd25519, .skEcdsaP256:
                continue
            }
        }
        return map
    }
}
