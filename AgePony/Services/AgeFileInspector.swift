//
//  AgeFileInspector.swift
//  AgePony
//
//  Pre-flight inspection of a .age file. The Decrypt flow runs this before
//  prompting for biometrics or a passphrase, so the user sees what they are
//  about to decrypt before the OS authentication popup fires.
//
//  Nothing is decrypted here. Only the header is parsed, which is cheap — no
//  scrypt KDF, no key agreement — and lets FileInfoCard show the file's size,
//  its format, a per-stanza summary, and for SSH stanzas a "matches your
//  identity X" hint.
//
//  Two entry points, because the two callers have genuinely different needs:
//
//    inspect(fileURL:)   — reads only the header off disk. A file of any size
//                          inspects instantly and costs a few KB of memory.
//                          Used by the Files decrypt flow.
//
//    inspect(fileBytes:) — takes bytes already in hand and keeps the decoded
//                          payload in the summary. Used by Text mode, where
//                          the input is pasted text and is small by nature.
//
//  The URL path exists because the buffered one was the real memory ceiling on
//  the decrypt side: it held the file as Data, converted the *whole* file to a
//  String to sniff for armor, decoded that whole string, and then kept the
//  decoded payload alive in the view's state for as long as the screen was up.
//  For a 130 MB armored file that is several hundred MB resident before the
//  user has even tapped Decrypt.
//

import Foundation
import CryptoKit
import AgePonyCore

public struct AgeFileSummary: Equatable {
    /// Size of the age payload. For a file read from disk this is its size on
    /// disk, which is what the user recognises; for pasted text it is the size
    /// of the decoded binary.
    public let byteCount: Int
    /// True if the input was PEM-armored.
    public let armored: Bool
    public let stanzas: [StanzaSummary]
    /// True if every stanza is "scrypt", meaning a passphrase is the only way in.
    public let onlyScrypt: Bool
    /// The binary age payload, when the caller already had it in memory.
    ///
    /// nil for the URL-based inspection, which never reads past the header —
    /// that is the point of it. Callers decrypt from the file instead.
    public let binaryBytes: Data?

    /// True if any recipient is post-quantum.
    public var isPostQuantum: Bool {
        stanzas.contains { $0.kind == .postQuantum }
    }

    /// True if a stanza names one of the user's own identities.
    ///
    /// Only SSH stanzas carry a recipient tag; X25519 and post-quantum stanzas
    /// are deliberately anonymous, so false means "cannot tell from the header",
    /// not "you cannot open it".
    public var matchesAKnownIdentity: Bool {
        stanzas.contains { $0.matchedIdentityName != nil }
    }

    /// The scrypt work factor, when this is a passphrase file.
    public var scryptWorkFactor: Int? {
        stanzas.compactMap(\.scryptWorkFactor).first
    }
}

public struct StanzaSummary: Equatable, Identifiable {
    public let id: UUID = UUID()
    public let kind: Kind
    /// For SSH stanzas, the first 4 bytes of SHA256(wireBlob) in base64.
    /// nil for X25519 (anonymous-recipient stanzas) and scrypt.
    public let sshTag: String?
    /// Set by the inspector when the sshTag matches one of the user's own
    /// identities. Used to render the "matches your X identity" hint.
    public let matchedIdentityName: String?
    /// For scrypt stanzas, the work factor recorded in the file.
    ///
    /// What opening the file will cost, regardless of the reader's own setting:
    /// the factor travels with the file, not with the app.
    public let scryptWorkFactor: Int?

    public enum Kind: String, Equatable {
        case x25519        = "X25519"
        case sshEd25519    = "ssh-ed25519"
        case sshRSA        = "ssh-rsa"
        case scrypt        = "scrypt"
        case postQuantum   = "mlkem768x25519"
        case unknown       = "unknown"

        public var displayLabel: String {
            switch self {
            case .x25519:      return "age X25519 recipient"
            case .sshEd25519:  return "SSH Ed25519 recipient"
            case .sshRSA:      return "SSH RSA recipient"
            case .scrypt:      return "Passphrase (scrypt)"
            case .postQuantum: return "Post-quantum recipient"
            case .unknown:     return "Unknown recipient type"
            }
        }
    }

    public init(
        kind: Kind,
        sshTag: String? = nil,
        matchedIdentityName: String? = nil,
        scryptWorkFactor: Int? = nil
    ) {
        self.kind = kind
        self.sshTag = sshTag
        self.matchedIdentityName = matchedIdentityName
        self.scryptWorkFactor = scryptWorkFactor
    }
}

public enum AgeFileInspectorError: Error, Equatable {
    case notAnAgeFile
    case malformedArmor
    case headerParseFailed(String)
    case cannotOpenFile(String)
}

public enum AgeFileInspector {

    // MARK: - Header-only inspection, from disk

    /// Inspect a file by reading only its header.
    ///
    /// Instant regardless of file size, and holds nothing but the header. The
    /// returned summary has a nil `binaryBytes`; decrypt straight from the file.
    public static func inspect(
        fileURL: URL,
        knownIdentities: [StoredIdentity]
    ) throws -> AgeFileSummary {
        let scoped = fileURL.startAccessingSecurityScopedResource()
        defer { if scoped { fileURL.stopAccessingSecurityScopedResource() } }

        let armored = try sniffArmored(fileURL)

        guard let raw = InputStream(url: fileURL) else {
            throw AgeFileInspectorError.cannotOpenFile(fileURL.lastPathComponent)
        }
        raw.open()
        defer { raw.close() }

        let source: InputStream = armored ? ArmorDecodingSource(raw) : raw
        source.open()

        let header: AgeHeader
        do {
            header = try Age.parseHeaderStream(ciphertext: source)
        } catch {
            // An armor fault surfaces on the decoding source rather than as a
            // header error, so report that specifically when it is the cause.
            if armored, (source as? ArmorDecodingSource)?.streamError != nil {
                throw AgeFileInspectorError.malformedArmor
            }
            throw mapHeaderError(error)
        }

        let size = (try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? NSNumber)??
            .intValue ?? 0

        return summarize(
            header: header,
            byteCount: size,
            armored: armored,
            binaryBytes: nil,
            knownIdentities: knownIdentities
        )
    }

    // MARK: - Buffered inspection, for bytes already in hand

    /// Inspect bytes already in memory, keeping the decoded payload in the summary.
    ///
    /// For Text mode, where the input is pasted and small. Prefer the URL entry
    /// point for anything file-sized.
    public static func inspect(
        fileBytes raw: Data,
        knownIdentities: [StoredIdentity]
    ) throws -> AgeFileSummary {
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

        let versionBytes = Data((AgeHeaderConstants.versionLine + "\n").utf8)
        guard binary.count >= versionBytes.count,
              binary.prefix(versionBytes.count) == versionBytes else {
            throw AgeFileInspectorError.notAnAgeFile
        }

        let header: AgeHeader
        do {
            (header, _) = try AgeHeader.parse(bytes: binary)
        } catch {
            throw mapHeaderError(error)
        }

        return summarize(
            header: header,
            byteCount: binary.count,
            armored: armored,
            binaryBytes: binary,
            knownIdentities: knownIdentities
        )
    }

    // MARK: - Internals

    /// Read only the first bytes to decide whether the file is armored.
    private static func sniffArmored(_ url: URL) throws -> Bool {
        guard let probe = InputStream(url: url) else {
            throw AgeFileInspectorError.cannotOpenFile(url.lastPathComponent)
        }
        probe.open()
        defer { probe.close() }
        var buffer = [UInt8](repeating: 0, count: AgeArmor.sniffLength)
        let n = probe.read(&buffer, maxLength: buffer.count)
        guard n > 0 else { throw AgeFileInspectorError.notAnAgeFile }
        return AgeArmor.looksArmored(prefix: Data(buffer[0..<n]))
    }

    private static func mapHeaderError(_ error: Error) -> AgeFileInspectorError {
        if let e = error as? AgeError {
            switch e {
            case .headerError(let h): return .headerParseFailed(String(describing: h))
            default:                  return .headerParseFailed(String(describing: e))
            }
        }
        if let e = error as? AgeHeaderError {
            return .headerParseFailed(String(describing: e))
        }
        return .headerParseFailed(error.localizedDescription)
    }

    private static func summarize(
        header: AgeHeader,
        byteCount: Int,
        armored: Bool,
        binaryBytes: Data?,
        knownIdentities: [StoredIdentity]
    ) -> AgeFileSummary {
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
                // -> scrypt <base64 salt> <workFactor>
                let factor = stanza.args.count >= 2 ? Int(stanza.args[1]) : nil
                summaries.append(StanzaSummary(kind: .scrypt, scryptWorkFactor: factor))
            case "mlkem768x25519":
                summaries.append(StanzaSummary(kind: .postQuantum))
            default:
                summaries.append(StanzaSummary(kind: .unknown))
            }
        }

        let onlyScrypt = !summaries.isEmpty && summaries.allSatisfy { $0.kind == .scrypt }

        return AgeFileSummary(
            byteCount: byteCount,
            armored: armored,
            stanzas: summaries,
            onlyScrypt: onlyScrypt,
            binaryBytes: binaryBytes
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
            // No SSH tag: like X25519, the post-quantum stanza is anonymous,
            // so a file cannot advertise that it is addressed to you.
            case .x25519, .postQuantum, .secureEnclaveP256, .skEd25519, .skEcdsaP256:
                continue
            }
        }
        return map
    }
}
