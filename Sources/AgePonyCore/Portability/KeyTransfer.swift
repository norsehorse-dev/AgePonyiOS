//
//  KeyTransfer.swift
//  AgePonyCore
//
//  Moving identities between devices (format `agepony.com/transfer v1`, Android 5.0.0).
//
//  The receiving device makes a one-time post-quantum identity and shows its recipient.
//  The sending device encrypts a small tar to that recipient. The result is an ordinary
//  age file, so a transfer never depends on AgePony being at both ends:
//
//    FORMAT           the literal `agepony.com/transfer v1`
//    identities.txt   a standard age identity file (`AGE-SECRET-KEY-1...`,
//                     `AGE-SECRET-KEY-PQ-1...`, with `# name` / `# created` /
//                     `# public key` comments). `age -d` then `tar x` gives a file that
//                     works with `age -i` as it is.
//    ssh/<name>       OpenSSH private keys, when any were sent
//    agepony.json     AgePony's metadata (names, types, recipients, trusted signers).
//                     Opaque here; the app owns its schema (Android's JSON shapes).
//
//  Nothing here decides what may be sent: hardware-bound keys can't be exported at all
//  and the app filters them out before packing.
//
//  Two short codes go with a transfer:
//    - confirmationCode(recipient:): both screens show it so the sender can check it
//      scanned the right receiver;
//    - TransferCode.of(sealed:) (5.0.1, audit M-6): over the exact sealed bytes, so the
//      receiver can check it holds the sender's transfer and not one someone else sent
//      first after photographing the QR code.
//
//  Mirrors Android agepony-core `portability/KeyTransfer.kt` and `TransferCode.kt`.
//

import Foundation
import CryptoKit

public enum KeyTransferError: Error, Equatable {
    case notATransfer(String)
    case unsupportedFormat(String)
    case tooManyEntries
    case wrongSession
    case notARecipient
}

public enum KeyTransfer {
    public static let formatLine = "agepony.com/transfer v1"

    static let formatFile = "FORMAT"
    static let identitiesFile = "identities.txt"
    static let metadataFile = "agepony.json"
    static let sshDirectory = "ssh/"
    static let maxEntries = 512

    public struct Bundle: Equatable {
        /// Contents of identities.txt (may be empty if only SSH keys were sent).
        public var identitiesTxt: String
        /// OpenSSH private keys, file name to PEM text.
        public var sshKeys: [String: String]
        /// App metadata JSON, opaque to the core.
        public var metadataJSON: String

        public init(identitiesTxt: String, sshKeys: [String: String] = [:], metadataJSON: String = "") {
            self.identitiesTxt = identitiesTxt
            self.sshKeys = sshKeys
            self.metadataJSON = metadataJSON
        }
    }

    /// One entry of an age identity file.
    public struct IdentityLine: Equatable {
        public let name: String?
        public let publicKey: String
        public let secretKey: String
        public let createdISO: String?

        public init(name: String?, publicKey: String, secretKey: String, createdISO: String?) {
            self.name = name
            self.publicKey = publicKey
            self.secretKey = secretKey
            self.createdISO = createdISO
        }
    }

    /// Render entries as a standard age identity file. `includePublicKey` false leaves
    /// out the `# public key:` comment, which for a post-quantum key is ~2000 characters:
    /// too much for a paper backup's QR code, and derivable from the secret key anyway.
    public static func identityFile(_ lines: [IdentityLine], includePublicKey: Bool = true) -> String {
        var out = ""
        for l in lines {
            if let name = l.name, !name.trimmingCharacters(in: .whitespaces).isEmpty {
                out += "# name: " + oneLine(name) + "\n"
            }
            if let created = l.createdISO { out += "# created: " + created + "\n" }
            if includePublicKey { out += "# public key: " + l.publicKey + "\n" }
            out += l.secretKey + "\n\n"
        }
        return out
    }

    public static func pack(_ bundle: Bundle) throws -> Data {
        var entries = [TarArchive.Entry(name: formatFile, data: Data((formatLine + "\n").utf8))]
        entries.append(TarArchive.Entry(name: identitiesFile, data: Data(bundle.identitiesTxt.utf8)))
        var used = Set<String>()
        // Sorted so the tar is deterministic (Kotlin keeps insertion order; Swift
        // dictionaries have none).
        for name in bundle.sshKeys.keys.sorted() {
            let base = safeName(name)
            var unique = base
            var n = 2
            while !used.insert(unique).inserted { unique = "\(base)-\(n)"; n += 1 }
            entries.append(TarArchive.Entry(name: sshDirectory + unique, data: Data(bundle.sshKeys[name]!.utf8)))
        }
        entries.append(TarArchive.Entry(name: metadataFile, data: Data(bundle.metadataJSON.utf8)))
        return try TarArchive.create(entries)
    }

    public static func unpack(_ tar: Data) throws -> Bundle {
        let entries: [TarArchive.Entry]
        do {
            entries = try TarArchive.extract(tar)
        } catch {
            throw KeyTransferError.notATransfer("not a valid archive")
        }
        guard entries.count <= maxEntries else { throw KeyTransferError.tooManyEntries }
        func text(_ name: String) -> String? {
            entries.first { $0.name == name }.map { String(decoding: $0.data, as: UTF8.self) }
        }
        guard let format = text(formatFile)?.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw KeyTransferError.notATransfer("no FORMAT entry")
        }
        guard format == formatLine else { throw KeyTransferError.unsupportedFormat(format) }
        var ssh: [String: String] = [:]
        for e in entries where e.name.hasPrefix(sshDirectory) && e.name.count > sshDirectory.count {
            ssh[String(e.name.dropFirst(sshDirectory.count))] = String(decoding: e.data, as: UTF8.self)
        }
        return Bundle(identitiesTxt: text(identitiesFile) ?? "", sshKeys: ssh, metadataJSON: text(metadataFile) ?? "")
    }

    /// Encrypt `bundle` to the receiving device's one-time recipient. Binary age output.
    public static func seal(_ bundle: Bundle, to recipient: AgeRecipient) throws -> Data {
        try Age.encrypt(plaintext: try pack(bundle), to: [recipient])
    }

    /// Decrypt a transfer (binary or armored) with the receiving device's one-time identity.
    public static func open(_ ciphertext: Data, with identity: HybridIdentity) throws -> Bundle {
        let binary = looksArmored(ciphertext)
            ? try AgeArmor.decode(String(decoding: ciphertext, as: UTF8.self))
            : ciphertext
        let tar: Data
        do {
            tar = try Age.decrypt(ciphertext: binary, identities: [identity])
        } catch AgeError.noMatchingIdentity {
            throw KeyTransferError.wrongSession
        }
        return try unpack(tar)
    }

    /// Parse a transfer recipient as the receiver shows it: `age1pq1...` preferred,
    /// `age1...` accepted. QR codes carry it upper-cased (alphanumeric mode is denser).
    public static func parseRecipient(_ s: String) throws -> AgeRecipient {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if t.hasPrefix("age1pq1") { return try HybridRecipient(ageRecipient: t) }
        if t.hasPrefix("age1") { return try X25519Recipient(ageRecipient: t) }
        throw KeyTransferError.notARecipient
    }

    /// Short code both screens show so the user can confirm the sender scanned the
    /// right receiver: 60 bits of SHA-256 over the recipient string.
    public static func confirmationCode(recipient: String) -> String {
        let normalized = recipient.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return code60(Data(SHA256.hash(data: Data(normalized.utf8))))
    }

    /// The first 60 bits of `digest` as 12 Crockford base32 characters, `XXXX-XXXX-XXXX`.
    static func code60(_ digest: Data) -> String {
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        let acc = digest.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let chars = (0..<12).map { i in alphabet[Int((acc >> UInt64(64 - 5 * (i + 1))) & 31)] }
        return [chars[0..<4], chars[4..<8], chars[8..<12]].map { String($0) }.joined(separator: "-")
    }

    static func looksArmored(_ b: Data) -> Bool {
        String(decoding: b.prefix(64), as: UTF8.self)
            .drop(while: { $0.isWhitespace })
            .hasPrefix("-----BEGIN AGE ENCRYPTED FILE-----")
    }

    static func safeName(_ name: String) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        let mapped = String(name.map { allowed.contains($0) ? $0 : "_" })
        let trimmed = mapped.trimmingCharacters(in: CharacterSet(charactersIn: "._"))
        let cut = String(trimmed.prefix(60))
        return cut.isEmpty ? "key" : cut
    }

    static func oneLine(_ s: String) -> String {
        s.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespaces)
    }
}

/// A short code over the exact sealed transfer (audit M-6). The sender shows it over
/// what it sent, the receiver over what it received, before Import is enabled. They
/// match only if the receiver holds the sender's transfer.
///
/// code = first 60 bits of SHA-256("agepony.com/transfer-code v1" || 0x00 || sealed),
/// Crockford base32, `XXXX-XXXX-XXXX`. An armored transfer (the paste route) is
/// de-armored first, so every route gives the same code.
public enum TransferCode {
    public static let domain = "agepony.com/transfer-code v1"

    public static func of(sealed: Data) -> String {
        var binary = sealed
        if KeyTransfer.looksArmored(sealed),
           let decoded = try? AgeArmor.decode(String(decoding: sealed, as: UTF8.self)) {
            binary = decoded
        }
        var h = SHA256()
        h.update(data: Data(domain.utf8))
        h.update(data: Data([0]))
        h.update(data: binary)
        return KeyTransfer.code60(Data(h.finalize()))
    }
}
