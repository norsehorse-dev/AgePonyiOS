//
//  RecipientImportService.swift
//  AgePony
//
//  Adapter sitting between the Add Recipient UI and the AgePonyCore
//  parsers. Three import paths (paste, QR, GitHub) all funnel into one
//  internal "make a StoredRecipient from this text" function so the UI
//  surface stays small.
//
//  The crypto-core already knows how to parse `age1...` strings
//  (X25519Recipient.init(ageRecipient:)) and `ssh-* AAAA…` lines
//  (SSHKeySource.parse(text:)). This service wraps those, picks the right
//  StoredRecipientType, copies the public-key bytes into the right
//  serialization shape for the vault, and surfaces a single Result type.
//

import Foundation
import AgePonyCore

public enum RecipientImportError: Error, Equatable {
    case unrecognizedFormat
    case noUsableKeysInResponse
    case fetchFailed(String)
    case invalidUsername
}

public struct RecipientImportCandidate {
    public let type: StoredRecipientType
    public let publicKeyMaterial: Data
    public let sshComment: String?
    public let defaultName: String

    public init(type: StoredRecipientType, publicKeyMaterial: Data, sshComment: String?, defaultName: String) {
        self.type = type
        self.publicKeyMaterial = publicKeyMaterial
        self.sshComment = sshComment
        self.defaultName = defaultName
    }
}

public enum RecipientImportService {

    // MARK: - Paste / QR

    /// Parse a single pasted blob into a recipient candidate. Used for
    /// both the paste field and QR scan results (which are just text).
    public static func parsePastedText(_ rawInput: String) throws -> RecipientImportCandidate {
        let trimmed = rawInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { throw RecipientImportError.unrecognizedFormat }

        // age1pq1... — checked before the plain age1 branch, since "age1pq1"
        // also starts with "age1" and would otherwise be parsed as X25519 and
        // rejected for being the wrong length.
        if trimmed.hasPrefix("age1pq1") {
            let recipient = try HybridRecipient(ageRecipient: trimmed)
            return RecipientImportCandidate(
                type: .postQuantum,
                publicKeyMaterial: recipient.publicKey,
                sshComment: nil,
                defaultName: shortenedAgeName(trimmed)
            )
        }

        // age1...
        if trimmed.hasPrefix("age1") {
            let recipient = try X25519Recipient(ageRecipient: trimmed)
            return RecipientImportCandidate(
                type: .x25519,
                publicKeyMaterial: recipient.publicKey,
                sshComment: nil,
                defaultName: shortenedAgeName(trimmed)
            )
        }

        // ssh-ed25519 / ssh-rsa
        if trimmed.hasPrefix("ssh-ed25519 ") || trimmed.hasPrefix("ssh-rsa ") {
            return try parseSSHLine(trimmed)
        }

        throw RecipientImportError.unrecognizedFormat
    }

    private static func parseSSHLine(_ line: String) throws -> RecipientImportCandidate {
        // We use SSHKeySource.parse so we get the AgeRecipient (which has
        // already validated the line), then extract the right material from
        // it via a follow-up parse. Since SSHKeySource.parse returns the
        // AgeRecipient protocol, we have to do a tiny bit of casting to get
        // back the type-specific wire blob.
        let recipients = SSHKeySource.parse(text: line)
        guard let recipient = recipients.first else {
            throw RecipientImportError.unrecognizedFormat
        }

        // Pull the trailing comment off the line, if any.
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true).map(String.init)
        let comment: String? = parts.count == 3 ? parts[2] : nil

        if let ed = recipient as? SSHEd25519Recipient {
            return RecipientImportCandidate(
                type: .sshEd25519,
                publicKeyMaterial: ed.wireBlob,
                sshComment: comment,
                defaultName: nameFromCommentOr("SSH Ed25519", comment: comment)
            )
        }
        if let rsa = recipient as? SSHRSARecipient {
            return RecipientImportCandidate(
                type: .sshRSA,
                publicKeyMaterial: rsa.wireBlob,
                sshComment: comment,
                defaultName: nameFromCommentOr("SSH RSA", comment: comment)
            )
        }
        // Should not happen with the current AgePonyCore SSH support, but
        // hedge in case future key types are added.
        throw RecipientImportError.unrecognizedFormat
    }

    // MARK: - GitHub

    /// Fetch `https://github.com/<username>.keys` and return every parsable
    /// recipient. The crypto-core's `SSHKeySource.github` does the network
    /// + parsing in one call.
    public static func fetchFromGitHub(username rawUsername: String) async throws -> [RecipientImportCandidate] {
        let username = rawUsername.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty, username.allSatisfy({ isValidUsernameChar($0) }) else {
            throw RecipientImportError.invalidUsername
        }
        let recipients: [any AgeRecipient]
        do {
            recipients = try await SSHKeySource.github(username: username)
        } catch let e as SSHKeySourceError {
            switch e {
            case .invalidURL:           throw RecipientImportError.invalidUsername
            case .fetchFailed(let s):   throw RecipientImportError.fetchFailed("HTTP \(s)")
            case .noUsableKeys:         throw RecipientImportError.noUsableKeysInResponse
            }
        } catch {
            throw RecipientImportError.fetchFailed(error.localizedDescription)
        }

        if recipients.isEmpty {
            throw RecipientImportError.noUsableKeysInResponse
        }

        // Build candidates. GitHub doesn't tell us comments for the keys
        // (they're stripped from the `.keys` endpoint), so we synthesize
        // names from the username.
        var candidates: [RecipientImportCandidate] = []
        for (i, recipient) in recipients.enumerated() {
            if let ed = recipient as? SSHEd25519Recipient {
                candidates.append(RecipientImportCandidate(
                    type: .sshEd25519,
                    publicKeyMaterial: ed.wireBlob,
                    sshComment: "from github.com/\(username)",
                    defaultName: recipients.count > 1
                        ? "\(username) (ed25519 #\(i + 1))"
                        : username
                ))
            } else if let rsa = recipient as? SSHRSARecipient {
                candidates.append(RecipientImportCandidate(
                    type: .sshRSA,
                    publicKeyMaterial: rsa.wireBlob,
                    sshComment: "from github.com/\(username)",
                    defaultName: recipients.count > 1
                        ? "\(username) (rsa #\(i + 1))"
                        : username
                ))
            }
        }
        if candidates.isEmpty {
            throw RecipientImportError.noUsableKeysInResponse
        }
        return candidates
    }

    // MARK: - Helpers

    private static func shortenedAgeName(_ s: String) -> String {
        let head = s.prefix(10)
        let tail = s.suffix(4)
        return "\(head)…\(tail)"
    }

    private static func nameFromCommentOr(_ fallback: String, comment: String?) -> String {
        if let c = comment?.trimmingCharacters(in: .whitespaces), !c.isEmpty {
            return c
        }
        return fallback
    }

    private static func isValidUsernameChar(_ c: Character) -> Bool {
        c.isLetter || c.isNumber || c == "-" || c == "_"
    }

    // MARK: - Source mapping

    /// Map the UI's source choice to the StoredRecipientSource used by the
    /// vault. Kept here so the persistence layer doesn't have to know
    /// about UI affordances.
    public static func storedSource(forUIChoice ui: UIImportSource) -> StoredRecipientSource {
        switch ui {
        case .paste:  return .pasteAge      // refined per-candidate by the caller
        case .qr:     return .qrScan
        case .github: return .github
        }
    }

    public enum UIImportSource: String, CaseIterable, Identifiable {
        case paste
        case qr
        case github
        public var id: String { rawValue }
    }
}
