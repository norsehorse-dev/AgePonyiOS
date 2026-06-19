//
//  AllowedSigners.swift
//  AgePonyCore
//
//  Parse and serialize the OpenSSH `allowed_signers` file format, the trust
//  store `ssh-keygen -Y verify -f allowed_signers` reads. AgePony's
//  trusted-signers vault collection (C2) round-trips through this so a list
//  built in the app drops straight onto a machine's command line and back.
//
//  Line format (per ssh-keygen(1), ALLOWED SIGNERS):
//
//      principals [options] keytype base64-key [comment]
//
//  where `principals` is a comma-separated list (no spaces), `options` is an
//  optional comma-separated list of restrictions (e.g.
//  namespaces="agepony", valid-after=...), and comment is free text.
//  Blank lines and lines beginning with '#' are ignored.
//

import Foundation

public struct AllowedSigner: Equatable {
    /// Comma-separated principals split out (e.g. ["alice@example.com"]).
    public let principals: [String]
    /// Raw options field, preserved verbatim if present (e.g. `namespaces="agepony"`).
    public let options: String?
    /// Key algorithm, e.g. "ssh-ed25519".
    public let keyType: String
    /// Base64 of the SSH public-key wire blob.
    public let keyBase64: String
    /// Optional trailing comment.
    public let comment: String?

    public init(
        principals: [String],
        options: String? = nil,
        keyType: String,
        keyBase64: String,
        comment: String? = nil
    ) {
        self.principals = principals
        self.options = options
        self.keyType = keyType
        self.keyBase64 = keyBase64
        self.comment = comment
    }

    /// The public key as raw SSH wire bytes, if the base64 decodes.
    public var publicKeyWire: Data? {
        Data(base64Encoded: keyBase64)
    }

    /// Does this entry authorize `principal` to sign with the key whose wire
    /// blob is `publicKeyWire`? Principal matching is exact (and case-sensitive,
    /// matching ssh-keygen's behavior for plain identities); pattern principals
    /// are not expanded here.
    public func matches(principal: String, publicKeyWire candidate: Data) -> Bool {
        guard let mine = self.publicKeyWire, mine == candidate else { return false }
        return principals.contains(principal)
    }
}

public enum AllowedSigners {

    /// Key types recognized as the start of the key field (used to tell whether
    /// the token after the principals is an options field or the key type).
    private static let knownKeyTypes: Set<String> = [
        "ssh-ed25519",
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com"
    ]

    /// Parse an allowed_signers file body. Unparseable lines are skipped.
    public static func parse(_ text: String) -> [AllowedSigner] {
        var out: [AllowedSigner] = []
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
                             .replacingOccurrences(of: "\r", with: "\n")
        for rawLine in normalized.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if let signer = parseLine(line) { out.append(signer) }
        }
        return out
    }

    /// Parse a single non-comment line.
    public static func parseLine(_ line: String) -> AllowedSigner? {
        // Tokenize on whitespace, but keep at most enough fields: the comment
        // can contain spaces, so we cap the split once we reach the comment.
        let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard parts.count >= 3 else { return nil }

        let principalsField = parts[0]
        let principals = principalsField
            .split(separator: ",", omittingEmptySubsequences: true)
            .map { String($0) }
        guard !principals.isEmpty else { return nil }

        var index = 1
        var options: String? = nil

        // The token after principals is either options or the key type.
        if !knownKeyTypes.contains(parts[index]) {
            options = parts[index]
            index += 1
        }
        guard index < parts.count else { return nil }

        let keyType = parts[index]; index += 1
        guard knownKeyTypes.contains(keyType) else { return nil }
        guard index < parts.count else { return nil }

        let keyBase64 = parts[index]; index += 1
        guard Data(base64Encoded: keyBase64) != nil else { return nil }

        let comment: String? = index < parts.count
            ? parts[index...].joined(separator: " ")
            : nil

        return AllowedSigner(
            principals: principals,
            options: options,
            keyType: keyType,
            keyBase64: keyBase64,
            comment: comment
        )
    }

    /// Serialize signers back into allowed_signers file text (LF-terminated).
    public static func serialize(_ signers: [AllowedSigner]) -> String {
        var out = ""
        for s in signers {
            var fields: [String] = [s.principals.joined(separator: ",")]
            if let opts = s.options, !opts.isEmpty { fields.append(opts) }
            fields.append(s.keyType)
            fields.append(s.keyBase64)
            if let c = s.comment, !c.isEmpty { fields.append(c) }
            out.append(fields.joined(separator: " "))
            out.append("\n")
        }
        return out
    }

    /// Build a signer entry from an SSH public-key line (`keytype base64 [comment]`)
    /// for one or more principals. Convenient for "promote recipient to signer".
    public static func makeSigner(
        principals: [String],
        sshPublicKeyLine: String,
        namespaceRestricted: Bool = false
    ) -> AllowedSigner? {
        let parts = sshPublicKeyLine
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: " ", omittingEmptySubsequences: true)
            .map(String.init)
        guard parts.count >= 2 else { return nil }
        let keyType = parts[0]
        guard knownKeyTypes.contains(keyType) else { return nil }
        let keyBase64 = parts[1]
        guard Data(base64Encoded: keyBase64) != nil else { return nil }
        let comment = parts.count >= 3 ? parts[2...].joined(separator: " ") : nil
        let options = namespaceRestricted ? "namespaces=\"\(SSHSig.defaultNamespace)\"" : nil
        return AllowedSigner(
            principals: principals,
            options: options,
            keyType: keyType,
            keyBase64: keyBase64,
            comment: comment
        )
    }
}
