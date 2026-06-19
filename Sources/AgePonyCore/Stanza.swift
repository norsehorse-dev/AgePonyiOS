//
//  Stanza.swift
//  AgePonyCore
//
//  A "stanza" in the age v1 format is a recipient block in the header:
//
//      -> TYPE ARG1 ARG2 ...
//      base64_body_line_1
//      base64_body_line_2
//      ...
//
//  Stanza body lines are raw base64 (no padding), wrapped at 64 characters.
//  Per the spec, every non-final body line is exactly 64 characters and the
//  final body line is strictly less than 64 (possibly empty). The terminating
//  "less-than-64" line is what makes the stanza body unambiguous to parse.
//

import Foundation

/// A single recipient stanza from an age v1 header.
public struct Stanza: Equatable {
    /// Stanza type, e.g. "X25519", "scrypt", "ssh-ed25519".
    public let type: String

    /// Whitespace-separated arguments after the type on the "->" line.
    /// For X25519: [base64(ephemeral_pub)]
    /// For scrypt: [base64(salt), workFactorDecimalString]
    public let args: [String]

    /// Raw body bytes after base64 decoding.
    public let body: Data

    public init(type: String, args: [String], body: Data) {
        self.type = type
        self.args = args
        self.body = body
    }
}

public enum StanzaError: Error, Equatable {
    case missingArrow
    case invalidBase64
    case bodyLineTooLong
    case argMissingType
    case argEmpty
    case argInvalidCharacter
    case trailingDataAfterStanza
}

extension Stanza {

    /// Serialize this stanza to its on-the-wire bytes (no trailing newline).
    /// The returned bytes are appended to the header followed by `\n` by the caller.
    public func serialize() -> String {
        var out = "-> " + type
        for a in args {
            out.append(" ")
            out.append(a)
        }
        out.append("\n")
        let b64 = Self.base64NoPad(body)
        let chunked = Self.wrapBase64Body(b64)
        out.append(chunked)
        return out
    }

    /// Wrap a base64 string to 64-char lines per the age v1 stanza body rules.
    /// The output ALWAYS ends with a line strictly shorter than 64 characters,
    /// which may be empty. The final line does not include a trailing newline.
    internal static func wrapBase64Body(_ b64: String) -> String {
        if b64.isEmpty {
            // Empty body still requires an empty final line (no leading newline,
            // because the caller adds the newline after the "-> ..." line and
            // appends what we return; the empty body line and its terminator are
            // both produced by the caller's own newline). For our spec-aligned
            // output we emit an empty string here, and the header serializer
            // ensures a newline ends the stanza.
            return ""
        }
        var lines: [String] = []
        var start = b64.startIndex
        while true {
            let remaining = b64.distance(from: start, to: b64.endIndex)
            if remaining < 64 {
                lines.append(String(b64[start..<b64.endIndex]))
                break
            }
            if remaining == 64 {
                // Exact multiple: emit the 64-char line then an empty terminator line.
                lines.append(String(b64[start..<b64.endIndex]))
                lines.append("")
                break
            }
            let end = b64.index(start, offsetBy: 64)
            lines.append(String(b64[start..<end]))
            start = end
        }
        return lines.joined(separator: "\n")
    }

    /// Base64-encode without padding (per age stanza body rules).
    internal static func base64NoPad(_ data: Data) -> String {
        var s = data.base64EncodedString()
        while s.hasSuffix("=") {
            s.removeLast()
        }
        return s
    }

    /// Base64-decode tolerating optional padding and rejecting whitespace/newlines.
    internal static func base64Decode(_ s: String) throws -> Data {
        // Re-pad to a multiple of 4 chars.
        let needed = (4 - (s.count % 4)) % 4
        let padded = s + String(repeating: "=", count: needed)
        // Strict decoding: do NOT accept whitespace or unknown characters.
        guard let data = Data(base64Encoded: padded, options: []) else {
            throw StanzaError.invalidBase64
        }
        return data
    }
}

// MARK: - Parser

extension Stanza {

    /// Parse a single stanza starting at `lines[index]`.
    /// Advances `index` past the stanza on success.
    ///
    /// The first line must be `-> TYPE ARG1 ARG2 ...`. Body lines follow until
    /// the first line of length < 64 (inclusive), or until a line starting with
    /// `-> ` or `---` (which belongs to the next stanza or the MAC line — that
    /// line is NOT consumed here).
    public static func parse(lines: [String], index: inout Int) throws -> Stanza {
        guard index < lines.count else {
            throw StanzaError.missingArrow
        }
        let head = lines[index]
        guard head.hasPrefix("-> ") else {
            throw StanzaError.missingArrow
        }
        index += 1

        // Split the "-> TYPE ARG1 ARG2 ..." line on single spaces.
        let after = String(head.dropFirst(3))
        let parts = after.split(separator: " ", omittingEmptySubsequences: false)
        guard let typeSub = parts.first, !typeSub.isEmpty else {
            throw StanzaError.argMissingType
        }
        let type = String(typeSub)
        let args = parts.dropFirst().map(String.init)
        // Validate args: each must be non-empty (no double-space, no trailing space)
        // and contain only printable ASCII in [33, 126].
        for a in args {
            if a.isEmpty { throw StanzaError.argEmpty }
            for c in a.unicodeScalars {
                guard c.value >= 33 && c.value <= 126 else {
                    throw StanzaError.argInvalidCharacter
                }
            }
        }

        // Read body lines until a "-> " or "---" line (or end of lines).
        // Per the age v1 spec, the stanza body terminates after the first
        // line of length strictly less than 64 (which may be empty).
        var bodyB64 = ""
        var sawTerminator = false
        while index < lines.count {
            let line = lines[index]
            if line.hasPrefix("-> ") || line.hasPrefix("---") {
                break
            }
            // Body line. Length must be ≤ 64.
            if line.count > 64 {
                throw StanzaError.bodyLineTooLong
            }
            bodyB64.append(line)
            index += 1
            if line.count < 64 {
                sawTerminator = true
                break
            }
        }
        if !sawTerminator {
            // The stanza body must always end with a short line. If we hit
            // a "-> " / "---" before seeing one, the body is malformed.
            throw StanzaError.bodyLineTooLong
        }

        let body = try base64Decode(bodyB64)
        return Stanza(type: type, args: args, body: body)
    }
}
