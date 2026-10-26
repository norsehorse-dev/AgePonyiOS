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

    /// Strict, canonical unpadded standard base64, as Go age's
    /// `base64.RawStdEncoding.Strict()`: no `=` padding, no whitespace, and the unused
    /// trailing bits must be zero. Anything that doesn't re-encode to the same text is
    /// refused (audit L-1), so a body line can't be altered without changing its bytes.
    internal static func base64Decode(_ s: String) throws -> Data {
        if s.isEmpty { return Data() }
        guard !s.contains("=") else { throw StanzaError.invalidBase64 }
        let needed = (4 - (s.utf8.count % 4)) % 4
        guard needed != 3,
              let data = Data(base64Encoded: s + String(repeating: "=", count: needed), options: []),
              base64NoPad(data) == s else {
            throw StanzaError.invalidBase64
        }
        return data
    }
}

// MARK: - Parser

extension Stanza {

    /// Parse a single stanza starting at `lines[index]`; advances `index` past it.
    ///
    /// Matches filippo.io/age `ReadStanza` (audit L-1): `-> ` then one or more
    /// single-space-separated arguments, each VCHAR (33...126); then body lines, each
    /// strict base64. A line of 64 columns (48 bytes) is full and the body continues; the
    /// first shorter line (possibly empty) ends it and is consumed. A body that runs into
    /// `-> `, `---` or the end without a short line is refused, as is any line over 64.
    public static func parse(lines: [String], index: inout Int) throws -> Stanza {
        guard index < lines.count else { throw StanzaError.missingArrow }
        let head = lines[index]
        guard head.hasPrefix("-> ") else { throw StanzaError.missingArrow }
        // Split on every single space, like Go's strings.Split: a doubled or trailing
        // space gives an empty argument, which is refused.
        let parts = head.dropFirst(3).split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard let type = parts.first, !type.isEmpty else { throw StanzaError.argMissingType }
        for p in parts {
            if p.isEmpty { throw StanzaError.argEmpty }
            guard p.unicodeScalars.allSatisfy({ (33...126).contains($0.value) }) else {
                throw StanzaError.argInvalidCharacter
            }
        }
        index += 1

        var body = Data()
        while true {
            guard index < lines.count else { throw StanzaError.bodyLineTooLong }
            let line = lines[index]
            guard line.utf8.count <= 64 else { throw StanzaError.bodyLineTooLong }
            let decoded: Data
            do {
                decoded = try base64Decode(line)
            } catch {
                if line.hasPrefix("->") || line.hasPrefix("---") { throw StanzaError.bodyLineTooLong }
                throw StanzaError.invalidBase64
            }
            body.append(decoded)
            index += 1
            if decoded.count < 48 { break }
        }
        return Stanza(type: type, args: Array(parts.dropFirst()), body: body)
    }
}
