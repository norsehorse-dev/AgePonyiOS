//
//  AgeArmor.swift
//  AgePonyCore
//
//  PEM-style armored encoding for age files, used by AgePony's Text Mode.
//
//  Wrapped between markers, base64-encoded body wrapped at 64 chars per line:
//
//      -----BEGIN AGE ENCRYPTED FILE-----
//      YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpV0Q5RDFkbWhDakRtdkRz
//      ...
//      -----END AGE ENCRYPTED FILE-----
//
//  The wrapped base64 is the binary age file in its entirety (header + payload).
//

import Foundation

public enum AgeArmorError: Error, Equatable {
    case missingBeginMarker
    case missingEndMarker
    case invalidBase64
    case extraDataOutsideArmor
    /// A body line after a short one (every body line but the last is 64 columns).
    case bodyAfterShortLine
    /// A raw line longer than the streaming reader buffers (no accepted input has one).
    case lineTooLong
}

public enum AgeArmor {
    public static let beginMarker = "-----BEGIN AGE ENCRYPTED FILE-----"
    public static let endMarker = "-----END AGE ENCRYPTED FILE-----"
    public static let lineLength = 64

    /// Wrap binary age bytes in PEM-style armor. Lines are LF-terminated.
    public static func encode(_ bytes: Data) -> String {
        let b64 = bytes.base64EncodedString()
        var out = beginMarker + "\n"
        var index = b64.startIndex
        while index < b64.endIndex {
            let end = b64.index(index, offsetBy: lineLength, limitedBy: b64.endIndex) ?? b64.endIndex
            out.append(String(b64[index..<end]))
            out.append("\n")
            index = end
        }
        out.append(endMarker)
        out.append("\n")
        return out
    }

    /// Unwrap armored text back to its binary bytes.
    ///
    /// Follows Go age's armor reader (audit L-1): every body line but the last is exactly
    /// 64 columns, the last is shorter (or a full line directly followed by END), each
    /// line is strict padded base64 with zero trailing bits, CRLF is accepted, and only
    /// whitespace may come before BEGIN or after END. On top of Go it tolerates whitespace
    /// around each line, which pasted text picks up and which can't change the bytes.
    public static func decode(_ text: String) throws -> Data {
        var parser = ArmorLineParser()
        var out = Data()
        // "\r\n" is one Character in Swift, so split on it as well as "\n".
        for line in text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            try parser.line(Substring(line), into: &out)
        }
        try parser.end()
        return out
    }

    /// Heuristic: does this text look like an armored age file?
    public static func looksArmored(_ text: String) -> Bool {
        text.contains(beginMarker)
    }
}

/// The armor grammar one line at a time, shared by `AgeArmor.decode` and
/// `ArmorDecodingSource` so both accept exactly the same inputs. Mirrors
/// filippo.io/age/armor's reader and Android's `Armor.LineParser`.
struct ArmorLineParser {
    private enum State { case beforeBegin, body, needEnd, afterEnd }
    private var state = State.beforeBegin
    /// A blank line arrived after the short line: fine at end of input (it's the final
    /// newline), an error before END.
    private var blankAfterShortLine = false

    /// Bytes per full 64-column line.
    static let group = 48
    /// Longest raw line the streaming reader buffers.
    static let maxRawLine = 4096

    /// Feed one line (without its '\n'); decoded bytes are appended to `out`.
    mutating func line(_ raw: Substring, into out: inout Data) throws {
        let line = Self.trim(raw)
        switch state {
        case .beforeBegin:
            if line.isEmpty { return }
            guard line == AgeArmor.beginMarker else { throw AgeArmorError.missingBeginMarker }
            state = .body
        case .body:
            if line == AgeArmor.endMarker { state = .afterEnd; return }
            if line == AgeArmor.beginMarker { throw AgeArmorError.extraDataOutsideArmor }
            let bytes = try Self.decodeLine(line)
            out.append(bytes)
            // A short line ends the body; only END may follow it.
            if bytes.count < Self.group { state = .needEnd }
        case .needEnd:
            if line.isEmpty && !blankAfterShortLine { blankAfterShortLine = true; return }
            guard line == AgeArmor.endMarker, !blankAfterShortLine else { throw AgeArmorError.bodyAfterShortLine }
            state = .afterEnd
        case .afterEnd:
            if !line.isEmpty { throw AgeArmorError.extraDataOutsideArmor }
        }
    }

    /// End of input.
    func end() throws {
        switch state {
        case .beforeBegin: throw AgeArmorError.missingBeginMarker
        case .body, .needEnd: throw AgeArmorError.missingEndMarker
        case .afterEnd: return
        }
    }

    /// Strict padded base64 for one line, like Go's `base64.StdEncoding.Strict()`.
    static func decodeLine(_ line: String) throws -> Data {
        guard line.utf8.count <= AgeArmor.lineLength else { throw AgeArmorError.invalidBase64 }
        if line.isEmpty { return Data() }
        guard let bytes = Data(base64Encoded: line, options: []) else { throw AgeArmorError.invalidBase64 }
        if bytes.count < group && bytes.base64EncodedString() != line { throw AgeArmorError.invalidBase64 }
        return bytes
    }

    /// Kotlin's `trim()`: drop every leading and trailing character at or below U+0020,
    /// which covers spaces, tabs and the CR of a CRLF line ending.
    static func trim(_ s: Substring) -> String {
        let scalars = s.unicodeScalars
        guard let first = scalars.firstIndex(where: { $0.value > 0x20 }),
              let last = scalars.lastIndex(where: { $0.value > 0x20 }) else { return "" }
        return String(scalars[first...last])
    }
}
