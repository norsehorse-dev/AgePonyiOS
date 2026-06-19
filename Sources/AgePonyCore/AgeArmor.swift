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

    /// Unwrap a PEM-style armored age string back to its binary bytes.
    ///
    /// Tolerates leading/trailing whitespace, mixed line endings (CRLF/LF),
    /// and surrounding empty lines, but rejects non-whitespace content
    /// outside the markers.
    public static func decode(_ text: String) throws -> Data {
        // Normalize to LF and split into lines.
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
                             .replacingOccurrences(of: "\r", with: "\n")
        let rawLines = normalized.split(separator: "\n", omittingEmptySubsequences: false)
                                 .map(String.init)

        // Trim entirely-empty leading and trailing lines.
        var lines = rawLines
        while let first = lines.first, first.trimmingCharacters(in: .whitespaces).isEmpty {
            lines.removeFirst()
        }
        while let last = lines.last, last.trimmingCharacters(in: .whitespaces).isEmpty {
            lines.removeLast()
        }

        guard let beginIdx = lines.firstIndex(of: beginMarker) else {
            throw AgeArmorError.missingBeginMarker
        }
        guard let endIdx = lines.firstIndex(of: endMarker), endIdx > beginIdx else {
            throw AgeArmorError.missingEndMarker
        }
        // Anything before begin or after end (other than already-trimmed
        // whitespace) is treated as extraneous content.
        for i in 0..<beginIdx {
            if !lines[i].trimmingCharacters(in: .whitespaces).isEmpty {
                throw AgeArmorError.extraDataOutsideArmor
            }
        }
        for i in (endIdx + 1)..<lines.count {
            if !lines[i].trimmingCharacters(in: .whitespaces).isEmpty {
                throw AgeArmorError.extraDataOutsideArmor
            }
        }

        let bodyLines = lines[(beginIdx + 1)..<endIdx]
        let b64 = bodyLines.joined()
        guard let data = Data(base64Encoded: b64, options: []) else {
            throw AgeArmorError.invalidBase64
        }
        return data
    }

    /// Heuristic: does this text look like an armored age file?
    public static func looksArmored(_ text: String) -> Bool {
        text.contains(beginMarker)
    }
}
