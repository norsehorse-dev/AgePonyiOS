//
//  AgeHeader.swift
//  AgePonyCore
//
//  Parser and serializer for the age v1 file header.
//
//  On-the-wire layout:
//
//      age-encryption.org/v1\n
//      -> X25519 base64(ephemeral_pub)\n
//      base64(wrapped_file_key)\n
//      -> X25519 base64(ephemeral_pub)\n
//      base64(wrapped_file_key)\n
//      ---<space>base64(header_mac)\n
//      <16-byte payload nonce>
//      <chunked ChaCha20-Poly1305 payload>
//
//  The HMAC-SHA-256 of the header is computed over every byte from
//  "age-encryption.org/v1" through the trailing "---" inclusive, WITHOUT
//  the space or MAC value that follow on that final line.
//

import Foundation
import CryptoKit

public struct AgeHeader: Equatable {
    public let stanzas: [Stanza]
    /// 32-byte HMAC-SHA-256 of the header (excluding the MAC line's trailing
    /// space + base64 mac). Filled in by the serializer; parsed off the wire.
    public let mac: Data
    /// The exact header bytes the MAC covers, as read off the wire (version line through
    /// "---"). The MAC is checked over these rather than a re-serialization, so a header
    /// has exactly one accepted encoding (audit L-1). Nil for a header built in memory.
    public let macInput: Data?

    public init(stanzas: [Stanza], mac: Data, macInput: Data? = nil) {
        self.stanzas = stanzas
        self.mac = mac
        self.macInput = macInput
    }
}

public enum AgeHeaderError: Error, Equatable {
    case missingVersionLine
    case unsupportedVersion(String)
    case missingFooter
    case malformedMACLine
    case invalidMAC
    case noStanzas
    case stanzaError(StanzaError)
    /// A header byte outside US-ASCII.
    case notASCII
    /// A line between stanzas that isn't a stanza (Go age accepts none).
    case unexpectedLine
    /// No MAC line within the 1 MiB header cap (audit L-3).
    case tooLarge
}

public enum AgeHeaderConstants {
    public static let versionLine = "age-encryption.org/v1"
    /// Largest header accepted, MAC line included.
    public static let maxHeaderSize = 1 << 20
    public static let footer = "---"
    public static let macInfo = Data("header".utf8)
}

// MARK: - Serialize

extension AgeHeader {

    /// Serialize header bytes up to and including the "---" marker, but NOT
    /// including the trailing space or the MAC value. This is exactly the
    /// byte sequence over which the MAC is computed.
    public static func serializeUpToFooter(stanzas: [Stanza]) -> Data {
        var s = AgeHeaderConstants.versionLine + "\n"
        for st in stanzas {
            s.append(st.serialize())
            s.append("\n")
        }
        s.append(AgeHeaderConstants.footer)
        return Data(s.utf8)
    }

    /// Full header bytes: version + stanzas + "---" + " " + base64(mac) + "\n".
    /// Given a file key, this computes the MAC internally per the age v1 spec.
    public static func serialize(stanzas: [Stanza], fileKey: Data) -> Data {
        precondition(stanzas.count > 0, "age header requires at least one stanza")
        var bytes = serializeUpToFooter(stanzas: stanzas)
        let macKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey),
            salt: Data(),
            info: AgeHeaderConstants.macInfo,
            outputByteCount: 32
        )
        let macTag = HMAC<SHA256>.authenticationCode(for: bytes, using: macKey)
        let macData = Data(macTag)
        // Append: " " + base64NoPad(mac) + "\n"
        bytes.append(0x20)  // space
        bytes.append(contentsOf: Stanza.base64NoPad(macData).utf8)
        bytes.append(0x0A)  // newline
        return bytes
    }
}

// MARK: - Parse

extension AgeHeader {

    /// Parse a header from raw bytes. Returns the parsed `AgeHeader` plus the byte
    /// offset where the payload begins (immediately after the MAC line's newline).
    ///
    /// Strict, matching filippo.io/age `format.Parse` and Android (audit L-1): US-ASCII
    /// only, the exact version line, stanzas back to back with no stray lines (see
    /// `Stanza.parse` for body rules), and a closing line of exactly `--- ` plus 43
    /// characters of canonical unpadded base64. Anything else throws, so a header can't
    /// be re-encoded without the file key.
    public static func parse(bytes input: Data) throws -> (header: AgeHeader, payloadOffset: Int) {
        let bytes = Array(input.prefix(AgeHeaderConstants.maxHeaderSize))
        // The first "\n--- " is the MAC line: stanza lines start with "->" and body
        // lines hold only base64.
        let needle: [UInt8] = [0x0A, 0x2D, 0x2D, 0x2D, 0x20]
        var idx = -1
        if bytes.count >= needle.count {
            search: for i in 0...(bytes.count - needle.count) {
                for j in 0..<needle.count where bytes[i + j] != needle[j] { continue search }
                idx = i
                break
            }
        }
        if idx < 0 {
            if input.count >= AgeHeaderConstants.maxHeaderSize { throw AgeHeaderError.tooLarge }
            if bytes.starts(with: Array(AgeHeaderConstants.versionLine.utf8)) { throw AgeHeaderError.missingFooter }
            throw AgeHeaderError.missingVersionLine
        }

        let macInput = Array(bytes[0..<(idx + 4)])          // through "---"
        let macStart = idx + 5
        let newline = macStart + 43
        guard newline < AgeHeaderConstants.maxHeaderSize else { throw AgeHeaderError.tooLarge }
        guard newline < bytes.count else { throw AgeHeaderError.malformedMACLine }
        guard bytes[newline] == 0x0A, bytes[macStart..<newline].allSatisfy({ $0 < 0x80 }) else {
            throw AgeHeaderError.malformedMACLine
        }
        let mac: Data
        do {
            mac = try Stanza.base64Decode(String(decoding: bytes[macStart..<newline], as: UTF8.self))
        } catch {
            throw AgeHeaderError.malformedMACLine
        }
        guard mac.count == 32 else { throw AgeHeaderError.malformedMACLine }

        guard macInput.allSatisfy({ $0 < 0x80 }) else { throw AgeHeaderError.notASCII }
        let lines = String(decoding: macInput, as: UTF8.self)
            .split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.first == AgeHeaderConstants.versionLine else {
            if let first = lines.first, first.hasPrefix("age-encryption.org/") {
                throw AgeHeaderError.unsupportedVersion(first)
            }
            throw AgeHeaderError.missingVersionLine
        }

        var stanzas: [Stanza] = []
        let last = lines.count - 1      // lines[last] is the "---" before the MAC
        var index = 1
        while index < last {
            guard lines[index].hasPrefix("-> ") else { throw AgeHeaderError.unexpectedLine }
            do {
                stanzas.append(try Stanza.parse(lines: lines, index: &index))
            } catch let e as StanzaError {
                throw AgeHeaderError.stanzaError(e)
            }
            guard index <= last else { throw AgeHeaderError.stanzaError(.bodyLineTooLong) }
        }
        guard !stanzas.isEmpty else { throw AgeHeaderError.noStanzas }
        return (AgeHeader(stanzas: stanzas, mac: mac, macInput: Data(macInput)), newline + 1)
    }

    /// Verify this header's MAC using the given file key.
    public func verifyMAC(fileKey: Data) throws {
        let macInput = self.macInput ?? AgeHeader.serializeUpToFooter(stanzas: stanzas)
        let macKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey),
            salt: Data(),
            info: AgeHeaderConstants.macInfo,
            outputByteCount: 32
        )
        let valid = HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: macInput, using: macKey)
        if !valid {
            throw AgeHeaderError.invalidMAC
        }
    }
}
