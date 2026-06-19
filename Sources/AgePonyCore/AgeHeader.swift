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

    public init(stanzas: [Stanza], mac: Data) {
        self.stanzas = stanzas
        self.mac = mac
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
}

public enum AgeHeaderConstants {
    public static let versionLine = "age-encryption.org/v1"
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

    /// Parse a header from raw bytes. Returns the parsed `AgeHeader` plus the
    /// byte offset where the payload begins (immediately after the MAC line's
    /// trailing newline).
    public static func parse(bytes: Data) throws -> (header: AgeHeader, payloadOffset: Int) {
        // Split into lines on '\n'. Carriage returns are NOT acceptable in age files.
        // We need to track byte offsets for the payloadOffset return value, so we
        // walk the bytes directly rather than using String.components.
        var lines: [String] = []
        var lineEndOffsets: [Int] = []  // index just past each '\n'
        var lineStart = 0
        for i in 0..<bytes.count {
            if bytes[i] == 0x0A {  // \n
                let lineBytes = bytes.subdata(in: lineStart..<i)
                guard let line = String(data: lineBytes, encoding: .utf8) else {
                    throw AgeHeaderError.missingVersionLine
                }
                lines.append(line)
                lineEndOffsets.append(i + 1)
                lineStart = i + 1
                // Stop reading lines once we've consumed the MAC line.
                if line.hasPrefix(AgeHeaderConstants.footer + " ") || line == AgeHeaderConstants.footer {
                    break
                }
            }
        }

        guard !lines.isEmpty else { throw AgeHeaderError.missingVersionLine }

        // Version line
        guard lines[0] == AgeHeaderConstants.versionLine else {
            if lines[0].hasPrefix("age-encryption.org/") {
                throw AgeHeaderError.unsupportedVersion(lines[0])
            }
            throw AgeHeaderError.missingVersionLine
        }

        // Parse stanzas until we encounter the "---" line.
        var index = 1
        var stanzas: [Stanza] = []
        while index < lines.count {
            if lines[index].hasPrefix(AgeHeaderConstants.footer) {
                break
            }
            do {
                let s = try Stanza.parse(lines: lines, index: &index)
                stanzas.append(s)
            } catch let e as StanzaError {
                throw AgeHeaderError.stanzaError(e)
            }
        }
        if stanzas.isEmpty {
            throw AgeHeaderError.noStanzas
        }

        // MAC line
        guard index < lines.count else { throw AgeHeaderError.missingFooter }
        let macLine = lines[index]
        guard macLine.hasPrefix(AgeHeaderConstants.footer + " ") else {
            throw AgeHeaderError.malformedMACLine
        }
        let macB64 = String(macLine.dropFirst(AgeHeaderConstants.footer.count + 1))
        let mac: Data
        do {
            mac = try Stanza.base64Decode(macB64)
        } catch {
            throw AgeHeaderError.malformedMACLine
        }
        guard mac.count == 32 else {
            throw AgeHeaderError.malformedMACLine
        }

        let payloadOffset = lineEndOffsets[index]
        return (AgeHeader(stanzas: stanzas, mac: mac), payloadOffset)
    }

    /// Verify this header's MAC using the given file key.
    public func verifyMAC(fileKey: Data) throws {
        let macInput = AgeHeader.serializeUpToFooter(stanzas: stanzas)
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
