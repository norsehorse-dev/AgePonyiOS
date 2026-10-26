import Foundation

public enum SSHRSAKeyParserError: Error {
    case malformedPubLine
    case wrongKeyType(String)
    case wireBlobMismatch
    case malformedPEM
    case unsupportedCipher(String)
    case unsupportedKDF(String)
    case checkIntsMismatch
    case keySizeTooSmall(Int)
    /// Exponent outside OpenSSH's range (odd, 3 <= e < 2^32) or modulus over 16384 bits.
    case unacceptableKey
}

public struct SSHRSAPublicKeyParts {
    public let e: Data
    public let n: Data
    public let wireBlob: Data
    public let comment: String
}

public struct SSHRSAPrivateKeyParts {
    public let n: Data
    public let e: Data
    public let d: Data
    public let p: Data
    public let q: Data
    public let iqmp: Data
    public let wireBlob: Data
    public let comment: String
}

/// Parser for ssh-rsa keys. Peer to the existing `SSHKey` parser, which only handles ssh-ed25519.
/// Kept as a separate type rather than extending `SSHKey.KeyType` to avoid disturbing the
/// existing ed25519 parser surface.
public enum SSHRSAKeyParser {
    /// Parse a public key line of the form `"ssh-rsa BASE64 [comment]"`.
    public static func parsePublicKey(_ line: String) throws -> SSHRSAPublicKeyParts {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2 else { throw SSHRSAKeyParserError.malformedPubLine }
        let keyType = String(parts[0])
        guard keyType == "ssh-rsa" else { throw SSHRSAKeyParserError.wrongKeyType(keyType) }
        guard let blob = Data(base64Encoded: String(parts[1])) else {
            throw SSHRSAKeyParserError.malformedPubLine
        }
        var reader = SSHWireReader(blob)
        let typeBytes = try reader.readString()
        guard String(data: typeBytes, encoding: .utf8) == "ssh-rsa" else {
            throw SSHRSAKeyParserError.wireBlobMismatch
        }
        let e = try reader.readMPInt()
        let n = try reader.readMPInt()
        let comment = parts.count >= 3 ? String(parts[2]) : ""
        let nBits = BigUInt(bigEndianBytes: n).bitWidth
        guard nBits >= 2048 else { throw SSHRSAKeyParserError.keySizeTooSmall(nBits) }
        // Same bounds as a signer (audit L-4): a huge exponent or modulus is a CPU sink.
        guard (try? SSHSigVerifier.checkRSASigner(e: e, n: n)) != nil else { throw SSHRSAKeyParserError.unacceptableKey }
        return SSHRSAPublicKeyParts(e: e, n: n, wireBlob: blob, comment: comment)
    }

    /// Parse an unencrypted OpenSSH ssh-rsa private key PEM (cipher=none, kdf=none).
    public static func parseOpenSSHPrivateKey(_ pem: String) throws -> SSHRSAPrivateKeyParts {
        let normalized = pem.replacingOccurrences(of: "\r\n", with: "\n")
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: true).map { String($0) }
        guard let first = lines.first, first == "-----BEGIN OPENSSH PRIVATE KEY-----",
              let last = lines.last, last == "-----END OPENSSH PRIVATE KEY-----" else {
            throw SSHRSAKeyParserError.malformedPEM
        }
        let b64 = lines.dropFirst().dropLast().joined()
        guard let raw = Data(base64Encoded: b64) else { throw SSHRSAKeyParserError.malformedPEM }

        let magic = Data("openssh-key-v1\0".utf8)
        guard raw.count >= magic.count, raw.prefix(magic.count) == magic else {
            throw SSHRSAKeyParserError.malformedPEM
        }
        var reader = SSHWireReader(Data(raw.dropFirst(magic.count)))

        let cipher = try reader.readString()
        guard String(data: cipher, encoding: .utf8) == "none" else {
            throw SSHRSAKeyParserError.unsupportedCipher(String(data: cipher, encoding: .utf8) ?? "?")
        }
        let kdf = try reader.readString()
        guard String(data: kdf, encoding: .utf8) == "none" else {
            throw SSHRSAKeyParserError.unsupportedKDF(String(data: kdf, encoding: .utf8) ?? "?")
        }
        _ = try reader.readString()  // kdfopts, empty for "none"
        let numKeys = try reader.readUInt32()
        guard numKeys == 1 else { throw SSHRSAKeyParserError.malformedPEM }
        let publicBlob = try reader.readString()
        let privateBlob = try reader.readString()

        // Validate the public blob type
        var pubReader = SSHWireReader(publicBlob)
        let pubType = try pubReader.readString()
        guard String(data: pubType, encoding: .utf8) == "ssh-rsa" else {
            throw SSHRSAKeyParserError.wrongKeyType(String(data: pubType, encoding: .utf8) ?? "?")
        }

        // Parse the private blob: check1 check2 type n e d iqmp p q comment [padding]
        var privReader = SSHWireReader(privateBlob)
        let check1 = try privReader.readUInt32()
        let check2 = try privReader.readUInt32()
        guard check1 == check2 else { throw SSHRSAKeyParserError.checkIntsMismatch }
        let privKeyType = try privReader.readString()
        guard String(data: privKeyType, encoding: .utf8) == "ssh-rsa" else {
            throw SSHRSAKeyParserError.wrongKeyType(String(data: privKeyType, encoding: .utf8) ?? "?")
        }
        let n = try privReader.readMPInt()
        let e = try privReader.readMPInt()
        let d = try privReader.readMPInt()
        let iqmp = try privReader.readMPInt()
        let p = try privReader.readMPInt()
        let q = try privReader.readMPInt()
        let commentRaw = try privReader.readString()
        let comment = String(data: commentRaw, encoding: .utf8) ?? ""

        let nBits = BigUInt(bigEndianBytes: n).bitWidth
        guard nBits >= 2048 else { throw SSHRSAKeyParserError.keySizeTooSmall(nBits) }

        // The outer public key must be this private key's (n, e).
        var outer = SSHWireWriter()
        outer.writeString("ssh-rsa")
        outer.writeMPInt(e)
        outer.writeMPInt(n)
        guard SSHRSAKeyParser.sameRSAPublic(publicBlob, outer.data) else {
            throw SSHRSAKeyParserError.wireBlobMismatch
        }

        return SSHRSAPrivateKeyParts(
            n: n, e: e, d: d, p: p, q: q, iqmp: iqmp,
            wireBlob: publicBlob, comment: comment
        )
    }

    /// Compare two ssh-rsa public blobs by their (e, n), ignoring mpint padding quirks.
    static func sameRSAPublic(_ a: Data, _ b: Data) -> Bool {
        guard let x = try? SSHSig.rsaComponents(fromWire: a), let y = try? SSHSig.rsaComponents(fromWire: b) else { return false }
        func strip(_ d: Data) -> Data { Data(d.drop(while: { $0 == 0 })) }
        return strip(x.e) == strip(y.e) && strip(x.n) == strip(y.n)
    }
}
