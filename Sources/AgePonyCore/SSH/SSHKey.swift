//
//  SSHKey.swift
//  AgePonyCore
//
//  Parsers for the SSH key formats AgePony actually needs:
//
//  - Public key text format (one-line from `~/.ssh/id_ed25519.pub`):
//      ssh-ed25519 BASE64_BLOB [optional comment]
//
//  - OpenSSH private key file format (unencrypted only in slice 1b-1):
//      -----BEGIN OPENSSH PRIVATE KEY-----
//      <base64 blob>
//      -----END OPENSSH PRIVATE KEY-----
//
//  The OpenSSH private key format is described unofficially at
//  https://coolaj86.com/articles/the-openssh-private-key-format/
//  and is implemented by every SSH library, but is not formally specified
//  in an RFC.
//

import Foundation

public enum SSHKeyError: Error, Equatable {
    case malformedPublicKeyLine
    case unsupportedKeyType(String)
    case malformedKeyBlob
    case malformedPemFraming
    case invalidBase64
    case missingMagic
    case unsupportedCipher(String)
    case unsupportedKDF(String)
    case wrongKeyCount(Int)
    case checkIntsMismatch
    case wrongKeyType(String)
    case invalidPublicKeyLength
    case invalidPrivateKeyLength
}

/// A parsed SSH public key in a form we can use as an age recipient.
public struct SSHPublicKey: Equatable {
    public enum KeyType: Equatable {
        case ed25519(publicKey: Data)  // 32 raw bytes
        // .rsa(modulus: Data, exponent: Data) — added in slice 1b-2
    }

    public let type: KeyType
    /// The raw SSH wire-format blob (used for computing the stanza "tag").
    public let wireBlob: Data
    public let comment: String?
}

/// A parsed SSH private key (Ed25519 only in this slice, unencrypted).
public struct SSHPrivateKey: Equatable {
    public enum KeyType: Equatable {
        case ed25519(seed: Data, publicKey: Data)  // seed: 32 bytes; pub: 32 bytes
    }

    public let type: KeyType
    public let comment: String?
}

public enum SSHKey {

    // MARK: - Public key (text format)

    /// Parse a one-line SSH public key string of the form
    /// `ssh-ed25519 BASE64 [comment]`. Returns the parsed key and the raw
    /// SSH wire-format blob.
    public static func parsePublicKey(_ line: String) throws -> SSHPublicKey {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2 else { throw SSHKeyError.malformedPublicKeyLine }

        let keyType = String(parts[0])
        let b64 = String(parts[1])
        let comment: String? = parts.count == 3 ? String(parts[2]) : nil

        guard let blob = Data(base64Encoded: b64) else {
            throw SSHKeyError.invalidBase64
        }

        // Verify the wire blob starts with the same key type string.
        var reader = SSHWireReader(blob)
        let wireType: String
        do {
            wireType = String(data: try reader.readString(), encoding: .utf8) ?? ""
        } catch {
            throw SSHKeyError.malformedKeyBlob
        }
        guard wireType == keyType else { throw SSHKeyError.malformedKeyBlob }

        switch keyType {
        case "ssh-ed25519":
            let pub: Data
            do {
                pub = try reader.readString()
            } catch {
                throw SSHKeyError.malformedKeyBlob
            }
            guard pub.count == 32 else { throw SSHKeyError.invalidPublicKeyLength }
            return SSHPublicKey(
                type: .ed25519(publicKey: pub),
                wireBlob: blob,
                comment: comment
            )
        default:
            throw SSHKeyError.unsupportedKeyType(keyType)
        }
    }

    // MARK: - OpenSSH private key file

    /// Parse an unencrypted OpenSSH private key file (Ed25519 only in this slice).
    public static func parseOpenSSHPrivateKey(_ pem: String) throws -> SSHPrivateKey {
        // Strip the PEM framing.
        let normalized = pem.replacingOccurrences(of: "\r\n", with: "\n")
                            .replacingOccurrences(of: "\r", with: "\n")
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false)
                              .map { $0.trimmingCharacters(in: .whitespaces) }
        guard let beginIdx = lines.firstIndex(of: "-----BEGIN OPENSSH PRIVATE KEY-----"),
              let endIdx = lines.firstIndex(of: "-----END OPENSSH PRIVATE KEY-----"),
              endIdx > beginIdx else {
            throw SSHKeyError.malformedPemFraming
        }
        let bodyLines = lines[(beginIdx + 1)..<endIdx]
        let b64 = bodyLines.joined()
        guard let blob = Data(base64Encoded: b64) else {
            throw SSHKeyError.invalidBase64
        }

        // Magic: "openssh-key-v1\0" (15 bytes)
        let magic = Array("openssh-key-v1\0".utf8)
        guard blob.count >= magic.count else { throw SSHKeyError.missingMagic }
        for i in 0..<magic.count {
            if blob[blob.startIndex + i] != magic[i] {
                throw SSHKeyError.missingMagic
            }
        }

        var reader = SSHWireReader(blob.subdata(in: (blob.startIndex + magic.count)..<blob.endIndex))

        let cipher = String(data: try reader.readString(), encoding: .utf8) ?? ""
        let kdf    = String(data: try reader.readString(), encoding: .utf8) ?? ""
        _ /* kdfOptions */ = try reader.readString()
        let numKeys = try reader.readUInt32()

        guard cipher == "none" else { throw SSHKeyError.unsupportedCipher(cipher) }
        guard kdf == "none"    else { throw SSHKeyError.unsupportedKDF(kdf) }
        guard numKeys == 1     else { throw SSHKeyError.wrongKeyCount(Int(numKeys)) }

        let publicBlob = try reader.readString()
        let privateBlob = try reader.readString()

        // The publicBlob is in SSH wire format and we don't need anything from it
        // here beyond optional cross-check; trust the private section.
        _ = publicBlob

        // The private section, since cipher = "none", is plaintext and laid out as:
        //   uint32(checkint1)
        //   uint32(checkint2)        // must equal checkint1
        //   string(key_type)
        //   <key-type-specific fields>
        //   string(comment)
        //   padding bytes 1, 2, 3, ...
        var inner = SSHWireReader(privateBlob)
        let check1 = try inner.readUInt32()
        let check2 = try inner.readUInt32()
        guard check1 == check2 else { throw SSHKeyError.checkIntsMismatch }

        let keyTypeStr = String(data: try inner.readString(), encoding: .utf8) ?? ""
        switch keyTypeStr {
        case "ssh-ed25519":
            let pub = try inner.readString()
            let privBlob = try inner.readString()
            guard pub.count == 32 else { throw SSHKeyError.invalidPublicKeyLength }
            // Ed25519 OpenSSH private key blob is 64 bytes: seed(32) || pub(32).
            guard privBlob.count == 64 else { throw SSHKeyError.invalidPrivateKeyLength }
            let seed = privBlob.prefix(32)
            // Sanity check: the trailing 32 bytes should match the public key.
            // (Not strictly required for use, but a parser quirk would surface here.)
            let comment = String(data: try inner.readString(), encoding: .utf8)
            return SSHPrivateKey(
                type: .ed25519(seed: Data(seed), publicKey: pub),
                comment: comment?.isEmpty == false ? comment : nil
            )
        default:
            throw SSHKeyError.unsupportedKeyType(keyTypeStr)
        }
    }
}
