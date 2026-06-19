//
//  OpenSSHEd25519Export.swift
//  AgePonyCore
//
//  Generates Ed25519 keypairs and serializes them to the unencrypted OpenSSH
//  private-key PEM (`-----BEGIN OPENSSH PRIVATE KEY-----`). This is the inverse
//  of the parser in SSHKey.parseOpenSSHPrivateKey, and lets AgePony mint a
//  signing-capable SSH identity in-app (B0) and export it in a form ssh-keygen,
//  ssh-agent, and git all accept.
//
//  Byte layout (confirmed byte-for-byte against ssh-keygen 9.x):
//
//      "openssh-key-v1\0"
//      string  ciphername  = "none"
//      string  kdfname     = "none"
//      string  kdfoptions  = ""        (empty)
//      uint32  numkeys     = 1
//      string  publickey                // wire(ssh-ed25519, pub)
//      string  privatekeys:
//          uint32 checkint1             // random
//          uint32 checkint2             // == checkint1
//          string keytype = "ssh-ed25519"
//          string pub  (32)
//          string priv (64 = seed || pub)
//          string comment
//          pad bytes 1,2,3,...          // to a multiple of the 8-byte block
//
//  The exported key is unencrypted by design: it mirrors exactly what the app
//  generates and holds in the vault. Reveal/export is biometric-gated at the UI.
//

import Foundation
import CryptoKit

public enum OpenSSHEd25519ExportError: Error, Equatable {
    case invalidSeedLength
    case invalidPublicKeyLength
}

public enum OpenSSHEd25519Export {

    public static let pemBegin = "-----BEGIN OPENSSH PRIVATE KEY-----"
    public static let pemEnd   = "-----END OPENSSH PRIVATE KEY-----"
    public static let pemLineWidth = 70

    /// Block size for the "none" cipher (padding is rounded up to this).
    private static let noneBlockSize = 8

    /// Generate a fresh Ed25519 keypair.
    /// - Returns: the 32-byte private seed and the 32-byte raw public key.
    public static func generate() -> (seed: Data, publicKey: Data) {
        let key = Curve25519.Signing.PrivateKey()
        return (key.rawRepresentation, key.publicKey.rawRepresentation)
    }

    /// Serialize an Ed25519 keypair to an unencrypted OpenSSH private-key PEM.
    ///
    /// - Parameters:
    ///   - seed: 32-byte Ed25519 private seed.
    ///   - publicKey: 32-byte raw Ed25519 public key.
    ///   - comment: the key comment (e.g. "agepony" or "user@host").
    public static func privateKeyPEM(seed: Data, publicKey: Data, comment: String = "") throws -> String {
        guard seed.count == 32 else { throw OpenSSHEd25519ExportError.invalidSeedLength }
        guard publicKey.count == 32 else { throw OpenSSHEd25519ExportError.invalidPublicKeyLength }

        // Public key wire blob: string("ssh-ed25519") || string(pub).
        var pubWire = SSHWireWriter()
        pubWire.writeString("ssh-ed25519")
        pubWire.writeString(publicKey)

        // Private key section.
        let checkint = UInt32.random(in: 0...UInt32.max)
        var sec = SSHWireWriter()
        sec.writeUInt32(checkint)
        sec.writeUInt32(checkint)
        sec.writeString("ssh-ed25519")
        sec.writeString(publicKey)
        sec.writeString(seed + publicKey)   // 64-byte OpenSSH private blob
        sec.writeString(comment)
        // Pad with 1, 2, 3, ... up to the block size.
        var pad: UInt8 = 1
        while sec.data.count % noneBlockSize != 0 {
            sec.writeByte(pad)
            pad &+= 1
        }

        // Outer container.
        var body = Data()
        body.append(Data("openssh-key-v1\u{0}".utf8))  // raw magic incl. NUL
        var w = SSHWireWriter()
        w.writeString("none")          // ciphername
        w.writeString("none")          // kdfname
        w.writeString(Data())          // kdfoptions (empty)
        w.writeUInt32(1)               // numkeys
        w.writeString(pubWire.data)
        w.writeString(sec.data)
        body.append(w.data)

        return pem(body)
    }

    /// Convenience for the vault's 64-byte private material (`seed(32) || pub(32)`).
    public static func privateKeyPEM(privateMaterial: Data, comment: String = "") throws -> String {
        guard privateMaterial.count == 64 else { throw OpenSSHEd25519ExportError.invalidSeedLength }
        return try privateKeyPEM(
            seed: Data(privateMaterial.prefix(32)),
            publicKey: Data(privateMaterial.suffix(32)),
            comment: comment
        )
    }

    /// Public-key one-liner (`ssh-ed25519 BASE64 [comment]`) for a raw public key.
    public static func publicKeyLine(publicKey: Data, comment: String = "") -> String {
        let b64 = SSHSig.ed25519PublicKeyWire(publicKey).base64EncodedString()
        let trimmed = comment.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "ssh-ed25519 \(b64)" : "ssh-ed25519 \(b64) \(trimmed)"
    }

    // MARK: - PEM

    private static func pem(_ data: Data) -> String {
        let b64 = data.base64EncodedString()
        var out = pemBegin + "\n"
        var idx = b64.startIndex
        while idx < b64.endIndex {
            let end = b64.index(idx, offsetBy: pemLineWidth, limitedBy: b64.endIndex) ?? b64.endIndex
            out.append(String(b64[idx..<end]))
            out.append("\n")
            idx = end
        }
        out.append(pemEnd)
        out.append("\n")
        return out
    }
}
