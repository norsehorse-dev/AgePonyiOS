//
//  SSHSig.swift
//  AgePonyCore
//
//  SSHSIG signature format (OpenSSH PROTOCOL.sshsig). This is the format
//  produced by `ssh-keygen -Y sign` and checked by `ssh-keygen -Y verify`,
//  and the one git uses for SSH-key commit signing.
//
//  age itself has no signature primitive, so AgePony's detached signing
//  rides on SSHSIG, reusing the SSH Ed25519/RSA identities the vault already
//  holds. This file is the pure format layer: it builds the signed-data
//  blob, serializes/parses the wrapped signature blob, and does the PEM
//  armor. Signing lives in SSHSigner; verification in SSHSigVerifier.
//
//  Wire layout (confirmed byte-for-byte against ssh-keygen 9.x):
//
//  Signed data (the bytes the signature is actually computed over):
//      "SSHSIG"                 // 6 raw bytes, NOT length-prefixed
//      string  namespace
//      string  reserved         // empty
//      string  hash_algorithm   // "sha256" or "sha512"
//      string  H(message)       // message hashed with hash_algorithm
//
//  Wrapped blob (what gets base64-armored into the .sig file):
//      "SSHSIG"                 // 6 raw bytes
//      uint32  version = 1
//      string  publickey        // signer pubkey, SSH wire format
//      string  namespace
//      string  reserved         // empty
//      string  hash_algorithm
//      string  signature        // inner SSH signature wire format
//
//  Inner SSH signature wire format:
//      ed25519:       string("ssh-ed25519")  || string(raw 64-byte sig)
//      rsa-sha2-512:  string("rsa-sha2-512") || string(sig)        [D0]
//      ecdsa-p256:    string("ecdsa-sha2-nistp256") || string(...)  [E0]
//
//  Armor: "-----BEGIN SSH SIGNATURE-----" / "-----END SSH SIGNATURE-----",
//  base64 body wrapped at 70 columns, LF-terminated (matches ssh-keygen).
//

import Foundation
import CryptoKit

// MARK: - Errors

public enum SSHSigError: Error, Equatable {
    case missingBeginMarker
    case missingEndMarker
    case invalidBase64
    case extraDataOutsideArmor
    case badMagic
    case unsupportedVersion(UInt32)
    case malformedBlob
    case unsupportedKeyType(String)
    case unsupportedHashAlgorithm(String)
    case malformedPublicKey
    case malformedInnerSignature
    case namespaceMismatch(expected: String, found: String)
    case signatureInvalid
    case signingFailed(String)
}

// MARK: - Hash algorithm

/// The hash applied to the message before it goes into the signed-data blob.
/// ssh-keygen defaults to sha512; AgePony follows that default.
public enum SSHSigHash: String, Equatable, Sendable {
    case sha256
    case sha512

    public func digest(_ message: Data) -> Data {
        switch self {
        case .sha256: return Data(SHA256.hash(data: message))
        case .sha512: return Data(SHA512.hash(data: message))
        }
    }
}

// MARK: - SSHSig format

public enum SSHSig {

    // MARK: Constants

    /// 6-byte raw magic preamble. Present in both the signed data and the
    /// wrapped blob, un-length-prefixed.
    public static let magic = Data("SSHSIG".utf8)

    /// Wrapped-blob version.
    public static let version: UInt32 = 1

    /// AgePony's branded namespace. Verifiers (and `ssh-keygen -Y verify -n`)
    /// must pass the matching namespace, so a signature made for AgePony is
    /// scoped to AgePony's use and won't be mistaken for, say, a git signature.
    public static let defaultNamespace = "agepony"

    public static let armorBegin = "-----BEGIN SSH SIGNATURE-----"
    public static let armorEnd   = "-----END SSH SIGNATURE-----"
    public static let armorLineWidth = 70

    // MARK: Parsed blob

    /// A parsed (unwrapped) SSHSIG blob.
    public struct Blob: Equatable {
        /// Signer public key in SSH wire format
        /// (e.g. `string("ssh-ed25519") || string(pub)`).
        public let publicKeyWire: Data
        public let namespace: String
        public let hash: SSHSigHash
        /// Inner SSH signature wire format.
        public let signature: Data

        public init(publicKeyWire: Data, namespace: String, hash: SSHSigHash, signature: Data) {
            self.publicKeyWire = publicKeyWire
            self.namespace = namespace
            self.hash = hash
            self.signature = signature
        }
    }

    // MARK: Signed data

    /// Build the exact bytes a signature is computed over.
    public static func signedData(message: Data, namespace: String, hash: SSHSigHash) -> Data {
        var out = Data()
        out.append(magic)                       // raw 6 bytes
        var w = SSHWireWriter()
        w.writeString(namespace)
        w.writeString(Data())                   // reserved, empty
        w.writeString(hash.rawValue)
        w.writeString(hash.digest(message))     // H(message)
        out.append(w.data)
        return out
    }

    // MARK: Blob serialize / parse

    /// Serialize a wrapped blob (before armoring).
    public static func serialize(blob: Blob) -> Data {
        var out = Data()
        out.append(magic)                       // raw 6 bytes
        var w = SSHWireWriter()
        w.writeUInt32(version)
        w.writeString(blob.publicKeyWire)
        w.writeString(blob.namespace)
        w.writeString(Data())                   // reserved, empty
        w.writeString(blob.hash.rawValue)
        w.writeString(blob.signature)
        out.append(w.data)
        return out
    }

    /// Parse a wrapped blob (after de-armoring).
    public static func parse(blob: Data) throws -> Blob {
        guard blob.count >= magic.count else { throw SSHSigError.malformedBlob }
        let head = blob.prefix(magic.count)
        guard head.elementsEqual(magic) else { throw SSHSigError.badMagic }

        var reader = SSHWireReader(blob.subdata(in: (blob.startIndex + magic.count)..<blob.endIndex))
        let ver: UInt32
        do { ver = try reader.readUInt32() } catch { throw SSHSigError.malformedBlob }
        guard ver == version else { throw SSHSigError.unsupportedVersion(ver) }

        let pub: Data, nsData: Data, reserved: Data, hashData: Data, sig: Data
        do {
            pub      = try reader.readString()
            nsData   = try reader.readString()
            reserved = try reader.readString()
            hashData = try reader.readString()
            sig      = try reader.readString()
        } catch {
            throw SSHSigError.malformedBlob
        }
        _ = reserved  // reserved is ignored per spec

        guard let ns = String(data: nsData, encoding: .utf8),
              let hashStr = String(data: hashData, encoding: .utf8) else {
            throw SSHSigError.malformedBlob
        }
        guard let hash = SSHSigHash(rawValue: hashStr) else {
            throw SSHSigError.unsupportedHashAlgorithm(hashStr)
        }
        return Blob(publicKeyWire: pub, namespace: ns, hash: hash, signature: sig)
    }

    // MARK: Armor

    /// Wrap a serialized blob in `-----BEGIN SSH SIGNATURE-----` armor.
    public static func armor(_ blob: Data) -> String {
        let b64 = blob.base64EncodedString()
        var out = armorBegin + "\n"
        var idx = b64.startIndex
        while idx < b64.endIndex {
            let end = b64.index(idx, offsetBy: armorLineWidth, limitedBy: b64.endIndex) ?? b64.endIndex
            out.append(String(b64[idx..<end]))
            out.append("\n")
            idx = end
        }
        out.append(armorEnd)
        out.append("\n")
        return out
    }

    /// Unwrap an armored SSH signature back to its binary blob. Tolerates
    /// CRLF/LF, leading/trailing blank lines, and any wrap width.
    public static func dearmor(_ text: String) throws -> Data {
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
                             .replacingOccurrences(of: "\r", with: "\n")
        var lines = normalized.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        while let first = lines.first, first.trimmingCharacters(in: .whitespaces).isEmpty {
            lines.removeFirst()
        }
        while let last = lines.last, last.trimmingCharacters(in: .whitespaces).isEmpty {
            lines.removeLast()
        }
        guard let beginIdx = lines.firstIndex(of: armorBegin) else {
            throw SSHSigError.missingBeginMarker
        }
        guard let endIdx = lines.firstIndex(of: armorEnd), endIdx > beginIdx else {
            throw SSHSigError.missingEndMarker
        }
        for i in 0..<beginIdx where !lines[i].trimmingCharacters(in: .whitespaces).isEmpty {
            throw SSHSigError.extraDataOutsideArmor
        }
        for i in (endIdx + 1)..<lines.count where !lines[i].trimmingCharacters(in: .whitespaces).isEmpty {
            throw SSHSigError.extraDataOutsideArmor
        }
        let b64 = lines[(beginIdx + 1)..<endIdx].joined()
        guard let data = Data(base64Encoded: b64, options: []) else {
            throw SSHSigError.invalidBase64
        }
        return data
    }

    /// Convenience: parse an armored signature straight to a `Blob`.
    public static func parseArmored(_ text: String) throws -> Blob {
        try parse(blob: try dearmor(text))
    }

    // MARK: Wire helpers

    /// SSH wire blob for an Ed25519 public key:
    /// `string("ssh-ed25519") || string(pub)`.
    public static func ed25519PublicKeyWire(_ rawPublicKey: Data) -> Data {
        var w = SSHWireWriter()
        w.writeString("ssh-ed25519")
        w.writeString(rawPublicKey)
        return w.data
    }

    /// Read the leading key-type string from an SSH public-key wire blob,
    /// without consuming the rest. Used to dispatch on algorithm.
    public static func publicKeyType(_ wire: Data) throws -> String {
        var reader = SSHWireReader(wire)
        guard let t = try? reader.readString(),
              let s = String(data: t, encoding: .utf8) else {
            throw SSHSigError.malformedPublicKey
        }
        return s
    }

    /// SSH wire blob for an RSA public key:
    /// `string("ssh-rsa") || mpint(e) || mpint(n)`.
    public static func rsaPublicKeyWire(e: Data, n: Data) -> Data {
        var w = SSHWireWriter()
        w.writeString("ssh-rsa")
        w.writeMPInt(e)
        w.writeMPInt(n)
        return w.data
    }

    /// Extract `(e, n)` from an `ssh-rsa` public-key wire blob (canonical
    /// big-endian, leading-zero-stripped). Used to rebuild a verify key.
    public static func rsaComponents(fromWire wire: Data) throws -> (e: Data, n: Data) {
        var reader = SSHWireReader(wire)
        guard let t = try? reader.readString(),
              String(data: t, encoding: .utf8) == "ssh-rsa",
              let e = try? reader.readMPInt(),
              let n = try? reader.readMPInt() else {
            throw SSHSigError.malformedPublicKey
        }
        return (e, n)
    }

    /// SSH wire blob for an ECDSA P-256 public key:
    /// `string("ecdsa-sha2-nistp256") || string("nistp256") || string(Q)`,
    /// where `Q` is the uncompressed point `0x04 || X || Y` (65 bytes), i.e.
    /// CryptoKit's `x963Representation`.
    public static func ecdsaP256PublicKeyWire(x963Q: Data) -> Data {
        var w = SSHWireWriter()
        w.writeString("ecdsa-sha2-nistp256")
        w.writeString("nistp256")
        w.writeString(x963Q)
        return w.data
    }

    /// Extract the uncompressed point `Q` (x963, `0x04 || X || Y`) from an
    /// `ecdsa-sha2-nistp256` public-key wire blob.
    public static func ecdsaP256X963(fromWire wire: Data) throws -> Data {
        var reader = SSHWireReader(wire)
        guard let t = try? reader.readString(),
              String(data: t, encoding: .utf8) == "ecdsa-sha2-nistp256",
              let c = try? reader.readString(),
              String(data: c, encoding: .utf8) == "nistp256",
              let q = try? reader.readString(),
              q.count == 65, q.first == 0x04 else {
            throw SSHSigError.malformedPublicKey
        }
        return q
    }

    // MARK: FIDO security-key (sk-*) wire helpers

    /// SSH wire blob for a FIDO `sk-ssh-ed25519@openssh.com` public key:
    /// `string(type) || string(ed25519Pub) || string(application)`.
    public static func skEd25519PublicKeyWire(rawPublicKey: Data, application: Data) -> Data {
        var w = SSHWireWriter()
        w.writeString("sk-ssh-ed25519@openssh.com")
        w.writeString(rawPublicKey)
        w.writeString(application)
        return w.data
    }

    /// Parse an `sk-ssh-ed25519@openssh.com` public-key wire blob.
    public static func skEd25519Components(fromWire wire: Data) throws -> (publicKey: Data, application: Data) {
        var r = SSHWireReader(wire)
        guard let t = try? r.readString(),
              String(data: t, encoding: .utf8) == "sk-ssh-ed25519@openssh.com",
              let pub = try? r.readString(), pub.count == 32,
              let app = try? r.readString() else {
            throw SSHSigError.malformedPublicKey
        }
        return (pub, app)
    }

    /// SSH wire blob for a FIDO `sk-ecdsa-sha2-nistp256@openssh.com` public key:
    /// `string(type) || string("nistp256") || string(Q) || string(application)`.
    public static func skEcdsaP256PublicKeyWire(x963Q: Data, application: Data) -> Data {
        var w = SSHWireWriter()
        w.writeString("sk-ecdsa-sha2-nistp256@openssh.com")
        w.writeString("nistp256")
        w.writeString(x963Q)
        w.writeString(application)
        return w.data
    }

    /// Parse an `sk-ecdsa-sha2-nistp256@openssh.com` public-key wire blob.
    public static func skEcdsaP256Components(fromWire wire: Data) throws -> (q: Data, application: Data) {
        var r = SSHWireReader(wire)
        guard let t = try? r.readString(),
              String(data: t, encoding: .utf8) == "sk-ecdsa-sha2-nistp256@openssh.com",
              let c = try? r.readString(), String(data: c, encoding: .utf8) == "nistp256",
              let q = try? r.readString(), q.count == 65, q.first == 0x04,
              let app = try? r.readString() else {
            throw SSHSigError.malformedPublicKey
        }
        return (q, app)
    }

    /// Parse a FIDO inner signature:
    /// `string(type) || string(sig) || byte(flags) || uint32(counter)`.
    public static func parseSkInnerSignature(_ inner: Data) throws -> (type: String, sig: Data, flags: UInt8, counter: UInt32) {
        var r = SSHWireReader(inner)
        guard let t = try? r.readString(),
              let type = String(data: t, encoding: .utf8),
              let sig = try? r.readString(),
              let flags = try? r.readByte(),
              let counter = try? r.readUInt32() else {
            throw SSHSigError.malformedInnerSignature
        }
        return (type, sig, flags, counter)
    }

    /// The message a FIDO authenticator actually signs:
    /// `SHA256(application) || flags || counter(BE) || SHA256(signedData)`.
    /// (authenticatorData || clientDataHash, per WebAuthn/CTAP, where
    /// clientDataHash is SHA-256 of the SSHSIG signed-data blob.)
    public static func skAuthenticatorMessage(application: Data, flags: UInt8, counter: UInt32, signedData: Data) -> Data {
        var out = Data()
        out.append(Data(SHA256.hash(data: application)))
        out.append(flags)
        var cw = SSHWireWriter()
        cw.writeUInt32(counter)
        out.append(cw.data)
        out.append(Data(SHA256.hash(data: signedData)))
        return out
    }

    /// Extract the raw 32-byte Ed25519 public key from its wire blob.
    public static func ed25519RawPublicKey(fromWire wire: Data) throws -> Data {
        var reader = SSHWireReader(wire)
        guard let t = try? reader.readString(),
              String(data: t, encoding: .utf8) == "ssh-ed25519",
              let pub = try? reader.readString(),
              pub.count == 32 else {
            throw SSHSigError.malformedPublicKey
        }
        return pub
    }

    /// Split an inner SSH signature blob into (type, raw signature bytes).
    public static func parseInnerSignature(_ inner: Data) throws -> (type: String, raw: Data) {
        var reader = SSHWireReader(inner)
        guard let t = try? reader.readString(),
              let type = String(data: t, encoding: .utf8),
              let raw = try? reader.readString() else {
            throw SSHSigError.malformedInnerSignature
        }
        return (type, raw)
    }
}
