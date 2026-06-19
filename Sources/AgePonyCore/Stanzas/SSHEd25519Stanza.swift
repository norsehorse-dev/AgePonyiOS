//
//  SSHEd25519Stanza.swift
//  AgePonyCore
//
//  `ssh-ed25519` recipient stanza per age v1.
//
//  Stanza layout:
//      -> ssh-ed25519 base64(tag) base64(ephemeral_X25519_share)
//      base64(wrapped_file_key)
//
//  where:
//    tag = first 4 bytes of SHA-256(ssh_wire_format_blob_of_recipient)
//          (the wire blob is `string("ssh-ed25519") || string(pubkey_32_bytes)`)
//    ephemeral_X25519_share = a fresh ephemeral X25519 public key
//    wrap_key = HKDF-SHA-256(
//        ikm  = X25519(ephemeral_priv, converted_recipient_X25519_pub),
//        salt = ephemeral_share || converted_recipient_X25519_pub,
//        info = "age-encryption.org/v1/ssh-ed25519",
//        L = 32)
//    wrapped = ChaCha20-Poly1305(file_key, wrap_key, zero_nonce, empty_aad)
//
//  "converted X25519 pub" means the Edwards-to-Montgomery conversion of the
//  recipient's Ed25519 SSH public key, computed via `Ed25519Conversion`.
//

import Foundation
import CryptoKit

public enum SSHEd25519Error: Error, Equatable {
    case invalidEdPublicKey
    case invalidEdPrivateKey
    case conversionFailed
}

/// Compute the 4-byte stanza tag for an SSH Ed25519 public key.
internal func sshEd25519Tag(wireBlob: Data) -> Data {
    let h = SHA256.hash(data: wireBlob)
    return Data(h.prefix(4))
}

/// Build the SSH wire-format blob for an Ed25519 public key:
///   string("ssh-ed25519") || string(pubkey)
internal func sshEd25519WireBlob(publicKey: Data) -> Data {
    var w = SSHWireWriter()
    w.writeString("ssh-ed25519")
    w.writeString(publicKey)
    return w.data
}

// MARK: - Recipient

public struct SSHEd25519Recipient: AgeRecipient {
    public let edPublicKey: Data  // 32 bytes
    /// SSH wire-format blob for this key (used to compute the stanza tag).
    public let wireBlob: Data
    /// X25519 (Montgomery) form of the recipient's public key.
    public let x25519Pub: Data

    public init(edPublicKey: Data) throws {
        guard edPublicKey.count == 32 else {
            throw SSHEd25519Error.invalidEdPublicKey
        }
        self.edPublicKey = edPublicKey
        self.wireBlob = sshEd25519WireBlob(publicKey: edPublicKey)
        self.x25519Pub = try Ed25519Conversion.publicKeyToX25519(edPublicKey: edPublicKey)
    }

    /// Convenience: parse from a one-line `ssh-ed25519 BASE64 [comment]` string.
    public init(sshPublicKeyLine: String) throws {
        let parsed = try SSHKey.parsePublicKey(sshPublicKeyLine)
        guard case .ed25519(let pub) = parsed.type else {
            throw SSHKeyError.unsupportedKeyType("(non-ed25519)")
        }
        try self.init(edPublicKey: pub)
    }

    public func wrap(fileKey: Data) throws -> Stanza {
        let ephemeralPriv = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPub = ephemeralPriv.publicKey.rawRepresentation

        let theirPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: x25519Pub)
        let shared = try ephemeralPriv.sharedSecretFromKeyAgreement(with: theirPub)

        // filippo age tweak: HKDF empty-IKM with wireBlob salt, then second X25519
        let label = Data("age-encryption.org/v1/ssh-ed25519".utf8)
        let tweakKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data()),
            salt: wireBlob,
            info: label,
            outputByteCount: 32
        )
        let tweakBytes = tweakKey.withUnsafeBytes { Data($0) }
        let tweakScalar = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: tweakBytes)
        let sharedBytes = shared.withUnsafeBytes { Data($0) }
        let sharedAsPoint = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: sharedBytes)
        let tweakedShared = try tweakScalar.sharedSecretFromKeyAgreement(with: sharedAsPoint)

        let salt = ephemeralPub + x25519Pub
        let wrapKey = tweakedShared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: label,
            outputByteCount: 32
        )

        let zeroNonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
        let sealed = try ChaChaPoly.seal(fileKey, using: wrapKey, nonce: zeroNonce, authenticating: Data())
        let wrapped = sealed.ciphertext + sealed.tag  // 16 + 16 = 32 bytes

        let tagArg = Stanza.base64NoPad(sshEd25519Tag(wireBlob: wireBlob))
        let ephArg = Stanza.base64NoPad(ephemeralPub)
        return Stanza(type: "ssh-ed25519", args: [tagArg, ephArg], body: Data(wrapped))
    }
}

// MARK: - Identity

public struct SSHEd25519Identity: AgeIdentity {
    public let edSeed: Data       // 32-byte Ed25519 seed
    public let edPublicKey: Data  // 32-byte Ed25519 public key

    /// SSH wire-format blob for the public key (used to compute the tag).
    public let wireBlob: Data
    /// X25519 form of the private scalar, derived via SHA-512(seed)[0..32] + clamp.
    public let x25519Priv: Data
    /// X25519 form of the public key (Edwards→Montgomery).
    public let x25519Pub: Data

    public init(edSeed: Data, edPublicKey: Data) throws {
        guard edSeed.count == 32 else { throw SSHEd25519Error.invalidEdPrivateKey }
        guard edPublicKey.count == 32 else { throw SSHEd25519Error.invalidEdPublicKey }
        self.edSeed = edSeed
        self.edPublicKey = edPublicKey
        self.wireBlob = sshEd25519WireBlob(publicKey: edPublicKey)
        self.x25519Priv = try Ed25519Conversion.privateKeyToX25519(edPrivateSeed: edSeed)
        self.x25519Pub = try Ed25519Conversion.publicKeyToX25519(edPublicKey: edPublicKey)
    }

    /// Convenience: parse an unencrypted OpenSSH private key PEM string.
    public init(openSSHPrivateKey pem: String) throws {
        let parsed = try SSHKey.parseOpenSSHPrivateKey(pem)
        guard case .ed25519(let seed, let pub) = parsed.type else {
            throw SSHKeyError.unsupportedKeyType("(non-ed25519)")
        }
        try self.init(edSeed: seed, edPublicKey: pub)
    }

    public func unwrap(stanza: Stanza) throws -> Data? {
        guard stanza.type == "ssh-ed25519" else { return nil }
        guard stanza.args.count == 2 else { return nil }

        let tag: Data
        let ephemeralPub: Data
        do {
            tag = try Stanza.base64Decode(stanza.args[0])
            ephemeralPub = try Stanza.base64Decode(stanza.args[1])
        } catch {
            return nil
        }
        guard tag.count == 4 else { return nil }
        guard ephemeralPub.count == 32 else { return nil }

        // Reject if this stanza isn't tagged for our key.
        let ourTag = sshEd25519Tag(wireBlob: wireBlob)
        guard tag == ourTag else { return nil }

        // Key agreement on the X25519 forms.
        let ourPriv: Curve25519.KeyAgreement.PrivateKey
        let theirPub: Curve25519.KeyAgreement.PublicKey
        let shared: SharedSecret
        let tweakedShared: SharedSecret
        let label = Data("age-encryption.org/v1/ssh-ed25519".utf8)
        do {
            ourPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519Priv)
            theirPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPub)
            shared = try ourPriv.sharedSecretFromKeyAgreement(with: theirPub)
            let tweakKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: Data()),
                salt: wireBlob,
                info: label,
                outputByteCount: 32
            )
            let tweakBytes = tweakKey.withUnsafeBytes { Data($0) }
            let tweakScalar = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: tweakBytes)
            let sharedBytes = shared.withUnsafeBytes { Data($0) }
            let sharedAsPoint = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: sharedBytes)
            tweakedShared = try tweakScalar.sharedSecretFromKeyAgreement(with: sharedAsPoint)
        } catch {
            return nil
        }

        let salt = ephemeralPub + x25519Pub
        let wrapKey = tweakedShared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: label,
            outputByteCount: 32
        )

        guard stanza.body.count == 32 else { return nil }
        let ciphertext = stanza.body.prefix(16)
        let tagBytes = stanza.body.suffix(16)
        let zeroNonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))

        let sealed: ChaChaPoly.SealedBox
        do {
            sealed = try ChaChaPoly.SealedBox(nonce: zeroNonce, ciphertext: ciphertext, tag: tagBytes)
        } catch {
            return nil
        }
        do {
            return try ChaChaPoly.open(sealed, using: wrapKey, authenticating: Data())
        } catch {
            // Tag matched but auth failed — corrupt or tampered file.
            return nil
        }
    }
}
