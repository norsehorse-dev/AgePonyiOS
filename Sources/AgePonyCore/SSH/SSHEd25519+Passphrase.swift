import Foundation

public enum SSHEd25519PassphraseError: Error {
    case wrongKeyType(String)
    case malformedInnerBlob
    case unexpectedPublicKeyLength(Int)
    case unexpectedPrivateKeyLength(Int)
    case publicKeyMismatch
}

extension SSHEd25519Identity {
    /// Construct an ed25519 identity from a passphrase-protected (or unencrypted) OpenSSH PEM.
    /// If the PEM is unencrypted, `passphrase` is ignored.
    public init(openSSHPrivateKey pem: String, passphrase: String?) throws {
        let blobs = try OpenSSHEncryptedKey.decryptedBlobs(pem: pem, passphrase: passphrase)
        let (seed, pubKey) = try Self.parseInnerBlob(blobs.innerBlob, publicBlob: blobs.publicBlob)
        try self.init(edSeed: seed, edPublicKey: pubKey)
    }

    /// Parse the decrypted inner blob of an OpenSSH ssh-ed25519 private key.
    /// Layout: check1, check2, type="ssh-ed25519", public(32B), private(64B = seed||pub), comment, padding.
    static func parseInnerBlob(_ inner: Data, publicBlob: Data) throws -> (seed: Data, pubKey: Data) {
        var reader = SSHWireReader(inner)
        let check1 = try reader.readUInt32()
        let check2 = try reader.readUInt32()
        guard check1 == check2 else { throw SSHEd25519PassphraseError.malformedInnerBlob }

        let typeBytes = try reader.readString()
        guard String(data: typeBytes, encoding: .utf8) == "ssh-ed25519" else {
            throw SSHEd25519PassphraseError.wrongKeyType(String(data: typeBytes, encoding: .utf8) ?? "?")
        }
        let pub = try reader.readString()
        guard pub.count == 32 else {
            throw SSHEd25519PassphraseError.unexpectedPublicKeyLength(pub.count)
        }
        let priv = try reader.readString()
        guard priv.count == 64 else {
            throw SSHEd25519PassphraseError.unexpectedPrivateKeyLength(priv.count)
        }
        // private_key = seed (32B) || public (32B). Verify the embedded public matches.
        let seed = priv.prefix(32)
        let embeddedPub = priv.suffix(32)
        guard Data(embeddedPub) == pub else {
            throw SSHEd25519PassphraseError.publicKeyMismatch
        }
        // Also verify against the publicBlob's ed25519 pub field (defense in depth)
        var pubReader = SSHWireReader(publicBlob)
        _ = try pubReader.readString()  // skip "ssh-ed25519" type tag
        let pubFromBlob = try pubReader.readString()
        guard pubFromBlob == pub else {
            throw SSHEd25519PassphraseError.publicKeyMismatch
        }
        return (seed: Data(seed), pubKey: Data(pub))
    }
}
