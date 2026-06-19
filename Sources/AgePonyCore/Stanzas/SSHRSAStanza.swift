import Foundation
import Security
import CryptoKit

public enum SSHRSAStanzaError: Error {
    case keyTooSmall
    case wrapFailed(String)
    case unwrapFailed(String)
}

/// The OAEP label that filippo's age uses for ssh-rsa stanzas.
/// (Confirmed by reading `agessh/agessh.go` in the FiloSottile/age source tree.)
public let sshRSAOAEPLabel = "age-encryption.org/v1/ssh-rsa"

/// SSH RSA age recipient. Wraps the file_key with RSA-OAEP-SHA-256 using the OAEP label
/// `"age-encryption.org/v1/ssh-rsa"`. Apple's `SecKeyAlgorithm.rsaEncryptionOAEPSHA256`
/// hardcodes the empty label, so we do OAEP padding manually on top of `.rsaEncryptionRaw`.
public struct SSHRSARecipient: AgeRecipient, @unchecked Sendable {
    public let publicSecKey: SecKey
    public let wireBlob: Data
    public let blockSize: Int  // RSA modulus length in bytes

    public init(rsaPublicKey: SecKey, wireBlob: Data) throws {
        self.publicSecKey = rsaPublicKey
        self.wireBlob = wireBlob
        self.blockSize = SecKeyGetBlockSize(rsaPublicKey)
        // 2048-bit minimum (256 bytes). filippo's age enforces the same.
        guard blockSize >= 256 else { throw SSHRSAStanzaError.keyTooSmall }
    }

    public init(sshPublicKeyLine line: String) throws {
        let parts = try SSHRSAKeyParser.parsePublicKey(line)
        let key = try RSAKey.makePublic(n: parts.n, e: parts.e)
        try self.init(rsaPublicKey: key, wireBlob: parts.wireBlob)
    }

    public func wrap(fileKey: Data) throws -> Stanza {
        let label = Data(sshRSAOAEPLabel.utf8)
        let em: Data
        do {
            em = try OAEP.encode(message: fileKey, label: label, k: blockSize)
        } catch {
            throw SSHRSAStanzaError.wrapFailed("OAEP encode: \(error)")
        }
        var err: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(publicSecKey, .rsaEncryptionRaw, em as CFData, &err) as Data? else {
            let msg = (err?.takeRetainedValue()).map { (CFErrorCopyDescription($0) as String) } ?? "unknown"
            throw SSHRSAStanzaError.wrapFailed("raw encrypt: \(msg)")
        }
        let tag = Data(SHA256.hash(data: wireBlob).prefix(4))
        let tagArg = Stanza.base64NoPad(tag)
        return Stanza(type: "ssh-rsa", args: [tagArg], body: ciphertext)
    }
}

/// SSH RSA age identity. Reverses the wrap: raw RSA decrypt, then OAEP unpad with our label.
public struct SSHRSAIdentity: AgeIdentity, @unchecked Sendable {
    public let privateSecKey: SecKey
    public let publicSecKey: SecKey
    public let wireBlob: Data
    public let blockSize: Int

    public init(rsaPrivateKey: SecKey, rsaPublicKey: SecKey, wireBlob: Data) throws {
        self.privateSecKey = rsaPrivateKey
        self.publicSecKey = rsaPublicKey
        self.wireBlob = wireBlob
        self.blockSize = SecKeyGetBlockSize(rsaPrivateKey)
        guard blockSize >= 256 else { throw SSHRSAStanzaError.keyTooSmall }
    }

    public init(openSSHPrivateKey pem: String) throws {
        let parts = try SSHRSAKeyParser.parseOpenSSHPrivateKey(pem)
        let pub = try RSAKey.makePublic(n: parts.n, e: parts.e)
        let priv = try RSAKey.makePrivate(
            n: parts.n, e: parts.e, d: parts.d, p: parts.p, q: parts.q, iqmp: parts.iqmp
        )
        try self.init(rsaPrivateKey: priv, rsaPublicKey: pub, wireBlob: parts.wireBlob)
    }

    public func unwrap(stanza: Stanza) throws -> Data? {
        guard stanza.type == "ssh-rsa" else { return nil }
        guard stanza.args.count == 1 else { return nil }

        let tagBytes: Data
        do {
            tagBytes = try Stanza.base64Decode(stanza.args[0])
        } catch {
            return nil
        }
        guard tagBytes.count == 4 else { return nil }
        let expectedTag = Data(SHA256.hash(data: wireBlob).prefix(4))
        guard tagBytes == expectedTag else { return nil }

        // RSA ciphertext is always exactly blockSize bytes.
        guard stanza.body.count == blockSize else { return nil }

        var err: Unmanaged<CFError>?
        guard let em = SecKeyCreateDecryptedData(privateSecKey, .rsaEncryptionRaw, stanza.body as CFData, &err) as Data? else {
            return nil
        }
        // SecKey raw decrypt may strip leading zeros from the integer; pad back to blockSize.
        var paddedEM = em
        if paddedEM.count < blockSize {
            paddedEM = Data(repeating: 0, count: blockSize - paddedEM.count) + paddedEM
        }
        let label = Data(sshRSAOAEPLabel.utf8)
        do {
            return try OAEP.decode(encoded: paddedEM, label: label)
        } catch {
            return nil
        }
    }
}
