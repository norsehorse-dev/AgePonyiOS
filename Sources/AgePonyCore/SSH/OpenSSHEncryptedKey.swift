import Foundation

public enum OpenSSHEncryptedKeyError: Error {
    case malformedPEM
    case unsupportedCipher(String)
    case unsupportedKDF(String)
    case passphraseRequired
    case wrongPassphrase
    case malformedKDFOpts
    case checkIntsMismatch  // post-decryption sanity check failed
}

/// Decrypt passphrase-protected OpenSSH private keys. Operates at the envelope level —
/// parses `cipher`, `kdf`, `kdfopts`, runs `bcrypt_pbkdf` to derive (key, iv), AES-CTR
/// decrypts the inner blob, then synthesizes a `cipher=none` PEM containing the same
/// public + decrypted-private blobs. The existing unencrypted parsers (in
/// `SSHRSAKeyParser` and the ed25519 path) then accept that synthesized PEM as-is.
///
/// This approach means we don't have to modify or duplicate the existing key parsers.
public enum OpenSSHEncryptedKey {

    /// Synthesize a `cipher=none, kdf=none` PEM from a possibly-encrypted PEM.
    /// If the input is already unencrypted, it's returned unchanged (modulo line wrapping).
    /// If encrypted, `passphrase` is required; throws on wrong passphrase.
    public static func decryptedPEM(pem: String, passphrase: String?) throws -> String {
        let raw = try decodeOuterPEM(pem)
        let magic = Data("openssh-key-v1\0".utf8)
        guard raw.count >= magic.count, raw.prefix(magic.count) == magic else {
            throw OpenSSHEncryptedKeyError.malformedPEM
        }
        var reader = SSHWireReader(Data(raw.dropFirst(magic.count)))
        let cipher = try utf8String(reader.readString())
        let kdf    = try utf8String(reader.readString())
        let kdfopts = try reader.readString()
        let numKeys = try reader.readUInt32()
        guard numKeys == 1 else { throw OpenSSHEncryptedKeyError.malformedPEM }
        let publicBlob   = try reader.readString()
        let encryptedBlob = try reader.readString()

        // Already unencrypted? Just hand the PEM back.
        if cipher == "none" && kdf == "none" {
            return pem
        }

        // Encrypted: validate cipher and kdf, decrypt
        let (keyLen, ivLen) = try cipherKeyAndIVLength(cipher)
        guard kdf == "bcrypt" else {
            throw OpenSSHEncryptedKeyError.unsupportedKDF(kdf)
        }
        guard let passphrase = passphrase, !passphrase.isEmpty else {
            throw OpenSSHEncryptedKeyError.passphraseRequired
        }
        let (salt, rounds) = try parseKDFOpts(kdfopts)

        let derived = try BcryptPBKDF.bcryptPBKDF(
            password: Data(passphrase.utf8),
            salt: salt,
            rounds: rounds,
            keylen: keyLen + ivLen
        )
        let aesKey = derived.prefix(keyLen)
        let aesIV  = derived.subdata(in: derived.startIndex + keyLen ..< derived.startIndex + keyLen + ivLen)

        let decrypted = try AESCTR.process(
            key: Data(aesKey),
            iv: Data(aesIV),
            input: encryptedBlob
        )

        // Sanity check: the first 8 bytes of the inner blob are check1 || check2 (uint32 each).
        // If passphrase was wrong, they will not match.
        guard decrypted.count >= 8 else { throw OpenSSHEncryptedKeyError.wrongPassphrase }
        let c1 = uint32BE(decrypted, at: decrypted.startIndex)
        let c2 = uint32BE(decrypted, at: decrypted.startIndex + 4)
        guard c1 == c2 else { throw OpenSSHEncryptedKeyError.wrongPassphrase }

        // Synthesize an unencrypted PEM from (magic, "none", "none", "", 1, publicBlob, decrypted)
        return synthesizeUnencryptedPEM(publicBlob: publicBlob, innerBlob: decrypted)
    }

    /// Convenience: parse the envelope and return (innerBlob, publicBlob) directly without
    /// re-encoding to a PEM. Used by extensions that build identities from raw bytes.
    public static func decryptedBlobs(pem: String, passphrase: String?) throws -> (innerBlob: Data, publicBlob: Data) {
        let raw = try decodeOuterPEM(pem)
        let magic = Data("openssh-key-v1\0".utf8)
        guard raw.count >= magic.count, raw.prefix(magic.count) == magic else {
            throw OpenSSHEncryptedKeyError.malformedPEM
        }
        var reader = SSHWireReader(Data(raw.dropFirst(magic.count)))
        let cipher = try utf8String(reader.readString())
        let kdf    = try utf8String(reader.readString())
        let kdfopts = try reader.readString()
        let numKeys = try reader.readUInt32()
        guard numKeys == 1 else { throw OpenSSHEncryptedKeyError.malformedPEM }
        let publicBlob   = try reader.readString()
        let encryptedBlob = try reader.readString()

        if cipher == "none" && kdf == "none" {
            return (innerBlob: encryptedBlob, publicBlob: publicBlob)
        }

        let (keyLen, ivLen) = try cipherKeyAndIVLength(cipher)
        guard kdf == "bcrypt" else { throw OpenSSHEncryptedKeyError.unsupportedKDF(kdf) }
        guard let passphrase = passphrase, !passphrase.isEmpty else {
            throw OpenSSHEncryptedKeyError.passphraseRequired
        }
        let (salt, rounds) = try parseKDFOpts(kdfopts)

        let derived = try BcryptPBKDF.bcryptPBKDF(
            password: Data(passphrase.utf8),
            salt: salt,
            rounds: rounds,
            keylen: keyLen + ivLen
        )
        let aesKey = derived.prefix(keyLen)
        let aesIV  = derived.subdata(in: derived.startIndex + keyLen ..< derived.startIndex + keyLen + ivLen)
        let decrypted = try AESCTR.process(key: Data(aesKey), iv: Data(aesIV), input: encryptedBlob)

        guard decrypted.count >= 8 else { throw OpenSSHEncryptedKeyError.wrongPassphrase }
        let c1 = uint32BE(decrypted, at: decrypted.startIndex)
        let c2 = uint32BE(decrypted, at: decrypted.startIndex + 4)
        guard c1 == c2 else { throw OpenSSHEncryptedKeyError.wrongPassphrase }

        return (innerBlob: decrypted, publicBlob: publicBlob)
    }

    // MARK: - Internals

    /// Decode `-----BEGIN OPENSSH PRIVATE KEY-----` framed base64 to raw bytes.
    static func decodeOuterPEM(_ pem: String) throws -> Data {
        let normalized = pem.replacingOccurrences(of: "\r\n", with: "\n")
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: true).map { String($0) }
        guard let first = lines.first, first == "-----BEGIN OPENSSH PRIVATE KEY-----",
              let last = lines.last, last == "-----END OPENSSH PRIVATE KEY-----" else {
            throw OpenSSHEncryptedKeyError.malformedPEM
        }
        let b64 = lines.dropFirst().dropLast().joined()
        guard let raw = Data(base64Encoded: b64) else {
            throw OpenSSHEncryptedKeyError.malformedPEM
        }
        return raw
    }

    static func cipherKeyAndIVLength(_ cipher: String) throws -> (Int, Int) {
        switch cipher {
        case "aes256-ctr": return (32, 16)
        case "aes128-ctr": return (16, 16)
        default: throw OpenSSHEncryptedKeyError.unsupportedCipher(cipher)
        }
    }

    static func parseKDFOpts(_ kdfopts: Data) throws -> (salt: Data, rounds: Int) {
        var reader = SSHWireReader(kdfopts)
        let salt = try reader.readString()
        let rounds = try reader.readUInt32()
        guard !salt.isEmpty else { throw OpenSSHEncryptedKeyError.malformedKDFOpts }
        return (salt, Int(rounds))
    }

    static func utf8String(_ data: Data) throws -> String {
        guard let s = String(data: data, encoding: .utf8) else {
            throw OpenSSHEncryptedKeyError.malformedPEM
        }
        return s
    }

    static func uint32BE(_ data: Data, at index: Int) -> UInt32 {
        return (UInt32(data[index]) << 24)
             | (UInt32(data[index + 1]) << 16)
             | (UInt32(data[index + 2]) << 8)
             |  UInt32(data[index + 3])
    }

    /// Re-wrap the public + decrypted-private blobs as a valid `cipher=none` OpenSSH PEM.
    static func synthesizeUnencryptedPEM(publicBlob: Data, innerBlob: Data) -> String {
        var raw = Data("openssh-key-v1\0".utf8)
        raw.append(encodeSSHString("none"))
        raw.append(encodeSSHString("none"))
        raw.append(encodeSSHString(Data()))    // empty kdfopts
        raw.append(encodeUInt32BE(1))
        raw.append(encodeSSHString(publicBlob))
        raw.append(encodeSSHString(innerBlob))

        let b64 = raw.base64EncodedString(options: [])
        // Wrap base64 at 70 characters per line (matches the OpenSSH/Python convention).
        var wrapped = ""
        var i = b64.startIndex
        while i < b64.endIndex {
            let end = b64.index(i, offsetBy: 70, limitedBy: b64.endIndex) ?? b64.endIndex
            wrapped += b64[i..<end] + "\n"
            i = end
        }
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + wrapped + "-----END OPENSSH PRIVATE KEY-----\n"
    }

    // SSH wire-format encoding helpers (direct byte writers, no dependence on SSHWireWriter API).

    static func encodeUInt32BE(_ n: UInt32) -> Data {
        return Data([
            UInt8((n >> 24) & 0xff),
            UInt8((n >> 16) & 0xff),
            UInt8((n >>  8) & 0xff),
            UInt8( n        & 0xff),
        ])
    }

    static func encodeSSHString(_ d: Data) -> Data {
        var out = encodeUInt32BE(UInt32(d.count))
        out.append(d)
        return out
    }

    static func encodeSSHString(_ s: String) -> Data {
        return encodeSSHString(Data(s.utf8))
    }
}
