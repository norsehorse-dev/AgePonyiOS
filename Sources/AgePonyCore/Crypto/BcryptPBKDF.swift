import Foundation
import CryptoKit

/// OpenBSD's `bcrypt_pbkdf` and the inner `bcrypt_hash` function.
/// Mirrors `lib/libutil/bcrypt_pbkdf.c` from OpenBSD.
///
/// This is the KDF used by OpenSSH to derive a key+IV from a passphrase when
/// the private key PEM is encrypted (cipher != "none" in the envelope).
/// Built on top of our pure-Swift Blowfish + bcrypt-flavored key schedule.
public enum BcryptPBKDF {

    /// `bcrypt_hash` — the inner 32-byte hash used by `bcrypt_pbkdf`.
    /// Inputs are both pre-hashed with SHA-512 by the caller.
    public static func bcryptHash(sha2pass: Data, sha2salt: Data) -> Data {
        precondition(sha2pass.count == 64 && sha2salt.count == 64,
                     "bcryptHash inputs must be SHA-512 outputs (64 bytes each)")

        // The bcrypt magic plaintext (32 bytes, exactly 4 Blowfish blocks).
        let magic = Data("OxychromaticBlowfishSwatDynamite".utf8)

        // Key expansion
        var state = BlowfishState()
        Blowfish.expandState(&state, data: sha2salt, key: sha2pass)
        for _ in 0..<64 {
            Blowfish.expand0State(&state, key: sha2salt)
            Blowfish.expand0State(&state, key: sha2pass)
        }

        // Convert magic plaintext to 8 UInt32s (big-endian via streamToWord).
        var cdata = [UInt32](repeating: 0, count: 8)
        var j = 0
        for i in 0..<8 {
            cdata[i] = Blowfish.streamToWord(magic, offset: &j)
        }

        // Encrypt 64 times in ECB mode (4 blocks per call = 8 UInt32s).
        for _ in 0..<64 {
            Blowfish.encryptBlocks(state, data: &cdata, blocks: 4)
        }

        // Output: little-endian bytes from each UInt32 (matches OpenBSD's byte-swap).
        var out = Data(count: 32)
        for i in 0..<8 {
            out[4 * i + 0] = UInt8( cdata[i]        & 0xff)
            out[4 * i + 1] = UInt8((cdata[i] >>  8) & 0xff)
            out[4 * i + 2] = UInt8((cdata[i] >> 16) & 0xff)
            out[4 * i + 3] = UInt8((cdata[i] >> 24) & 0xff)
        }
        return out
    }

    public enum BcryptError: Error {
        case invalidInput
    }

    /// `bcrypt_pbkdf` — OpenBSD's password-based KDF used by OpenSSH for encrypted PEMs.
    /// Returns `keylen` bytes of derived key material.
    ///
    /// Note: rounds < 1 is rejected; `keylen` must be positive.
    public static func bcryptPBKDF(password: Data, salt: Data, rounds: Int, keylen: Int) throws -> Data {
        guard rounds >= 1, !password.isEmpty, !salt.isEmpty, keylen > 0,
              keylen <= 1024 else {  // OpenBSD limit: 32*32 = 1024
            throw BcryptError.invalidInput
        }

        let stride = (keylen + 32 - 1) / 32
        var amt = (keylen + stride - 1) / stride

        // Collapse password with SHA-512
        let sha2pass = Data(SHA512.hash(data: password))

        var key = Data(count: keylen)
        var remaining = keylen
        var count: UInt32 = 1
        var origCount = 0  // tracks bytes already placed
        _ = origCount  // silence warning; we use `keylen - remaining` instead

        var out = Data(count: 32)
        var tmpout = Data(count: 32)

        while remaining > 0 {
            // countsalt = uint32_be(count) appended to salt
            var saltedSalt = salt
            saltedSalt.append(UInt8((count >> 24) & 0xff))
            saltedSalt.append(UInt8((count >> 16) & 0xff))
            saltedSalt.append(UInt8((count >>  8) & 0xff))
            saltedSalt.append(UInt8( count        & 0xff))

            // First round: sha2salt = SHA-512(salt || countsalt)
            var sha2salt = Data(SHA512.hash(data: saltedSalt))
            tmpout = bcryptHash(sha2pass: sha2pass, sha2salt: sha2salt)
            out = tmpout

            // Subsequent rounds: salt = SHA-512(previous tmpout), XOR results
            for _ in 1..<rounds {
                sha2salt = Data(SHA512.hash(data: tmpout))
                tmpout = bcryptHash(sha2pass: sha2pass, sha2salt: sha2salt)
                for j in 0..<32 {
                    out[j] ^= tmpout[j]
                }
            }

            // pbkdf2 deviation: interleave output bytes non-linearly
            amt = min(amt, remaining)
            var i = 0
            while i < amt {
                let dest = i * stride + Int(count - 1)
                if dest >= keylen { break }
                key[dest] = out[i]
                i += 1
            }
            remaining -= i
            count += 1
        }

        return key
    }
}
