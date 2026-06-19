//
//  Scrypt.swift
//  AgePonyCore
//
//  Pure-Swift implementation of scrypt per RFC 7914.
//
//  Used by the age `scrypt` recipient stanza for passphrase-based encryption.
//  AgePony's locked parameters for the Notes feature: N=2^18, r=8, p=1, dkLen=32.
//
//  At N=2^18 the algorithm requires ~256 MiB of working memory and takes
//  roughly 4-8 seconds on Apple Silicon. This is intentional — it's what
//  makes brute-forcing the passphrase expensive.
//
//  PBKDF2-HMAC-SHA256 (the outer KDF) is implemented on top of
//  CryptoKit's HMAC<SHA256>.
//

import Foundation
import CryptoKit

public enum Scrypt {

    public enum ScryptError: Error, Equatable {
        /// N must be a power of two > 1.
        case invalidN
        /// r and p must be > 0; their product must satisfy r * p < 2^30.
        case invalidRP
        /// dkLen must be > 0 and <= (2^32 - 1) * 32.
        case invalidDkLen
    }

    // MARK: - Public API

    /// scrypt key derivation function (RFC 7914).
    public static func scrypt(
        password: [UInt8],
        salt: [UInt8],
        n: Int,
        r: Int,
        p: Int,
        dkLen: Int
    ) throws -> [UInt8] {
        // Parameter validation
        guard n > 1, (n & (n - 1)) == 0 else { throw ScryptError.invalidN }
        guard r > 0, p > 0 else { throw ScryptError.invalidRP }
        // r * p < 2^30
        guard r.multipliedReportingOverflow(by: p).overflow == false,
              r * p < (1 << 30) else { throw ScryptError.invalidRP }
        guard dkLen > 0 else { throw ScryptError.invalidDkLen }

        let blockSize = 128 * r

        // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
        var b = pbkdf2HmacSha256(
            password: password,
            salt: salt,
            iterations: 1,
            dkLen: p * blockSize
        )

        // Step 2: For each of p parallel chunks, run ROMix.
        for i in 0..<p {
            let start = i * blockSize
            var chunk = Array(b[start..<start + blockSize])
            roMix(&chunk, r: r, n: n, blockSize: blockSize)
            for j in 0..<blockSize {
                b[start + j] = chunk[j]
            }
        }

        // Step 3: derived_key = PBKDF2-HMAC-SHA256(password, B, 1, dkLen)
        return pbkdf2HmacSha256(
            password: password,
            salt: b,
            iterations: 1,
            dkLen: dkLen
        )
    }

    /// Data-based convenience overload.
    public static func scrypt(
        password: Data,
        salt: Data,
        n: Int,
        r: Int,
        p: Int,
        dkLen: Int
    ) throws -> Data {
        let bytes = try scrypt(
            password: Array(password),
            salt: Array(salt),
            n: n, r: r, p: p, dkLen: dkLen
        )
        return Data(bytes)
    }

    // MARK: - ROMix (the memory-hard part)

    private static func roMix(_ block: inout [UInt8], r: Int, n: Int, blockSize: Int) {
        // V is N copies of the working block — for N=2^18, r=8 this is ~256 MiB.
        var v = [UInt8](repeating: 0, count: blockSize * n)
        var x = block

        // First loop: fill V with successive BlockMix outputs.
        for i in 0..<n {
            for j in 0..<blockSize {
                v[i * blockSize + j] = x[j]
            }
            blockMix(&x, r: r, blockSize: blockSize)
        }

        // Second loop: random-access into V to mix.
        for _ in 0..<n {
            let j = integerify(x, r: r) & (n - 1)
            let vOffset = j * blockSize
            for k in 0..<blockSize {
                x[k] ^= v[vOffset + k]
            }
            blockMix(&x, r: r, blockSize: blockSize)
        }

        block = x
    }

    /// Integerify: interpret the first 4 bytes of the last 64-byte sub-block
    /// as a little-endian uint32. Sufficient for any N <= 2^30.
    @inline(__always)
    private static func integerify(_ block: [UInt8], r: Int) -> Int {
        let offset = (2 * r - 1) * 64
        return Int(block[offset])
            | (Int(block[offset + 1]) << 8)
            | (Int(block[offset + 2]) << 16)
            | (Int(block[offset + 3]) << 24)
    }

    // MARK: - BlockMix

    private static func blockMix(_ block: inout [UInt8], r: Int, blockSize: Int) {
        // X = last 64-byte sub-block of B.
        var x = [UInt8](repeating: 0, count: 64)
        let lastOffset = (2 * r - 1) * 64
        for i in 0..<64 {
            x[i] = block[lastOffset + i]
        }

        // Y holds the 2r intermediate Salsa outputs in their iteration order.
        var y = [UInt8](repeating: 0, count: blockSize)

        for i in 0..<(2 * r) {
            let offset = i * 64
            for k in 0..<64 {
                x[k] ^= block[offset + k]
            }
            salsa20_8(&x)
            for k in 0..<64 {
                y[offset + k] = x[k]
            }
        }

        // Reorder per RFC 7914: even-indexed Y blocks first, then odd-indexed.
        for i in 0..<r {
            let evenSrc = (2 * i) * 64
            let evenDst = i * 64
            let oddSrc = (2 * i + 1) * 64
            let oddDst = (r + i) * 64
            for k in 0..<64 {
                block[evenDst + k] = y[evenSrc + k]
                block[oddDst + k] = y[oddSrc + k]
            }
        }
    }

    // MARK: - Salsa20/8 core

    private static func salsa20_8(_ block: inout [UInt8]) {
        // Read as 16 uint32 little-endian words.
        var x: [UInt32] = Array(repeating: 0, count: 16)
        for i in 0..<16 {
            x[i] = UInt32(block[i * 4])
                | (UInt32(block[i * 4 + 1]) << 8)
                | (UInt32(block[i * 4 + 2]) << 16)
                | (UInt32(block[i * 4 + 3]) << 24)
        }
        let original = x

        // 8 rounds = 4 double-rounds.
        for _ in 0..<4 {
            // Column round
            x[ 4] ^= rotl(x[ 0] &+ x[12],  7)
            x[ 8] ^= rotl(x[ 4] &+ x[ 0],  9)
            x[12] ^= rotl(x[ 8] &+ x[ 4], 13)
            x[ 0] ^= rotl(x[12] &+ x[ 8], 18)
            x[ 9] ^= rotl(x[ 5] &+ x[ 1],  7)
            x[13] ^= rotl(x[ 9] &+ x[ 5],  9)
            x[ 1] ^= rotl(x[13] &+ x[ 9], 13)
            x[ 5] ^= rotl(x[ 1] &+ x[13], 18)
            x[14] ^= rotl(x[10] &+ x[ 6],  7)
            x[ 2] ^= rotl(x[14] &+ x[10],  9)
            x[ 6] ^= rotl(x[ 2] &+ x[14], 13)
            x[10] ^= rotl(x[ 6] &+ x[ 2], 18)
            x[ 3] ^= rotl(x[15] &+ x[11],  7)
            x[ 7] ^= rotl(x[ 3] &+ x[15],  9)
            x[11] ^= rotl(x[ 7] &+ x[ 3], 13)
            x[15] ^= rotl(x[11] &+ x[ 7], 18)
            // Row round
            x[ 1] ^= rotl(x[ 0] &+ x[ 3],  7)
            x[ 2] ^= rotl(x[ 1] &+ x[ 0],  9)
            x[ 3] ^= rotl(x[ 2] &+ x[ 1], 13)
            x[ 0] ^= rotl(x[ 3] &+ x[ 2], 18)
            x[ 6] ^= rotl(x[ 5] &+ x[ 4],  7)
            x[ 7] ^= rotl(x[ 6] &+ x[ 5],  9)
            x[ 4] ^= rotl(x[ 7] &+ x[ 6], 13)
            x[ 5] ^= rotl(x[ 4] &+ x[ 7], 18)
            x[11] ^= rotl(x[10] &+ x[ 9],  7)
            x[ 8] ^= rotl(x[11] &+ x[10],  9)
            x[ 9] ^= rotl(x[ 8] &+ x[11], 13)
            x[10] ^= rotl(x[ 9] &+ x[ 8], 18)
            x[12] ^= rotl(x[15] &+ x[14],  7)
            x[13] ^= rotl(x[12] &+ x[15],  9)
            x[14] ^= rotl(x[13] &+ x[12], 13)
            x[15] ^= rotl(x[14] &+ x[13], 18)
        }

        // Add original to result.
        for i in 0..<16 {
            x[i] = x[i] &+ original[i]
        }

        // Write back as little-endian bytes.
        for i in 0..<16 {
            let v = x[i]
            block[i * 4]     = UInt8(truncatingIfNeeded: v)
            block[i * 4 + 1] = UInt8(truncatingIfNeeded: v >> 8)
            block[i * 4 + 2] = UInt8(truncatingIfNeeded: v >> 16)
            block[i * 4 + 3] = UInt8(truncatingIfNeeded: v >> 24)
        }
    }

    @inline(__always)
    private static func rotl(_ v: UInt32, _ n: UInt32) -> UInt32 {
        (v << n) | (v >> (32 - n))
    }

    // MARK: - PBKDF2-HMAC-SHA256

    /// PBKDF2 with HMAC-SHA256 as the PRF.
    /// Internal but exposed for direct testing.
    static func pbkdf2HmacSha256(
        password: [UInt8],
        salt: [UInt8],
        iterations: Int,
        dkLen: Int
    ) -> [UInt8] {
        let hLen = 32  // SHA-256 output size
        let l = (dkLen + hLen - 1) / hLen
        let key = SymmetricKey(data: password)
        var output = [UInt8]()
        output.reserveCapacity(l * hLen)

        for i in 1...l {
            // INT(i) is a big-endian 4-byte counter.
            var saltedInput = salt
            saltedInput.append(UInt8((i >> 24) & 0xff))
            saltedInput.append(UInt8((i >> 16) & 0xff))
            saltedInput.append(UInt8((i >>  8) & 0xff))
            saltedInput.append(UInt8(i & 0xff))

            // U_1 = HMAC(P, S || INT(i))
            var u = Array(HMAC<SHA256>.authenticationCode(for: saltedInput, using: key))
            var t = u

            // U_j = HMAC(P, U_{j-1}) for j=2..c
            for _ in 1..<iterations {
                u = Array(HMAC<SHA256>.authenticationCode(for: u, using: key))
                for k in 0..<hLen {
                    t[k] ^= u[k]
                }
            }

            output.append(contentsOf: t)
        }

        return Array(output.prefix(dkLen))
    }
}

// MARK: - age-specific helper

public extension Scrypt {
    /// Derive a 32-byte wrap key for an age scrypt stanza per the age v1 spec.
    /// - parameters:
    ///   - passphrase: user passphrase, UTF-8 encoded internally
    ///   - stanzaSalt: 16-byte random salt from the stanza header
    ///   - workFactor: log2(N), e.g. 18 → N=262144
    static func ageWrapKey(
        passphrase: String,
        stanzaSalt: [UInt8],
        workFactor: Int
    ) throws -> [UInt8] {
        guard workFactor > 0 && workFactor <= 30 else {
            throw ScryptError.invalidN
        }
        guard stanzaSalt.count == 16 else {
            throw ScryptError.invalidRP
        }
        let label = Array("age-encryption.org/v1/scrypt".utf8)
        let salt = label + stanzaSalt
        let n = 1 << workFactor
        return try scrypt(
            password: Array(passphrase.utf8),
            salt: salt,
            n: n,
            r: 8,
            p: 1,
            dkLen: 32
        )
    }
}
