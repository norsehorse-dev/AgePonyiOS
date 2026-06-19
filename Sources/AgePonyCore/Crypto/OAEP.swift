import Foundation
import CryptoKit

public enum OAEPError: Error {
    case messageTooLong
    case decodingError
    case keyTooSmall
}

/// RFC 8017 §7.1 — RSAES-OAEP encoding/decoding with SHA-256 and MGF1-SHA-256.
/// Supports a non-empty `label` (which is what filippo's age uses for ssh-rsa — Apple's
/// `SecKeyAlgorithm.rsaEncryptionOAEPSHA256` hardcodes an empty label, so we do the
/// padding manually and feed the encoded message into `.rsaEncryptionRaw`).
public enum OAEP {
    public static let hLen = 32  // SHA-256 output length

    /// MGF1 mask generation function with SHA-256 (RFC 8017 §B.2.1).
    public static func mgf1(seed: Data, length: Int) -> Data {
        var out = Data()
        var counter: UInt32 = 0
        while out.count < length {
            var input = seed
            input.append(UInt8((counter >> 24) & 0xff))
            input.append(UInt8((counter >> 16) & 0xff))
            input.append(UInt8((counter >>  8) & 0xff))
            input.append(UInt8( counter        & 0xff))
            let h = SHA256.hash(data: input)
            out.append(contentsOf: h)
            counter += 1
        }
        return out.prefix(length)
    }

    /// RFC 8017 §7.1.1 — OAEP encode.
    /// - parameter message: plaintext to encrypt
    /// - parameter label: OAEP label (`"age-encryption.org/v1/ssh-rsa"` for our use case)
    /// - parameter k: RSA modulus length in bytes (256 for 2048-bit RSA)
    /// - parameter seed: optional fixed 32-byte seed for deterministic tests; otherwise random
    /// - returns: encoded message `EM` of length `k`
    public static func encode(message: Data, label: Data, k: Int, seed: Data? = nil) throws -> Data {
        let mLen = message.count
        guard k >= 2 * hLen + 2 else { throw OAEPError.keyTooSmall }
        guard mLen <= k - 2 * hLen - 2 else { throw OAEPError.messageTooLong }

        let lHash = Data(SHA256.hash(data: label))
        let psLen = k - mLen - 2 * hLen - 2
        var db = Data()
        db.append(lHash)
        db.append(Data(repeating: 0, count: psLen))
        db.append(0x01)
        db.append(message)

        let actualSeed: Data
        if let s = seed {
            precondition(s.count == hLen, "seed must be \(hLen) bytes")
            actualSeed = s
        } else {
            var sb = [UInt8](repeating: 0, count: hLen)
            for i in 0..<hLen { sb[i] = UInt8.random(in: 0...255) }
            actualSeed = Data(sb)
        }

        let dbMask = mgf1(seed: actualSeed, length: k - hLen - 1)
        var maskedDB = Data(count: db.count)
        for i in 0..<db.count {
            maskedDB[i] = db[db.startIndex + i] ^ dbMask[dbMask.startIndex + i]
        }
        let seedMask = mgf1(seed: maskedDB, length: hLen)
        var maskedSeed = Data(count: hLen)
        for i in 0..<hLen {
            maskedSeed[i] = actualSeed[actualSeed.startIndex + i] ^ seedMask[seedMask.startIndex + i]
        }

        var em = Data()
        em.append(0x00)
        em.append(maskedSeed)
        em.append(maskedDB)
        return em
    }

    /// RFC 8017 §7.1.2 — OAEP decode. Throws on any malformed input.
    public static func decode(encoded: Data, label: Data) throws -> Data {
        let k = encoded.count
        guard k >= 2 * hLen + 2 else { throw OAEPError.decodingError }

        let lHash = Data(SHA256.hash(data: label))

        guard encoded[encoded.startIndex] == 0x00 else { throw OAEPError.decodingError }
        let maskedSeed = encoded.subdata(in: (encoded.startIndex + 1)..<(encoded.startIndex + 1 + hLen))
        let maskedDB = encoded.subdata(in: (encoded.startIndex + 1 + hLen)..<encoded.endIndex)

        let seedMask = mgf1(seed: maskedDB, length: hLen)
        var seed = Data(count: hLen)
        for i in 0..<hLen {
            seed[i] = maskedSeed[maskedSeed.startIndex + i] ^ seedMask[seedMask.startIndex + i]
        }

        let dbMask = mgf1(seed: seed, length: k - hLen - 1)
        var db = Data(count: maskedDB.count)
        for i in 0..<maskedDB.count {
            db[i] = maskedDB[maskedDB.startIndex + i] ^ dbMask[dbMask.startIndex + i]
        }

        let lHashPrime = Data(db.prefix(hLen))
        guard lHashPrime == lHash else { throw OAEPError.decodingError }

        var idx = hLen
        while idx < db.count, db[db.startIndex + idx] == 0x00 {
            idx += 1
        }
        guard idx < db.count, db[db.startIndex + idx] == 0x01 else { throw OAEPError.decodingError }
        return db.subdata(in: (db.startIndex + idx + 1)..<db.endIndex)
    }
}
