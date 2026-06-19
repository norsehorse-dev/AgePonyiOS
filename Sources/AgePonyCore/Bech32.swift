//
//  Bech32.swift
//  AgePonyCore
//
//  Pure-Swift Bech32 encoder/decoder (BIP-0173).
//
//  age uses original Bech32 (constant = 1), NOT Bech32m.
//
//  age recipients are encoded as lowercase: "age1..."
//  age identities are encoded as uppercase: "AGE-SECRET-KEY-1..."
//
//  The case of the HRP passed to `encode(hrp:bytes:)` determines the
//  case of the entire returned string:
//    encode(hrp: "age",             bytes: pub)  -> "age1...."
//    encode(hrp: "AGE-SECRET-KEY-", bytes: sec)  -> "AGE-SECRET-KEY-1..."
//

import Foundation

public enum Bech32Error: Error, Equatable {
    case mixedCase
    case invalidCharacter(Character)
    case invalidChecksum
    case stringTooShort
    case stringTooLong
    case missingSeparator
    case emptyHRP
    case hrpOutOfRange
    case invalidPadding
    case invalidBitGroup
}

public enum Bech32 {
    /// The Bech32 character set.
    public static let charset: [Character] = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    /// Lookup table from character to 5-bit value.
    private static let charsetMap: [Character: UInt8] = {
        var map = [Character: UInt8]()
        for (i, c) in charset.enumerated() {
            map[c] = UInt8(i)
        }
        return map
    }()

    private static let generator: [UInt32] = [
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    ]

    // MARK: - Core polymod and HRP expansion

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ UInt32(v)
            for i in 0..<5 {
                if (top >> i) & 1 != 0 {
                    chk ^= generator[i]
                }
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(hrp.count * 2 + 1)
        for c in hrp.unicodeScalars {
            result.append(UInt8(c.value >> 5))
        }
        result.append(0)
        for c in hrp.unicodeScalars {
            result.append(UInt8(c.value & 31))
        }
        return result
    }

    private static func verifyChecksum(hrp: String, data: [UInt8]) -> Bool {
        polymod(hrpExpand(hrp) + data) == 1
    }

    private static func createChecksum(hrp: String, data: [UInt8]) -> [UInt8] {
        let values = hrpExpand(hrp) + data + [0, 0, 0, 0, 0, 0]
        let pm = polymod(values) ^ 1
        var result: [UInt8] = []
        result.reserveCapacity(6)
        for i in 0..<6 {
            result.append(UInt8((pm >> (5 * (5 - i))) & 31))
        }
        return result
    }

    // MARK: - Encode / Decode (5-bit groups)

    /// Encode an HRP and a sequence of 5-bit values into a Bech32 string.
    /// The case of `hrp` determines the case of the output.
    public static func encode(hrp: String, data: [UInt8]) -> String {
        let hrpLower = hrp.lowercased()
        let combined = data + createChecksum(hrp: hrpLower, data: data)
        var result = hrpLower
        result.append("1")
        for v in combined {
            result.append(charset[Int(v)])
        }
        // Match HRP case in the output.
        if hrp == hrp.uppercased() && hrp != hrp.lowercased() {
            return result.uppercased()
        }
        return result
    }

    /// Decode a Bech32 string into its HRP and 5-bit data values.
    public static func decode(_ string: String) throws -> (hrp: String, data: [UInt8]) {
        guard string.count >= 8 else { throw Bech32Error.stringTooShort }
        // BIP-0173 mandates a maximum string length of 90.
        guard string.count <= 90 else { throw Bech32Error.stringTooLong }
        let lower = string.lowercased()
        let upper = string.uppercased()
        guard string == lower || string == upper else {
            throw Bech32Error.mixedCase
        }
        let s = lower
        guard let sepIdx = s.lastIndex(of: "1") else {
            throw Bech32Error.missingSeparator
        }
        let hrp = String(s[..<sepIdx])
        guard !hrp.isEmpty else { throw Bech32Error.emptyHRP }
        // HRP characters must be printable ASCII in [33, 126]
        for c in hrp.unicodeScalars {
            guard c.value >= 33 && c.value <= 126 else {
                throw Bech32Error.hrpOutOfRange
            }
        }
        let dataPart = s[s.index(after: sepIdx)...]
        guard dataPart.count >= 6 else { throw Bech32Error.stringTooShort }
        var data: [UInt8] = []
        data.reserveCapacity(dataPart.count)
        for c in dataPart {
            guard let v = charsetMap[c] else {
                throw Bech32Error.invalidCharacter(c)
            }
            data.append(v)
        }
        guard verifyChecksum(hrp: hrp, data: data) else {
            throw Bech32Error.invalidChecksum
        }
        return (hrp, Array(data.dropLast(6)))
    }

    // MARK: - Bit-group conversion

    /// Convert between groups of different bit-widths.
    /// For encoding bytes (8-bit) -> 5-bit groups: `fromBits: 8, toBits: 5, pad: true`.
    /// For decoding 5-bit groups -> bytes (8-bit): `fromBits: 5, toBits: 8, pad: false`.
    public static func convertBits(
        _ data: [UInt8],
        fromBits: Int,
        toBits: Int,
        pad: Bool
    ) throws -> [UInt8] {
        var acc: Int = 0
        var bits: Int = 0
        var result: [UInt8] = []
        let maxv = (1 << toBits) - 1
        let maxAcc = (1 << (fromBits + toBits - 1)) - 1
        for value in data {
            let v = Int(value)
            if v < 0 || (v >> fromBits) != 0 {
                throw Bech32Error.invalidBitGroup
            }
            acc = ((acc << fromBits) | v) & maxAcc
            bits += fromBits
            while bits >= toBits {
                bits -= toBits
                result.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits > 0 {
                result.append(UInt8((acc << (toBits - bits)) & maxv))
            }
        } else if bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0 {
            throw Bech32Error.invalidPadding
        }
        return result
    }

    // MARK: - Convenience binary encode / decode

    /// Encode raw bytes (8-bit) into a Bech32 string with the given HRP.
    public static func encodeBytes(hrp: String, bytes: [UInt8]) -> String {
        // 8 -> 5 with padding never fails for valid byte input.
        let fiveBit = try! convertBits(bytes, fromBits: 8, toBits: 5, pad: true)
        return encode(hrp: hrp, data: fiveBit)
    }

    /// Decode a Bech32 string into HRP + raw bytes (8-bit).
    public static func decodeBytes(_ string: String) throws -> (hrp: String, bytes: [UInt8]) {
        let (hrp, fiveBit) = try decode(string)
        let bytes = try convertBits(fiveBit, fromBits: 5, toBits: 8, pad: false)
        return (hrp, bytes)
    }
}

// MARK: - age-specific helpers

public extension Bech32 {
    /// Encode an X25519 recipient public key as an `age1...` string.
    static func encodeAgeRecipient(_ publicKey: [UInt8]) -> String {
        encodeBytes(hrp: "age", bytes: publicKey)
    }

    /// Encode an X25519 identity private key as an `AGE-SECRET-KEY-1...` string.
    static func encodeAgeIdentity(_ privateKey: [UInt8]) -> String {
        encodeBytes(hrp: "AGE-SECRET-KEY-", bytes: privateKey)
    }

    /// Decode an `age1...` recipient string into the raw 32-byte X25519 public key.
    /// Verifies the HRP is `age` and the body is 32 bytes.
    static func decodeAgeRecipient(_ string: String) throws -> [UInt8] {
        let (hrp, bytes) = try decodeBytes(string)
        guard hrp == "age" else { throw Bech32Error.emptyHRP }
        guard bytes.count == 32 else { throw Bech32Error.invalidPadding }
        return bytes
    }

    /// Decode an `AGE-SECRET-KEY-1...` identity string into the raw 32-byte X25519 private key.
    /// Verifies the HRP is `AGE-SECRET-KEY-` and the body is 32 bytes.
    static func decodeAgeIdentity(_ string: String) throws -> [UInt8] {
        // decode() normalizes to lowercase HRP, so we compare lowercase.
        let (hrp, bytes) = try decodeBytes(string)
        guard hrp == "age-secret-key-" else { throw Bech32Error.emptyHRP }
        guard bytes.count == 32 else { throw Bech32Error.invalidPadding }
        return bytes
    }
}
