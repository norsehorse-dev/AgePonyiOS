//
//  Ed25519Conversion.swift
//  AgePonyCore
//
//  Convert between Ed25519 (Edwards-form) and X25519 (Montgomery-form) keys.
//
//  Per RFC 7748 the two curves are birationally equivalent. The conversion
//  needed by the `ssh-ed25519` age recipient stanza is:
//
//  - Public key (Edwards y-coordinate → Montgomery u-coordinate):
//        u = (1 + y) / (1 - y)  mod p
//
//  - Private key (Ed25519 seed → X25519 scalar):
//        h = SHA-512(seed)
//        scalar = clamp(h[0..32])      // X25519 standard clamping
//

import Foundation
import CryptoKit

public enum Ed25519ConversionError: Error, Equatable {
    case invalidPublicKeyLength
    case invalidPrivateKeyLength
    case denominatorIsZero  // would happen for y = 1 (point at infinity); not reachable for valid keys
    /// The encoded y isn't below p, or no curve point has it (RFC 8032 5.1.3).
    case invalidPoint
}

public enum Ed25519Conversion {

    /// Convert a 32-byte Ed25519 public key to the equivalent 32-byte X25519
    /// public key (raw little-endian).
    public static func publicKeyToX25519(edPublicKey: Data) throws -> Data {
        guard edPublicKey.count == 32 else {
            throw Ed25519ConversionError.invalidPublicKeyLength
        }
        // Decode the y-coordinate, masking off the x-sign bit (RFC 8032 §5.1.2).
        let y = Field25519(littleEndianBytes: edPublicKey, maskHighBit: true)
        // Validate first, as Android does with Bouncy Castle's partial RFC 8032 check:
        // canonical y and a point that decompresses. Otherwise a bad key gives a
        // recipient nobody can decrypt (audit L-13).
        guard isValidPublicKey(edPublicKey) else { throw Ed25519ConversionError.invalidPoint }
        let one = Field25519.one
        let numerator = one + y     // 1 + y
        let denominator = one - y   // 1 - y
        // Denominator can only be zero if y = 1, which is the identity point;
        // not a valid Ed25519 public key in practice.
        let denomCanonical = denominator.canonical()
        if denomCanonical.limbs.allSatisfy({ $0 == 0 }) {
            throw Ed25519ConversionError.denominatorIsZero
        }
        let u = numerator * denominator.inverse()
        return u.toLittleEndianBytes()
    }

    /// d = -121665/121666 mod p, little-endian.
    static let d = Field25519(littleEndianBytes: Data([163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0,
                                                       152, 232, 121, 119, 121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82]))
    /// (p - 1) / 2, little-endian: the Legendre-symbol exponent.
    static let halfPMinusOne: [UInt8] = [246] + [UInt8](repeating: 255, count: 30) + [63]

    /// RFC 8032 decoding check without the subgroup test: y < p, and x^2 = (y^2 - 1) /
    /// (d y^2 + 1) has a root, with x = 0 only when the sign bit is clear.
    public static func isValidPublicKey(_ key: Data) -> Bool {
        guard key.count == 32 else { return false }
        let y = Field25519(littleEndianBytes: key, maskHighBit: true)
        guard y.isCanonical else { return false }
        let y2 = y.squared()
        let u = y2 - Field25519.one
        let v = d * y2 + Field25519.one
        let x2 = u * v.inverse()
        if x2 == Field25519.zero {
            // x = 0: only valid with the sign bit clear.
            return key[key.startIndex + 31] & 0x80 == 0
        }
        return x2.pow(littleEndianExponent: halfPMinusOne) == Field25519.one
    }

    /// Convert a 32-byte Ed25519 private seed to the equivalent 32-byte X25519
    /// private scalar (raw, little-endian, clamped per RFC 7748).
    public static func privateKeyToX25519(edPrivateSeed: Data) throws -> Data {
        guard edPrivateSeed.count == 32 else {
            throw Ed25519ConversionError.invalidPrivateKeyLength
        }
        let h = SHA512.hash(data: edPrivateSeed)
        var scalar = [UInt8](h.prefix(32))
        // Standard X25519 clamping
        scalar[0]  &= 248
        scalar[31] &= 127
        scalar[31] |=  64
        return Data(scalar)
    }
}
