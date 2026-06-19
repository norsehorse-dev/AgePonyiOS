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
