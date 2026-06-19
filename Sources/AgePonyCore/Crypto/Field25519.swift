//
//  Field25519.swift
//  AgePonyCore
//
//  Pure-Swift arithmetic in the prime field GF(p) where p = 2^255 - 19.
//
//  This file's sole reason to exist is the Edwards-to-Montgomery conversion
//  needed for `ssh-ed25519` age recipients: we receive an SSH Ed25519 public
//  key (an Edwards-form point), and to encrypt to it we need the equivalent
//  X25519 (Montgomery-form) public key. The conversion is the field operation
//
//      u = (1 + y) / (1 - y)   mod p
//
//  where y is the Edwards y-coordinate decoded from the SSH key bytes.
//  CryptoKit does not expose this conversion, so we implement the field
//  operations ourselves.
//
//  Representation:
//  - A field element is stored as 8 UInt32 limbs, little-endian
//    (limbs[0] holds the least-significant 32 bits).
//  - Internally an element may exceed p (up to 2^256 - 1); call `canonical()`
//    to fully reduce.
//  - All public operations return values < 2^256; `canonical()` is needed
//    before serialization or equality comparison.
//
//  Correctness is verified by:
//  - Algebraic identity tests (a * inverse(a) == 1, a - a == 0, etc.)
//  - A cross-check against CryptoKit's X25519 in Ed25519ConversionTests:
//    convert an Ed25519 keypair → use the X25519 forms for key agreement →
//    confirm both sides agree on the shared secret.
//

import Foundation

public struct Field25519: Equatable, Sendable {

    /// 8 little-endian UInt32 limbs. Internally permitted to be >= p; use
    /// `canonical()` to fully reduce before extracting bytes or comparing.
    public var limbs: [UInt32]

    /// p = 2^255 - 19, in our little-endian limb form.
    static let pLimbs: [UInt32] = [
        0xffff_ffed, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff,
        0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 0x7fff_ffff
    ]

    public static let zero = Field25519(limbs: [0, 0, 0, 0, 0, 0, 0, 0])
    public static let one  = Field25519(limbs: [1, 0, 0, 0, 0, 0, 0, 0])

    public init(limbs: [UInt32]) {
        precondition(limbs.count == 8, "Field25519 requires exactly 8 limbs")
        self.limbs = limbs
    }

    /// Parse a 32-byte little-endian value. If `maskHighBit` is true, bit 255
    /// (the high bit of byte 31) is cleared — used for Ed25519 public keys
    /// where that bit encodes the sign of x, not the value of y.
    public init(littleEndianBytes bytes: Data, maskHighBit: Bool = false) {
        precondition(bytes.count == 32, "Field25519 requires exactly 32 bytes")
        var l = [UInt32](repeating: 0, count: 8)
        for i in 0..<8 {
            let base = bytes.startIndex + i * 4
            l[i] = UInt32(bytes[base])
                | (UInt32(bytes[base + 1]) << 8)
                | (UInt32(bytes[base + 2]) << 16)
                | (UInt32(bytes[base + 3]) << 24)
        }
        if maskHighBit {
            l[7] &= 0x7fff_ffff
        }
        self.limbs = l
    }

    /// Encode as 32 bytes little-endian, fully reduced mod p.
    public func toLittleEndianBytes() -> Data {
        let r = self.canonical()
        var out = Data(count: 32)
        for i in 0..<8 {
            let v = r.limbs[i]
            out[i * 4]     = UInt8(v & 0xff)
            out[i * 4 + 1] = UInt8((v >> 8) & 0xff)
            out[i * 4 + 2] = UInt8((v >> 16) & 0xff)
            out[i * 4 + 3] = UInt8((v >> 24) & 0xff)
        }
        return out
    }

    // MARK: - Canonical reduction

    /// Returns the unique representative in [0, p). May subtract p up to once.
    public func canonical() -> Field25519 {
        var l = self.limbs
        // Attempt l - p. If no borrow propagates out of the top, l >= p and we
        // commit the subtraction. Otherwise l < p and we leave it alone.
        var temp = [UInt32](repeating: 0, count: 8)
        var borrow: Int64 = 0
        for i in 0..<8 {
            let diff = Int64(l[i]) - Int64(Self.pLimbs[i]) - borrow
            temp[i] = UInt32(truncatingIfNeeded: diff)
            borrow = (diff < 0) ? 1 : 0
        }
        if borrow == 0 {
            l = temp
        }
        return Field25519(limbs: l)
    }

    // MARK: - Add

    public static func + (a: Field25519, b: Field25519) -> Field25519 {
        var result = [UInt32](repeating: 0, count: 8)
        var carry: UInt64 = 0
        for i in 0..<8 {
            let sum = UInt64(a.limbs[i]) + UInt64(b.limbs[i]) + carry
            result[i] = UInt32(truncatingIfNeeded: sum)
            carry = sum >> 32
        }
        // If carry, value overflowed 2^256. Reduce: 2^256 ≡ 38 (mod p).
        if carry > 0 {
            var c: UInt64 = 38 * carry
            for i in 0..<8 {
                let s = UInt64(result[i]) + c
                result[i] = UInt32(truncatingIfNeeded: s)
                c = s >> 32
                if c == 0 { break }
            }
            // Secondary overflow: if every limb wrapped during the carry pass
            // we'll still have c > 0 at the end. This is reachable when both
            // operands are non-canonical (close to 2^256), so handle it.
            // c here is tiny (≤ 1 in practice).
            if c > 0 {
                var c2: UInt64 = c * 38
                for i in 0..<8 {
                    let s = UInt64(result[i]) + c2
                    result[i] = UInt32(truncatingIfNeeded: s)
                    c2 = s >> 32
                    if c2 == 0 { break }
                }
            }
        }
        return Field25519(limbs: result)
    }

    // MARK: - Subtract

    public static func - (a: Field25519, b: Field25519) -> Field25519 {
        var result = [UInt32](repeating: 0, count: 8)
        var borrow: Int64 = 0
        for i in 0..<8 {
            let diff = Int64(a.limbs[i]) - Int64(b.limbs[i]) - borrow
            result[i] = UInt32(truncatingIfNeeded: diff)
            borrow = (diff < 0) ? 1 : 0
        }
        if borrow != 0 {
            // a < b: add p to restore positivity. Because p < 2^256, the carry
            // out of this addition cancels the "missing" 2^256 from the borrow.
            var carry: UInt64 = 0
            for i in 0..<8 {
                let s = UInt64(result[i]) + UInt64(Self.pLimbs[i]) + carry
                result[i] = UInt32(truncatingIfNeeded: s)
                carry = s >> 32
            }
            _ = carry  // expected to cancel the borrow
        }
        return Field25519(limbs: result)
    }

    // MARK: - Multiply

    public static func * (a: Field25519, b: Field25519) -> Field25519 {
        // Step 1: schoolbook 8x8 → 16-limb product.
        var prod = [UInt32](repeating: 0, count: 16)
        for i in 0..<8 {
            var carry: UInt64 = 0
            for j in 0..<8 {
                let s = UInt64(prod[i + j])
                      + UInt64(a.limbs[i]) * UInt64(b.limbs[j])
                      + carry
                prod[i + j] = UInt32(truncatingIfNeeded: s)
                carry = s >> 32
            }
            prod[i + 8] = UInt32(truncatingIfNeeded: carry)
        }
        // prod now holds a 512-bit value as 16 UInt32 limbs.

        // Step 2: reduce. 2^256 ≡ 38 (mod p), so multiply high 8 limbs by 38
        // and add to low 8 limbs.
        var r = [UInt64](repeating: 0, count: 8)
        for i in 0..<8 {
            r[i] = UInt64(prod[i]) + 38 * UInt64(prod[i + 8])
        }
        // r[i] is at most (2^32-1) + 38*(2^32-1) < 2^38.

        // Step 3: propagate carries across r[0..7].
        for i in 0..<7 {
            r[i + 1] += r[i] >> 32
            r[i] &= 0xffff_ffff
        }
        // r[7] may exceed 2^32 from accumulated carries.

        // Step 4: handle bits above 2^256 (in r[7]) — again via the 38 trick.
        let bigOverflow = r[7] >> 32
        r[7] &= 0xffff_ffff
        r[0] += bigOverflow * 38
        for i in 0..<7 {
            r[i + 1] += r[i] >> 32
            r[i] &= 0xffff_ffff
        }
        // Edge case: a carry from r[6] in the previous pass can push r[7] to
        // exactly 2^32 (since each carry between limbs adds 0 or 1 and r[7]
        // was already < 2^32 before this pass). Do one more clean-up pass if
        // we still have overflow above limb 7.
        if r[7] >> 32 != 0 {
            let extra = r[7] >> 32
            r[7] &= 0xffff_ffff
            r[0] += extra * 38
            for i in 0..<7 {
                r[i + 1] += r[i] >> 32
                r[i] &= 0xffff_ffff
            }
        }
        // r[0..7] are now all < 2^32, value is in [0, 2^256).

        var limbs = [UInt32](repeating: 0, count: 8)
        for i in 0..<8 {
            limbs[i] = UInt32(truncatingIfNeeded: r[i])
        }
        return Field25519(limbs: limbs)
    }

    /// Square (slightly more efficient than `self * self` could be, but here
    /// we just delegate for code-simplicity over speed).
    public func squared() -> Field25519 {
        self * self
    }

    // MARK: - Inverse

    /// Modular inverse via Fermat's little theorem: a^(p-2) ≡ a^(-1) (mod p).
    /// p - 2 = 2^255 - 21 — almost all-ones binary, sparse zeros.
    public func inverse() -> Field25519 {
        // p - 2 in little-endian bytes:
        //   byte 0  = 0xeb   (since 0xff - 20 = 0xeb)
        //   byte 1..30 = 0xff
        //   byte 31 = 0x7f
        var pm2 = [UInt8](repeating: 0xff, count: 32)
        pm2[0] = 0xeb
        pm2[31] = 0x7f
        return self.pow(littleEndianExponent: pm2)
    }

    /// Square-and-multiply exponentiation. `exponent` is little-endian bytes.
    /// Not constant-time — fine for our use case (only invoked for converting
    /// SSH public keys, which are not secret).
    public func pow(littleEndianExponent exponent: [UInt8]) -> Field25519 {
        var result = Field25519.one
        var base = self
        for byte in exponent {
            for bit in 0..<8 {
                if (byte >> bit) & 1 == 1 {
                    result = result * base
                }
                base = base.squared()
            }
        }
        return result
    }

    // MARK: - Equatable

    public static func == (a: Field25519, b: Field25519) -> Bool {
        a.canonical().limbs == b.canonical().limbs
    }
}
