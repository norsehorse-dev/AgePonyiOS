import Foundation

/// Minimal unsigned big-integer support, sized for RSA private key handling.
///
/// Storage: little-endian `[UInt64]` limbs (lowest limb first). Trailing zero limbs trimmed.
/// Operations: `init(bigEndianBytes:)`, `toBigEndianBytes()`, `subtract`, `subtractOne`, `mod`.
/// This is intentionally NOT a general-purpose BigInt — we only need enough to derive
/// `exp1 = d mod (p-1)` and `exp2 = d mod (q-1)` when constructing an RSA private SecKey.
public struct BigUInt: Equatable, Sendable {
    public var limbs: [UInt64]

    public init(limbs: [UInt64]) {
        var l = limbs
        while let last = l.last, last == 0 {
            l.removeLast()
        }
        self.limbs = l
    }

    public init(_ value: UInt64) {
        self.limbs = value == 0 ? [] : [value]
    }

    /// Parse a non-negative integer from big-endian bytes.
    public init(bigEndianBytes bytes: Data) {
        var trimmed = bytes
        while trimmed.count > 0, trimmed.first == 0 {
            trimmed = trimmed.dropFirst()
        }
        if trimmed.isEmpty {
            self.limbs = []
            return
        }
        let count = trimmed.count
        let limbCount = (count + 7) / 8
        var l = [UInt64](repeating: 0, count: limbCount)
        // bytes[count-1] is the lowest byte (little end), goes into l[0] byte 0
        for i in 0..<count {
            let byteVal = trimmed[trimmed.startIndex + (count - 1 - i)]
            let limbIdx = i / 8
            let byteIdx = i % 8
            l[limbIdx] |= UInt64(byteVal) << (byteIdx * 8)
        }
        while let last = l.last, last == 0 {
            l.removeLast()
        }
        self.limbs = l
    }

    /// Encode to big-endian bytes with no leading zeros (or empty Data if zero).
    public func toBigEndianBytes() -> Data {
        if limbs.isEmpty { return Data() }
        var bytes: [UInt8] = []
        let topLimb = limbs.last!
        var seenNonzero = false
        for shift in (0..<8).reversed() {
            let b = UInt8((topLimb >> (shift * 8)) & 0xff)
            if !seenNonzero {
                if b == 0 { continue }
                seenNonzero = true
            }
            bytes.append(b)
        }
        // Remaining limbs (all 8 bytes each) in BE order
        if limbs.count >= 2 {
            for i in (0..<limbs.count - 1).reversed() {
                let limb = limbs[i]
                for shift in (0..<8).reversed() {
                    bytes.append(UInt8((limb >> (shift * 8)) & 0xff))
                }
            }
        }
        return Data(bytes)
    }

    public var isZero: Bool { limbs.isEmpty }

    /// Bit length of self: 0 if zero, else position of highest set bit + 1.
    public var bitWidth: Int {
        guard let top = limbs.last else { return 0 }
        return (limbs.count - 1) * 64 + (64 - top.leadingZeroBitCount)
    }

    /// Return bit `index` (0 = lowest) as 0 or 1.
    public func bit(at index: Int) -> Int {
        let limbIdx = index / 64
        let bitIdx = index % 64
        if limbIdx >= limbs.count { return 0 }
        return Int((limbs[limbIdx] >> bitIdx) & 1)
    }

    /// Set bit `index` to 1.
    public mutating func setBit(at index: Int) {
        let limbIdx = index / 64
        let bitIdx = index % 64
        while limbs.count <= limbIdx {
            limbs.append(0)
        }
        limbs[limbIdx] |= UInt64(1) << bitIdx
    }

    /// Less-than comparison.
    public static func < (a: BigUInt, b: BigUInt) -> Bool {
        if a.limbs.count != b.limbs.count {
            return a.limbs.count < b.limbs.count
        }
        for i in (0..<a.limbs.count).reversed() {
            if a.limbs[i] != b.limbs[i] {
                return a.limbs[i] < b.limbs[i]
            }
        }
        return false
    }

    /// `(a - b, didUnderflow)`. If `a >= b`, `didUnderflow = false` and the result is exact.
    public static func subtract(_ a: BigUInt, _ b: BigUInt) -> (BigUInt, Bool) {
        let maxCount = max(a.limbs.count, b.limbs.count)
        var r = [UInt64](repeating: 0, count: maxCount)
        var borrow: UInt64 = 0
        for i in 0..<maxCount {
            let ai = i < a.limbs.count ? a.limbs[i] : 0
            let bi = i < b.limbs.count ? b.limbs[i] : 0
            let (s1, ov1) = ai.subtractingReportingOverflow(bi)
            let (s2, ov2) = s1.subtractingReportingOverflow(borrow)
            r[i] = s2
            borrow = (ov1 || ov2) ? 1 : 0
        }
        return (BigUInt(limbs: r), borrow != 0)
    }

    /// `self - 1`. Precondition: `self > 0`.
    public static func subtractOne(_ a: BigUInt) -> BigUInt {
        precondition(!a.isZero, "subtractOne from zero")
        var r = a.limbs
        var i = 0
        while i < r.count {
            let (s, ov) = r[i].subtractingReportingOverflow(1)
            r[i] = s
            if !ov { break }
            i += 1
        }
        return BigUInt(limbs: r)
    }

    /// Shift left by `n` bits, returning a new value. `n` must be non-negative.
    public func shiftedLeft(by n: Int) -> BigUInt {
        precondition(n >= 0, "negative shift")
        if n == 0 || limbs.isEmpty { return self }
        let limbShift = n / 64
        let bitShift = n % 64
        var out = [UInt64](repeating: 0, count: limbs.count + limbShift + (bitShift > 0 ? 1 : 0))
        for i in 0..<limbs.count {
            let l = limbs[i]
            out[i + limbShift] |= l << bitShift
            if bitShift > 0 {
                out[i + limbShift + 1] |= l >> (64 - bitShift)
            }
        }
        return BigUInt(limbs: out)
    }

    /// `self mod m` via shift-and-subtract long division. O(bitWidth(self) * limbs(m)).
    /// For RSA-sized inputs (d ~2048 bits, m ~1024 bits) this is plenty fast.
    public func mod(_ m: BigUInt) -> BigUInt {
        precondition(!m.isZero, "mod by zero")
        if self < m { return self }
        let bits = self.bitWidth
        var r = BigUInt(limbs: [])
        for i in (0..<bits).reversed() {
            r = r.shiftedLeft(by: 1)
            if self.bit(at: i) == 1 {
                r.setBit(at: 0)
            }
            if !(r < m) {
                let (sub, _) = BigUInt.subtract(r, m)
                r = sub
            }
        }
        return r
    }
}
