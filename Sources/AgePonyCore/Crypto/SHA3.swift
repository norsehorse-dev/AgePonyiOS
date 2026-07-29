//
//  SHA3.swift
//  AgePonyCore
//
//  Keccak-f[1600] sponge: SHA3-256, SHA3-512, and the SHAKE128 / SHAKE256 XOFs.
//
//  CryptoKit provides no SHA-3 and no XOF, so this is hand-rolled. It exists for
//  the MLKEM768-X25519 hybrid recipient (age-encryption.org/mlkem768x25519):
//
//    - SHA3-256 is the hybrid KEM shared-secret combiner, and ML-KEM's H.
//    - SHA3-512 is ML-KEM's G.
//    - SHAKE256 expands the identity seed, and is ML-KEM's PRF and J.
//    - SHAKE128 is ML-KEM's XOF for matrix expansion.
//
//  Squeezing is incremental: ML-KEM's SampleNTT rejection-samples until it has 256
//  coefficients and cannot bound its output length in advance, so a fixed-size
//  digest API would not be correct there. `KeccakSponge` lets a caller keep pulling.
//
//  Validated against FIPS 202 test vectors, including across block boundaries and
//  with incremental squeezes matching one-shot output.
//

import Foundation

// MARK: - Sponge

/// An absorb-then-squeeze Keccak sponge with incremental output.
///
/// Absorb with `absorb(_:)`, then pull output with `squeeze(_:)`. The first squeeze
/// applies padding and switches the sponge permanently into squeezing mode;
/// absorbing after that point is a programming error.
public struct KeccakSponge {
    private var state: [UInt64]
    private let rate: Int
    private let domainSeparator: UInt8
    private var buffer: [UInt8]
    private var squeezing: Bool
    private var outputBlock: [UInt8]
    private var outputPos: Int

    /// - Parameters:
    ///   - rate: sponge rate in bytes (168 for SHAKE128, 136 for SHA3-256/SHAKE256, 72 for SHA3-512).
    ///   - domainSeparator: 0x06 for SHA-3, 0x1F for the SHAKE XOFs.
    public init(rate: Int, domainSeparator: UInt8) {
        precondition(rate > 0 && rate < 200 && rate % 8 == 0, "invalid Keccak rate")
        self.state = [UInt64](repeating: 0, count: 25)
        self.rate = rate
        self.domainSeparator = domainSeparator
        self.buffer = []
        self.buffer.reserveCapacity(rate)
        self.squeezing = false
        self.outputBlock = [UInt8](repeating: 0, count: rate)
        self.outputPos = 0
    }

    // MARK: Absorbing

    public mutating func absorb(_ data: Data) {
        precondition(!squeezing, "cannot absorb after squeezing has begun")
        var offset = data.startIndex
        while offset < data.endIndex {
            let take = min(rate - buffer.count, data.endIndex - offset)
            buffer.append(contentsOf: data[offset..<(offset + take)])
            offset += take
            if buffer.count == rate {
                absorbBlock(buffer)
                buffer.removeAll(keepingCapacity: true)
            }
        }
    }

    public mutating func absorb(_ bytes: [UInt8]) {
        absorb(Data(bytes))
    }

    private mutating func absorbBlock(_ block: [UInt8]) {
        for i in 0..<(rate / 8) {
            var lane: UInt64 = 0
            for b in 0..<8 {
                lane |= UInt64(block[8 * i + b]) << (8 * b)
            }
            state[i] ^= lane
        }
        KeccakSponge.permute(&state)
    }

    // MARK: Squeezing

    /// Pull `length` more bytes of output, permuting as needed.
    public mutating func squeeze(_ length: Int) -> Data {
        precondition(length >= 0, "squeeze length must not be negative")
        if !squeezing { padAndSwitch() }
        var out = Data()
        out.reserveCapacity(length)
        while out.count < length {
            if outputPos == rate {
                KeccakSponge.permute(&state)
                refillOutputBlock()
            }
            let take = min(rate - outputPos, length - out.count)
            out.append(contentsOf: outputBlock[outputPos..<(outputPos + take)])
            outputPos += take
        }
        return out
    }

    private mutating func padAndSwitch() {
        // pad10*1, with the domain separator folded into the leading pad byte.
        var block = [UInt8](repeating: 0, count: rate)
        for (i, b) in buffer.enumerated() { block[i] = b }
        block[buffer.count] ^= domainSeparator
        block[rate - 1] ^= 0x80
        absorbBlock(block)
        buffer.removeAll(keepingCapacity: true)
        squeezing = true
        refillOutputBlock()
    }

    private mutating func refillOutputBlock() {
        for i in 0..<(rate / 8) {
            let lane = state[i]
            for b in 0..<8 {
                outputBlock[8 * i + b] = UInt8(truncatingIfNeeded: lane >> (8 * b))
            }
        }
        outputPos = 0
    }

    // MARK: - Keccak-f[1600]

    private static let roundConstants: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    private static let rhoOffsets: [UInt64] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ]

    @inline(__always)
    private static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
        n == 0 ? x : (x << n) | (x >> (64 - n))
    }

    /// The permutation. `state` is 25 lanes indexed `x + 5 * y`.
    static func permute(_ state: inout [UInt64]) {
        var b = [UInt64](repeating: 0, count: 25)
        var c = [UInt64](repeating: 0, count: 5)
        var d = [UInt64](repeating: 0, count: 5)

        for round in 0..<24 {
            // Theta
            for x in 0..<5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            }
            for x in 0..<5 {
                d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
            }
            for x in 0..<5 {
                for y in 0..<5 {
                    state[x + 5 * y] ^= d[x]
                }
            }

            // Rho and Pi
            for x in 0..<5 {
                for y in 0..<5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], rhoOffsets[x + 5 * y])
                }
            }

            // Chi
            for x in 0..<5 {
                for y in 0..<5 {
                    state[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
                }
            }

            // Iota
            state[0] ^= roundConstants[round]
        }
    }
}

// MARK: - One-shot API

public enum SHA3 {
    /// SHA3-256 (rate 136, domain 0x06).
    public static func sha3_256(_ data: Data) -> Data {
        var s = KeccakSponge(rate: 136, domainSeparator: 0x06)
        s.absorb(data)
        return s.squeeze(32)
    }

    /// SHA3-512 (rate 72, domain 0x06). ML-KEM's G.
    public static func sha3_512(_ data: Data) -> Data {
        var s = KeccakSponge(rate: 72, domainSeparator: 0x06)
        s.absorb(data)
        return s.squeeze(64)
    }

    /// SHAKE128 XOF (rate 168, domain 0x1F).
    public static func shake128(_ data: Data, outputByteCount: Int) -> Data {
        var s = shake128Sponge(data)
        return s.squeeze(outputByteCount)
    }

    /// SHAKE256 XOF (rate 136, domain 0x1F).
    public static func shake256(_ data: Data, outputByteCount: Int) -> Data {
        var s = shake256Sponge(data)
        return s.squeeze(outputByteCount)
    }

    /// An incremental SHAKE128 reader, for ML-KEM's SampleNTT.
    public static func shake128Sponge(_ data: Data) -> KeccakSponge {
        var s = KeccakSponge(rate: 168, domainSeparator: 0x1F)
        s.absorb(data)
        return s
    }

    /// An incremental SHAKE256 reader.
    public static func shake256Sponge(_ data: Data) -> KeccakSponge {
        var s = KeccakSponge(rate: 136, domainSeparator: 0x1F)
        s.absorb(data)
        return s
    }
}
