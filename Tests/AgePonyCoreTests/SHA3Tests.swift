//
//  SHA3Tests.swift
//  AgePonyCoreTests
//
//  FIPS 202 known-answer tests for the hand-rolled Keccak sponge, plus the
//  properties ML-KEM depends on: correct behaviour across rate boundaries, and
//  incremental squeezing that agrees with one-shot output.
//

import XCTest
@testable import AgePonyCore

final class SHA3Tests: XCTestCase {

    private func hex(_ d: Data) -> String {
        d.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Published FIPS 202 vectors

    func testSHA3_256KnownAnswers() {
        XCTAssertEqual(
            hex(SHA3.sha3_256(Data())),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
        XCTAssertEqual(
            hex(SHA3.sha3_256(Data("abc".utf8))),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        )
    }

    func testSHA3_512KnownAnswers() {
        XCTAssertEqual(
            hex(SHA3.sha3_512(Data())),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        )
        XCTAssertEqual(
            hex(SHA3.sha3_512(Data("abc".utf8))),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        )
    }

    func testSHAKEKnownAnswers() {
        XCTAssertEqual(
            hex(SHA3.shake128(Data(), outputByteCount: 32)),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        )
        XCTAssertEqual(
            hex(SHA3.shake256(Data(), outputByteCount: 32)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        )
        XCTAssertEqual(
            hex(SHA3.shake128(Data("abc".utf8), outputByteCount: 64)),
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
            + "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378"
        )
        XCTAssertEqual(
            hex(SHA3.shake256(Data("abc".utf8), outputByteCount: 64)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
            + "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        )
    }

    // MARK: - Rate boundaries
    //
    // SHA3-256 absorbs 136 bytes at a time. Inputs just under, exactly on, and just
    // over a block are where padding bugs live.

    func testAbsorbAcrossRateBoundary() {
        let a = { (n: Int) in Data(repeating: UInt8(ascii: "a"), count: n) }
        XCTAssertEqual(
            hex(SHA3.sha3_256(a(135))),
            "8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9"
        )
        XCTAssertEqual(
            hex(SHA3.sha3_256(a(136))),
            "3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1"
        )
        XCTAssertEqual(
            hex(SHA3.sha3_256(a(137))),
            "f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614"
        )
    }

    func testSqueezeAcrossRateBoundary() {
        // SHAKE128's rate is 168; pulling 400 bytes spans three permutations.
        let out = SHA3.shake128(Data(repeating: UInt8(ascii: "a"), count: 168), outputByteCount: 400)
        XCTAssertEqual(out.count, 400)
        XCTAssertEqual(
            hex(Data(out.suffix(32))),
            "f2f886745f7e2d838671bab432ad24d3a648190034302a96210094f47908786e"
        )
    }

    // MARK: - Incremental squeezing
    //
    // ML-KEM's SampleNTT pulls 3 bytes at a time for an unbounded number of rounds.
    // Incremental output must equal the one-shot digest of the same total length.

    func testIncrementalSqueezeMatchesOneShot() {
        for pattern in [[Int](repeating: 3, count: 400),
                        [1, 167, 1, 168, 169],
                        [168, 168, 168],
                        [Int](repeating: 5, count: 300)] {
            var sponge = SHA3.shake128Sponge(Data("seed".utf8))
            var incremental = Data()
            for n in pattern { incremental.append(sponge.squeeze(n)) }
            let oneShot = SHA3.shake128(Data("seed".utf8), outputByteCount: incremental.count)
            XCTAssertEqual(incremental, oneShot, "pattern starting \(pattern.prefix(3))")
        }
    }

    func testSHAKE256IncrementalMatchesOneShot() {
        var sponge = SHA3.shake256Sponge(Data("agepony".utf8))
        var incremental = Data()
        for n in [7, 129, 1, 136, 200] { incremental.append(sponge.squeeze(n)) }
        XCTAssertEqual(
            incremental,
            SHA3.shake256(Data("agepony".utf8), outputByteCount: incremental.count)
        )
    }
}
