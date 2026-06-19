//
//  Field25519Tests.swift
//  AgePonyCoreTests
//
//  Algebraic identity tests for the GF(2^255-19) arithmetic. These are the
//  primary correctness signal for Field25519: the cross-impl SSH round-trip
//  in ReferenceCLITests is the final check, but if any of these identities
//  fail, the field math is wrong and no higher-level test will be meaningful.
//

import XCTest
@testable import AgePonyCore

final class Field25519Tests: XCTestCase {

    // MARK: - Helpers

    private func randomBytes(_ n: Int) -> Data {
        var d = Data(count: n)
        for i in 0..<n { d[i] = UInt8.random(in: 0...255) }
        return d
    }

    /// Pick a random reduced (< p) field element.
    private func randomElement() -> Field25519 {
        var e = Field25519(littleEndianBytes: randomBytes(32), maskHighBit: true)
        e = e.canonical()
        return e
    }

    // MARK: - Identity & ordering tests

    func testZeroPlusZero() {
        XCTAssertEqual((Field25519.zero + Field25519.zero), Field25519.zero)
    }

    func testZeroPlusAEqualsA() {
        for _ in 0..<10 {
            let a = randomElement()
            XCTAssertEqual(Field25519.zero + a, a)
            XCTAssertEqual(a + Field25519.zero, a)
        }
    }

    func testAMinusAEqualsZero() {
        for _ in 0..<10 {
            let a = randomElement()
            XCTAssertEqual((a - a).canonical(), Field25519.zero)
        }
    }

    func testOneTimesA() {
        for _ in 0..<10 {
            let a = randomElement()
            XCTAssertEqual((Field25519.one * a).canonical(), a)
            XCTAssertEqual((a * Field25519.one).canonical(), a)
        }
    }

    func testZeroTimesA() {
        for _ in 0..<10 {
            let a = randomElement()
            XCTAssertEqual((Field25519.zero * a).canonical(), Field25519.zero)
        }
    }

    // MARK: - Commutativity

    func testAdditionCommutative() {
        for _ in 0..<10 {
            let a = randomElement(), b = randomElement()
            XCTAssertEqual((a + b).canonical(), (b + a).canonical())
        }
    }

    func testMultiplicationCommutative() {
        for _ in 0..<10 {
            let a = randomElement(), b = randomElement()
            XCTAssertEqual((a * b).canonical(), (b * a).canonical())
        }
    }

    // MARK: - Distributivity

    func testDistributivity() {
        for _ in 0..<5 {
            let a = randomElement(), b = randomElement(), c = randomElement()
            let lhs = (a * (b + c)).canonical()
            let rhs = ((a * b) + (a * c)).canonical()
            XCTAssertEqual(lhs, rhs)
        }
    }

    // MARK: - Inverse

    func testInverseOfOne() {
        XCTAssertEqual(Field25519.one.inverse(), Field25519.one)
    }

    func testAInverseTimesAIsOne() {
        for _ in 0..<5 {
            let a = randomElement()
            // skip the (astronomically unlikely) zero case
            if a.canonical().limbs.allSatisfy({ $0 == 0 }) { continue }
            let result = (a * a.inverse()).canonical()
            XCTAssertEqual(result, Field25519.one)
        }
    }

    func testDoubleInverseIsIdentity() {
        for _ in 0..<5 {
            let a = randomElement()
            if a.canonical().limbs.allSatisfy({ $0 == 0 }) { continue }
            XCTAssertEqual(a.inverse().inverse().canonical(), a.canonical())
        }
    }

    // MARK: - Reduction edge cases

    func testPModPIsZero() {
        // Construct an element holding exactly p in raw limbs.
        let p = Field25519(limbs: Field25519.pLimbs)
        XCTAssertEqual(p.canonical(), Field25519.zero)
    }

    func testPMinusOnePlusOneIsZero() {
        // p - 1 has the same limbs as p except limbs[0] = 0xffff_ffec.
        var pm1Limbs = Field25519.pLimbs
        pm1Limbs[0] = 0xffff_ffec
        let pm1 = Field25519(limbs: pm1Limbs)
        let result = (pm1 + Field25519.one).canonical()
        XCTAssertEqual(result, Field25519.zero)
    }

    func testZeroMinusOneIsPMinusOne() {
        var pm1Limbs = Field25519.pLimbs
        pm1Limbs[0] = 0xffff_ffec
        let pm1 = Field25519(limbs: pm1Limbs)
        let result = (Field25519.zero - Field25519.one).canonical()
        XCTAssertEqual(result, pm1)
    }

    // MARK: - Encoding round-trip

    func testByteRoundTrip() {
        for _ in 0..<10 {
            let bytes = randomBytes(32)
            var input = bytes
            input[31] &= 0x7f  // canonical form has top bit clear
            let f = Field25519(littleEndianBytes: input)
            // f might be >= p; the canonical form is what round-trips.
            let out = f.toLittleEndianBytes()
            // out should equal canonical(input).
            let reparsed = Field25519(littleEndianBytes: out)
            XCTAssertEqual(reparsed.canonical(), f.canonical())
        }
    }

    func testHighBitMaskHonoredByInit() {
        // Build a 32-byte value with bit 255 set, ensure the masking init clears it.
        var bytes = Data(repeating: 0x00, count: 32)
        bytes[31] = 0x80
        let f = Field25519(littleEndianBytes: bytes, maskHighBit: true)
        XCTAssertEqual(f.canonical(), Field25519.zero)
    }
}
