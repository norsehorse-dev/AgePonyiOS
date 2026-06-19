import XCTest
@testable import AgePonyCore

final class BigUIntTests: XCTestCase {
    func testZero() {
        let z = BigUInt(0)
        XCTAssertTrue(z.isZero)
        XCTAssertEqual(z.bitWidth, 0)
        XCTAssertEqual(z.toBigEndianBytes(), Data())
    }

    func testSmallValueRoundTrip() {
        for v: UInt64 in [1, 2, 0x80, 0xff, 0x100, 0xffff, 0xffffffff] {
            let n = BigUInt(v)
            let bytes = n.toBigEndianBytes()
            let parsed = BigUInt(bigEndianBytes: bytes)
            XCTAssertEqual(parsed, n, "round-trip failed for \(v)")
        }
    }

    func testBigEndianRoundTrip_largeRandom() {
        for _ in 0..<10 {
            var bytes = [UInt8]()
            for _ in 0..<200 { bytes.append(UInt8.random(in: 0...255)) }
            // ensure non-zero first byte
            bytes[0] = max(1, bytes[0])
            let data = Data(bytes)
            let n = BigUInt(bigEndianBytes: data)
            XCTAssertEqual(n.toBigEndianBytes(), data)
        }
    }

    func testLessThan() {
        XCTAssertTrue(BigUInt(5) < BigUInt(10))
        XCTAssertFalse(BigUInt(10) < BigUInt(5))
        XCTAssertFalse(BigUInt(5) < BigUInt(5))
        XCTAssertTrue(BigUInt(0) < BigUInt(1))
    }

    func testSubtract() {
        let (r1, b1) = BigUInt.subtract(BigUInt(10), BigUInt(3))
        XCTAssertEqual(r1, BigUInt(7))
        XCTAssertFalse(b1)
        let (_, b2) = BigUInt.subtract(BigUInt(3), BigUInt(10))
        XCTAssertTrue(b2)  // underflow
        let (r3, _) = BigUInt.subtract(BigUInt(10), BigUInt(10))
        XCTAssertEqual(r3, BigUInt(0))
    }

    func testSubtractOne() {
        XCTAssertEqual(BigUInt.subtractOne(BigUInt(1)), BigUInt(0))
        XCTAssertEqual(BigUInt.subtractOne(BigUInt(0x100)), BigUInt(0xff))
        // Borrow across limbs
        let bigVal = BigUInt(limbs: [0, 1])
        XCTAssertEqual(BigUInt.subtractOne(bigVal), BigUInt(limbs: [UInt64.max]))
    }

    func testShiftLeft() {
        XCTAssertEqual(BigUInt(1).shiftedLeft(by: 0), BigUInt(1))
        XCTAssertEqual(BigUInt(1).shiftedLeft(by: 1), BigUInt(2))
        XCTAssertEqual(BigUInt(1).shiftedLeft(by: 8), BigUInt(0x100))
        XCTAssertEqual(BigUInt(1).shiftedLeft(by: 64), BigUInt(limbs: [0, 1]))
        XCTAssertEqual(BigUInt(1).shiftedLeft(by: 65), BigUInt(limbs: [0, 2]))
    }

    func testBitWidth() {
        XCTAssertEqual(BigUInt(0).bitWidth, 0)
        XCTAssertEqual(BigUInt(1).bitWidth, 1)
        XCTAssertEqual(BigUInt(2).bitWidth, 2)
        XCTAssertEqual(BigUInt(0xff).bitWidth, 8)
        XCTAssertEqual(BigUInt(0x100).bitWidth, 9)
    }

    func testModSmallValues() {
        XCTAssertEqual(BigUInt(5).mod(BigUInt(3)), BigUInt(2))
        XCTAssertEqual(BigUInt(100).mod(BigUInt(7)), BigUInt(2))
        XCTAssertEqual(BigUInt(256).mod(BigUInt(255)), BigUInt(1))
        XCTAssertEqual(BigUInt(255).mod(BigUInt(256)), BigUInt(255))
        XCTAssertEqual(BigUInt(100).mod(BigUInt(100)), BigUInt(0))
        XCTAssertEqual(BigUInt(0).mod(BigUInt(7)), BigUInt(0))
    }

    /// RSA-sized mod vector verified offline with Python:
    ///   d  = 0x5a repeated 256 times (2047-bit value)
    ///   m  = (1 << 1024) - 1  =  0xff repeated 128 times
    ///   d mod m  =  0xb4 repeated 128 times
    func testModRSASized() {
        let d = BigUInt(bigEndianBytes: Data(repeating: 0x5a, count: 256))
        let m = BigUInt(bigEndianBytes: Data(repeating: 0xff, count: 128))
        let expected = BigUInt(bigEndianBytes: Data(repeating: 0xb4, count: 128))
        XCTAssertEqual(d.mod(m), expected)
    }
}
