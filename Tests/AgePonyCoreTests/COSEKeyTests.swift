//
//  COSEKeyTests.swift
//  AgePonyCoreTests
//
//  Golden COSE_Key blobs generated with cbor2, decoded back to the raw / x963
//  forms AgePony uses elsewhere.
//

import XCTest
@testable import AgePonyCore

final class COSEKeyTests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var d = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i ..< j], radix: 16)!)
            i = j
        }
        return d
    }

    func testDecodeEd25519() throws {
        let cose = hex(
            "a4010103272006215820" +
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        )
        let key = try COSEKey.decode(cose)
        guard case .ed25519(let raw) = key else { return XCTFail("expected ed25519") }
        XCTAssertEqual(raw, Data((0x40 ..< 0x60).map { UInt8($0) }))
    }

    func testDecodeP256() throws {
        let cose = hex(
            "a5010203262001215820" +
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
            "225820" +
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        )
        let key = try COSEKey.decode(cose)
        guard case .p256(let q) = key else { return XCTFail("expected p256") }
        XCTAssertEqual(q.first, 0x04)
        XCTAssertEqual(q.count, 65)
        XCTAssertEqual(q, hex("04") + Data((0x10 ..< 0x30).map { UInt8($0) }) + Data((0x80 ..< 0xA0).map { UInt8($0) }))
    }

    func testRejectsUnsupportedKeyType() {
        // kty = 4 (symmetric), not OKP/EC2.
        let cose = hex("a201040320")  // {1:4, 3:-1}
        XCTAssertThrowsError(try COSEKey.decode(cose))
    }

    func testRejectsWrongCurve() {
        // OKP but crv = 4 (X25519), not Ed25519(6).
        let cose = hex(
            "a4010103272004215820" +
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        )
        XCTAssertThrowsError(try COSEKey.decode(cose)) { e in
            XCTAssertEqual(e as? COSEKeyError, .unsupportedCurve(4))
        }
    }

    func testRejectsShortCoordinate() {
        // Well-formed EC2 P-256 map, but the coordinates are only 4 bytes each.
        let bad = CBOR.map([
            (.int(1), .int(2)),
            (.int(3), .int(-7)),
            (.int(-1), .int(1)),
            (.int(-2), .bytes(Data([0x10, 0x11, 0x12, 0x13]))),
            (.int(-3), .bytes(Data([0x80, 0x81, 0x82, 0x83]))),
        ]).encoded()
        XCTAssertThrowsError(try COSEKey.decode(bad)) { e in
            XCTAssertEqual(e as? COSEKeyError, .wrongCoordinateLength)
        }
    }
}
