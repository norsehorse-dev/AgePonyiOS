//
//  CBORTests.swift
//  AgePonyCoreTests
//
//  Golden vectors generated independently with Python's `cbor2` (canonical
//  mode), so these pin our encoder/decoder against a reference implementation,
//  not against itself.
//

import XCTest
@testable import AgePonyCore

final class CBORTests: XCTestCase {

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

    // MARK: Scalars (RFC 8949 Appendix A)

    func testEncodeUnsigned() {
        XCTAssertEqual(CBOR.int(0).encoded(), hex("00"))
        XCTAssertEqual(CBOR.int(10).encoded(), hex("0a"))
        XCTAssertEqual(CBOR.int(23).encoded(), hex("17"))
        XCTAssertEqual(CBOR.int(24).encoded(), hex("1818"))
        XCTAssertEqual(CBOR.int(100).encoded(), hex("1864"))
        XCTAssertEqual(CBOR.int(1000).encoded(), hex("1903e8"))
        XCTAssertEqual(CBOR.int(1_000_000).encoded(), hex("1a000f4240"))
    }

    func testEncodeNegative() {
        XCTAssertEqual(CBOR.int(-1).encoded(), hex("20"))
        XCTAssertEqual(CBOR.int(-10).encoded(), hex("29"))
        XCTAssertEqual(CBOR.int(-24).encoded(), hex("37"))
        XCTAssertEqual(CBOR.int(-100).encoded(), hex("3863"))
        XCTAssertEqual(CBOR.int(-1000).encoded(), hex("3903e7"))
    }

    func testDecodeScalars() throws {
        XCTAssertEqual(try CBORReader.decode(hex("1818")).intValue, 24)
        XCTAssertEqual(try CBORReader.decode(hex("1a000f4240")).intValue, 1_000_000)
        XCTAssertEqual(try CBORReader.decode(hex("20")).intValue, -1)
        XCTAssertEqual(try CBORReader.decode(hex("3903e7")).intValue, -1000)
    }

    func testStringsAndArrays() throws {
        XCTAssertEqual(CBOR.bytes(hex("01020304")).encoded(), hex("4401020304"))
        XCTAssertEqual(CBOR.text("ssh:").encoded(), hex("647373683a"))
        XCTAssertEqual(CBOR.array([.int(1), .int(2), .int(3)]).encoded(), hex("83010203"))
        XCTAssertEqual(CBOR.bool(true).encoded(), hex("f5"))
        XCTAssertEqual(CBOR.bool(false).encoded(), hex("f4"))

        XCTAssertEqual(try CBORReader.decode(hex("4401020304")).bytesValue, hex("01020304"))
        XCTAssertEqual(try CBORReader.decode(hex("647373683a")).textValue, "ssh:")
    }

    // MARK: Canonical map ordering

    func testCanonicalMapOrdering() {
        // COSE EC2 key, keys handed in deliberately shuffled order; canonical
        // output must order them 1, 3, -1, -2, -3.
        let x = Data((0x10 ..< 0x30).map { UInt8($0) })
        let y = Data((0x80 ..< 0xA0).map { UInt8($0) })
        let map = CBOR.map([
            (.int(-2), .bytes(x)),
            (.int(1), .int(2)),
            (.int(-3), .bytes(y)),
            (.int(3), .int(-7)),
            (.int(-1), .int(1)),
        ])
        let golden = hex(
            "a5010203262001215820" +
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
            "225820" +
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        )
        XCTAssertEqual(map.encoded(), golden)
    }

    func testNestedMapAndMixedTypes() {
        // getAssertion-style { 1: "ssh:", 2: <32 bytes>, 5: { "up": true } }
        let cdh = Data(repeating: 0xAA, count: 32)
        let map = CBOR.map([
            (.int(5), .map([(.text("up"), .bool(true))])),
            (.int(1), .text("ssh:")),
            (.int(2), .bytes(cdh)),
        ])
        let golden = hex(
            "a301647373683a025820" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "05a1627570f5"
        )
        XCTAssertEqual(map.encoded(), golden)
    }

    // MARK: Decode helpers and round trip

    func testDecodeMapByIntKey() throws {
        let golden = hex(
            "a5010203262001215820" +
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
            "225820" +
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        )
        let cbor = try CBORReader.decode(golden)
        XCTAssertEqual(cbor.value(forIntKey: 1)?.intValue, 2)
        XCTAssertEqual(cbor.value(forIntKey: 3)?.intValue, -7)
        XCTAssertEqual(cbor.value(forIntKey: -1)?.intValue, 1)
        XCTAssertEqual(cbor.value(forIntKey: -2)?.bytesValue, Data((0x10 ..< 0x30).map { UInt8($0) }))
        XCTAssertEqual(cbor.value(forIntKey: -3)?.bytesValue, Data((0x80 ..< 0xA0).map { UInt8($0) }))
    }

    func testRoundTrip() throws {
        let value = CBOR.map([
            (.int(1), .text("ssh:")),
            (.int(2), .bytes(Data([1, 2, 3]))),
            (.int(3), .array([.int(-7), .int(-8)])),
            (.int(4), .bool(false)),
            (.int(5), .null),
        ])
        let decoded = try CBORReader.decode(value.encoded())
        XCTAssertEqual(decoded, value)
    }

    // MARK: Cursor behaviour and errors

    func testCursorReportsOffset() throws {
        // Two concatenated items; decode each in turn.
        var reader = CBORReader(hex("0a") + hex("647373683a"))
        XCTAssertEqual(try reader.decode().intValue, 10)
        XCTAssertEqual(try reader.decode().textValue, "ssh:")
        XCTAssertTrue(reader.isAtEnd)
    }

    func testTrailingBytesRejected() {
        XCTAssertThrowsError(try CBORReader.decode(hex("0000"))) { e in
            XCTAssertEqual(e as? CBORError, .trailingBytes)
        }
    }

    func testTruncatedRejected() {
        XCTAssertThrowsError(try CBORReader.decode(hex("18"))) { e in
            XCTAssertEqual(e as? CBORError, .truncated)
        }
    }

    func testFloatRejectedAsUnsupported() {
        // 0xfa = major 7, additional info 26 (float32) — not in our subset.
        XCTAssertThrowsError(try CBORReader.decode(hex("fa47c35000"))) { e in
            XCTAssertEqual(e as? CBORError, .unsupportedAdditionalInfo(26))
        }
    }
}
