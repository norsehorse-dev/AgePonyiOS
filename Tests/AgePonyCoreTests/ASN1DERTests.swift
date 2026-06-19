import XCTest
@testable import AgePonyCore

final class ASN1DERTests: XCTestCase {
    func testIntegerZero() {
        XCTAssertEqual(ASN1DER.integer(Data()), Data([0x02, 0x01, 0x00]))
        XCTAssertEqual(ASN1DER.integer(Data([0x00])), Data([0x02, 0x01, 0x00]))
    }

    func testIntegerSmall() {
        // value 1 → 02 01 01
        XCTAssertEqual(ASN1DER.integer(Data([0x01])), Data([0x02, 0x01, 0x01]))
        // value 0x7f → 02 01 7f
        XCTAssertEqual(ASN1DER.integer(Data([0x7f])), Data([0x02, 0x01, 0x7f]))
    }

    func testIntegerHighBitSet() {
        // value 0x80 → 02 02 00 80 (leading 00 to mark positive)
        XCTAssertEqual(ASN1DER.integer(Data([0x80])), Data([0x02, 0x02, 0x00, 0x80]))
        // value 0xff → 02 02 00 ff
        XCTAssertEqual(ASN1DER.integer(Data([0xff])), Data([0x02, 0x02, 0x00, 0xff]))
    }

    func testIntegerStripsLeadingZeros() {
        // 0x00 0x01 → 02 01 01
        XCTAssertEqual(ASN1DER.integer(Data([0x00, 0x01])), Data([0x02, 0x01, 0x01]))
        // 0x00 0x80 → 02 02 00 80
        XCTAssertEqual(ASN1DER.integer(Data([0x00, 0x80])), Data([0x02, 0x02, 0x00, 0x80]))
    }

    func testLengthShortForm() {
        XCTAssertEqual(ASN1DER.length(0), Data([0x00]))
        XCTAssertEqual(ASN1DER.length(127), Data([0x7f]))
    }

    func testLengthLongForm() {
        XCTAssertEqual(ASN1DER.length(128), Data([0x81, 0x80]))
        XCTAssertEqual(ASN1DER.length(256), Data([0x82, 0x01, 0x00]))
        XCTAssertEqual(ASN1DER.length(1000), Data([0x82, 0x03, 0xe8]))
    }

    func testSequenceEmpty() {
        XCTAssertEqual(ASN1DER.sequence(Data()), Data([0x30, 0x00]))
    }

    func testSequenceWithIntegers() {
        // SEQUENCE { INTEGER 1, INTEGER 2 } → 30 06 02 01 01 02 01 02
        let inner = ASN1DER.integer(Data([0x01])) + ASN1DER.integer(Data([0x02]))
        XCTAssertEqual(ASN1DER.sequence(inner),
                       Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]))
    }

    func testSequenceLongForm() {
        // 200-byte contents → long-form length 0x81 0xc8
        let contents = Data(repeating: 0xab, count: 200)
        let der = ASN1DER.sequence(contents)
        XCTAssertEqual(der.prefix(3), Data([0x30, 0x81, 0xc8]))
        XCTAssertEqual(der.count, 3 + 200)
    }
}
