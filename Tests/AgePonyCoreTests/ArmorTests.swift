//
//  ArmorTests.swift
//  AgePonyCoreTests
//

import XCTest
@testable import AgePonyCore

final class ArmorTests: XCTestCase {

    func testEncodeWrapsAt64Chars() {
        let bytes = Data((0..<150).map { UInt8($0) })
        let armored = AgeArmor.encode(bytes)
        let lines = armored.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(lines.first, "-----BEGIN AGE ENCRYPTED FILE-----")
        let body = lines[1..<(lines.count - 2)]  // skip begin, end, trailing empty
        for line in body.dropLast() {
            XCTAssertEqual(line.count, 64, "non-final body lines must be exactly 64 chars")
        }
    }

    func testRoundTrip() throws {
        for size in [0, 1, 47, 48, 49, 64, 100, 4096, 65537] {
            let original = Data((0..<size).map { UInt8($0 % 256) })
            let armored = AgeArmor.encode(original)
            let decoded = try AgeArmor.decode(armored)
            XCTAssertEqual(decoded, original, "size=\(size)")
        }
    }

    func testDecodeTolerantToLeadingTrailingWhitespace() throws {
        let bytes = Data("hello world".utf8)
        let armored = AgeArmor.encode(bytes)
        let padded = "\n\n  \n" + armored + "\n  \n"
        XCTAssertEqual(try AgeArmor.decode(padded), bytes)
    }

    func testDecodeAcceptsCRLF() throws {
        let bytes = Data("hello world".utf8)
        let armored = AgeArmor.encode(bytes)
        let crlf = armored.replacingOccurrences(of: "\n", with: "\r\n")
        XCTAssertEqual(try AgeArmor.decode(crlf), bytes)
    }

    func testDecodeRejectsMissingBegin() {
        let text = "no markers here\njust some base64 maybe\n-----END AGE ENCRYPTED FILE-----\n"
        XCTAssertThrowsError(try AgeArmor.decode(text)) { error in
            XCTAssertEqual(error as? AgeArmorError, .missingBeginMarker)
        }
    }

    func testDecodeRejectsMissingEnd() {
        let text = "-----BEGIN AGE ENCRYPTED FILE-----\nABCD\n"
        XCTAssertThrowsError(try AgeArmor.decode(text)) { error in
            XCTAssertEqual(error as? AgeArmorError, .missingEndMarker)
        }
    }

    func testDecodeRejectsExtraneousContentOutsideMarkers() {
        let bytes = Data("hello".utf8)
        let armored = AgeArmor.encode(bytes)
        let polluted = "some junk\n" + armored
        XCTAssertThrowsError(try AgeArmor.decode(polluted)) { error in
            XCTAssertEqual(error as? AgeArmorError, .extraDataOutsideArmor)
        }
    }

    func testLooksArmoredHeuristic() {
        let armored = AgeArmor.encode(Data("x".utf8))
        XCTAssertTrue(AgeArmor.looksArmored(armored))
        XCTAssertFalse(AgeArmor.looksArmored("just some random text"))
    }
}
