//
//  StanzaTests.swift
//  AgePonyCoreTests
//

import XCTest
@testable import AgePonyCore

final class StanzaTests: XCTestCase {

    // MARK: - Serialization

    func testSerializeSimpleStanza() {
        let st = Stanza(type: "X25519", args: ["aGVsbG8"], body: Data([0xde, 0xad, 0xbe, 0xef]))
        let s = st.serialize()
        XCTAssertEqual(s, "-> X25519 aGVsbG8\n3q2+7w")
    }

    func testSerializeMultipleArgs() {
        let st = Stanza(type: "scrypt", args: ["AAAAAAAAAAAAAAAAAAAAAA", "18"], body: Data([0x01, 0x02, 0x03]))
        let s = st.serialize()
        XCTAssertEqual(s, "-> scrypt AAAAAAAAAAAAAAAAAAAAAA 18\nAQID")
    }

    func testSerializeBody64BytesAddsEmptyTerminator() {
        // 48 raw bytes encodes to exactly 64 base64 chars; spec requires an
        // empty terminator line so the body length is unambiguous.
        let body = Data(repeating: 0xAB, count: 48)
        let st = Stanza(type: "X", args: [], body: body)
        let s = st.serialize()
        let lines = s.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(lines.count, 3)
        XCTAssertEqual(lines[0], "-> X")
        XCTAssertEqual(lines[1].count, 64)
        XCTAssertEqual(lines[2], "")
    }

    func testSerializeWrapsLongBody() {
        let body = Data(repeating: 0xCD, count: 100)
        let st = Stanza(type: "X", args: [], body: body)
        let s = st.serialize()
        let lines = s.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(lines[0], "-> X")
        // 100 bytes = 134 base64 chars without padding → 64 + 64 + 6 → 2 full + 1 short = 3 lines
        // Wait: 100 bytes → ceil(100 * 4 / 3) - padding = 134 raw, but unpadded it's still 134.
        // 134 / 64 = 2 r 6, so lines: 64, 64, 6 (3 lines, last is short)
        XCTAssertEqual(lines[1].count, 64)
        XCTAssertEqual(lines[2].count, 64)
        XCTAssertEqual(lines[3].count, 6)
    }

    // MARK: - Parsing

    func testParseSimpleStanza() throws {
        let lines = ["-> X25519 aGVsbG8", "3q2+7w"]
        var idx = 0
        let st = try Stanza.parse(lines: lines, index: &idx)
        XCTAssertEqual(st.type, "X25519")
        XCTAssertEqual(st.args, ["aGVsbG8"])
        XCTAssertEqual(st.body, Data([0xde, 0xad, 0xbe, 0xef]))
        XCTAssertEqual(idx, 2)
    }

    func testParseMultipleArgs() throws {
        let lines = ["-> scrypt AAAAAAAAAAAAAAAAAAAAAA 18", "AQID"]
        var idx = 0
        let st = try Stanza.parse(lines: lines, index: &idx)
        XCTAssertEqual(st.type, "scrypt")
        XCTAssertEqual(st.args, ["AAAAAAAAAAAAAAAAAAAAAA", "18"])
        XCTAssertEqual(st.body, Data([0x01, 0x02, 0x03]))
    }

    func testParseEmptyBody() throws {
        let lines = ["-> X", "", "-> next"]
        var idx = 0
        let st = try Stanza.parse(lines: lines, index: &idx)
        XCTAssertEqual(st.type, "X")
        XCTAssertEqual(st.body.count, 0)
        XCTAssertEqual(idx, 2)
    }

    func testParseRejectsMissingArrow() {
        let lines = ["X25519 aGVsbG8", "3q2+7w"]
        var idx = 0
        XCTAssertThrowsError(try Stanza.parse(lines: lines, index: &idx)) { error in
            XCTAssertEqual(error as? StanzaError, .missingArrow)
        }
    }

    func testParseRejectsBodyLineTooLong() {
        // 65-char body line is invalid.
        let longLine = String(repeating: "A", count: 65)
        let lines = ["-> X", longLine, "short"]
        var idx = 0
        XCTAssertThrowsError(try Stanza.parse(lines: lines, index: &idx)) { error in
            XCTAssertEqual(error as? StanzaError, .bodyLineTooLong)
        }
    }

    // MARK: - Round-trip

    func testStanzaRoundTrip() throws {
        for bodyLen in [0, 1, 16, 32, 47, 48, 49, 95, 96, 97, 200] {
            let body = Data((0..<bodyLen).map { UInt8($0 % 256) })
            let original = Stanza(type: "X25519", args: ["abc"], body: body)
            let serialized = original.serialize()
            let lines = serialized.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            var idx = 0
            let parsed = try Stanza.parse(lines: lines, index: &idx)
            XCTAssertEqual(parsed.type, original.type, "bodyLen=\(bodyLen)")
            XCTAssertEqual(parsed.args, original.args, "bodyLen=\(bodyLen)")
            XCTAssertEqual(parsed.body, original.body, "bodyLen=\(bodyLen)")
        }
    }
}
