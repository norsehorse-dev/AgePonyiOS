//
//  SSHWireFormatTests.swift
//  AgePonyCoreTests
//

import XCTest
@testable import AgePonyCore

final class SSHWireFormatTests: XCTestCase {

    // MARK: - Reader

    func testReadByte() throws {
        var r = SSHWireReader(Data([0x42, 0x99]))
        XCTAssertEqual(try r.readByte(), 0x42)
        XCTAssertEqual(try r.readByte(), 0x99)
        XCTAssertThrowsError(try r.readByte())
    }

    func testReadUInt32() throws {
        var r = SSHWireReader(Data([0x12, 0x34, 0x56, 0x78]))
        XCTAssertEqual(try r.readUInt32(), 0x12_34_56_78)
        XCTAssertTrue(r.isAtEnd)
    }

    func testReadUInt32_truncated() {
        var r = SSHWireReader(Data([0x12, 0x34]))
        XCTAssertThrowsError(try r.readUInt32())
    }

    func testReadString() throws {
        // 4-byte BE length 3, then "abc"
        var r = SSHWireReader(Data([0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63]))
        XCTAssertEqual(try r.readString(), Data([0x61, 0x62, 0x63]))
        XCTAssertTrue(r.isAtEnd)
    }

    func testReadString_lengthExceedsRemaining() {
        // Says length is 100 but we only have a few bytes after.
        var r = SSHWireReader(Data([0x00, 0x00, 0x00, 0x64, 0x61, 0x62, 0x63]))
        XCTAssertThrowsError(try r.readString())
    }

    func testReadString_empty() throws {
        var r = SSHWireReader(Data([0x00, 0x00, 0x00, 0x00]))
        XCTAssertEqual(try r.readString(), Data())
    }

    func testReadBytes() throws {
        var r = SSHWireReader(Data([0xaa, 0xbb, 0xcc, 0xdd, 0xee]))
        XCTAssertEqual(try r.readBytes(3), Data([0xaa, 0xbb, 0xcc]))
        XCTAssertEqual(try r.readBytes(2), Data([0xdd, 0xee]))
    }

    // MARK: - Writer

    func testWriterUInt32() {
        var w = SSHWireWriter()
        w.writeUInt32(0x12_34_56_78)
        XCTAssertEqual(w.data, Data([0x12, 0x34, 0x56, 0x78]))
    }

    func testWriterString() {
        var w = SSHWireWriter()
        w.writeString(Data([0x61, 0x62, 0x63]))
        XCTAssertEqual(w.data, Data([0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63]))
    }

    func testWriterEmptyString() {
        var w = SSHWireWriter()
        w.writeString(Data())
        XCTAssertEqual(w.data, Data([0x00, 0x00, 0x00, 0x00]))
    }

    func testWriterStringByteValue() {
        var w = SSHWireWriter()
        w.writeByte(0xff)
        XCTAssertEqual(w.data, Data([0xff]))
    }

    // MARK: - Round-trip

    func testRoundTrip() throws {
        var w = SSHWireWriter()
        w.writeString("ssh-ed25519")
        w.writeString(Data(repeating: 0xab, count: 32))
        w.writeUInt32(0xdead_beef)
        w.writeByte(0x42)

        var r = SSHWireReader(w.data)
        XCTAssertEqual(String(data: try r.readString(), encoding: .utf8), "ssh-ed25519")
        XCTAssertEqual(try r.readString(), Data(repeating: 0xab, count: 32))
        XCTAssertEqual(try r.readUInt32(), 0xdead_beef)
        XCTAssertEqual(try r.readByte(), 0x42)
        XCTAssertTrue(r.isAtEnd)
    }
}
