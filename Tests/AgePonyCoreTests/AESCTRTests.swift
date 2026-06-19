import XCTest
@testable import AgePonyCore

final class AESCTRTests: XCTestCase {
    /// AES-256-CTR with the canonical RFC 3686 inputs, but using pure CTR semantics
    /// (the whole 16-byte IV as a big-endian 128-bit counter). Output verified
    /// against Python's `cryptography.hazmat.primitives.ciphers.modes.CTR`.
    func testAES256CTR_referenceVector() throws {
        let key = Data([
            0x77, 0x6B, 0xEF, 0xF2, 0x85, 0x1D, 0xB0, 0x6F,
            0x4C, 0x8A, 0x05, 0x42, 0xC8, 0x69, 0x6F, 0x6C,
            0x6A, 0x81, 0xAF, 0x1E, 0xEC, 0x96, 0xB4, 0xD3,
            0x7F, 0xC1, 0xD6, 0x89, 0xE6, 0xC1, 0xC1, 0x04,
        ])
        let iv = Data([
            0x00, 0x00, 0x00, 0x60, 0xDB, 0x56, 0x72, 0xC9,
            0x7A, 0xA8, 0xF0, 0xB2, 0x00, 0x00, 0x00, 0x01,
        ])
        var pt = Data()
        for i: UInt8 in 0...35 { pt.append(i) }
        let ct = try AESCTR.process(key: key, iv: iv, input: pt)
        XCTAssertEqual(ct.map { String(format: "%02x", $0) }.joined(),
                       "4732bc79d7e268a2326e0abc5d839da86390791668fda74460ad29c701c1e955725e37b8")
    }

    func testAES256CTR_roundTrip() throws {
        let key = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let iv  = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let pt  = Data((0..<200).map { _ in UInt8.random(in: 0...255) })
        let ct  = try AESCTR.process(key: key, iv: iv, input: pt)
        let back = try AESCTR.process(key: key, iv: iv, input: ct)  // CTR is symmetric
        XCTAssertEqual(back, pt)
    }

    func testAES128CTR_roundTrip() throws {
        let key = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let iv  = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let pt  = Data("hello AES-128-CTR\n".utf8)
        let ct  = try AESCTR.process(key: key, iv: iv, input: pt)
        let back = try AESCTR.process(key: key, iv: iv, input: ct)
        XCTAssertEqual(back, pt)
    }

    func testRejectsWrongKeySize() {
        let pt = Data(repeating: 0, count: 16)
        let iv = Data(repeating: 0, count: 16)
        XCTAssertThrowsError(try AESCTR.process(
            key: Data(repeating: 0, count: 24),  // AES-192 not supported here
            iv: iv, input: pt))
    }

    /// Output length should equal input length (CTR is a stream cipher — no padding).
    func testOutputLengthEqualsInputLength() throws {
        let key = Data(repeating: 0x11, count: 32)
        let iv  = Data(repeating: 0x22, count: 16)
        for n in [1, 8, 15, 16, 17, 100, 999] {
            let pt = Data(repeating: 0x33, count: n)
            let ct = try AESCTR.process(key: key, iv: iv, input: pt)
            XCTAssertEqual(ct.count, n)
        }
    }
}
