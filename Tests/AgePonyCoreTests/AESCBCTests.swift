import XCTest
@testable import AgePonyCore

final class AESCBCTests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return d
    }

    /// Independent vector generated with Python `cryptography`:
    /// AES-256-CBC, key 00..1f, zero IV, no padding, PT 40..4f.
    func testAES256CBC_referenceVector() throws {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let iv  = Data(repeating: 0, count: 16)
        let pt  = hex("404142434445464748494a4b4c4d4e4f")
        let ct  = try AESCBC.encrypt(key: key, iv: iv, input: pt)
        XCTAssertEqual(ct.map { String(format: "%02x", $0) }.joined(),
                       "a37edf3f975abaef937b62c78d5bb157")
    }

    func testAES256CBC_roundTrip() throws {
        let key = Data((0..<32).map { UInt8($0) })
        let iv  = Data(repeating: 0, count: 16)
        let pt  = Data((0..<32).map { UInt8(0xA0 &+ $0) })   // two blocks
        let ct  = try AESCBC.encrypt(key: key, iv: iv, input: pt)
        let back = try AESCBC.decrypt(key: key, iv: iv, input: ct)
        XCTAssertEqual(back, pt)
        XCTAssertNotEqual(ct, pt)
    }

    func testRejectsNonBlockAlignedInput() {
        let key = Data(repeating: 0, count: 32)
        let iv  = Data(repeating: 0, count: 16)
        XCTAssertThrowsError(try AESCBC.encrypt(key: key, iv: iv, input: Data(repeating: 1, count: 17)))
    }

    func testRejectsWrongKeySize() {
        let iv = Data(repeating: 0, count: 16)
        XCTAssertThrowsError(try AESCBC.encrypt(
            key: Data(repeating: 0, count: 24), iv: iv, input: Data(repeating: 0, count: 16)))
    }

    func testRejectsWrongIVSize() {
        XCTAssertThrowsError(try AESCBC.encrypt(
            key: Data(repeating: 0, count: 32),
            iv: Data(repeating: 0, count: 12),
            input: Data(repeating: 0, count: 16)))
    }
}
