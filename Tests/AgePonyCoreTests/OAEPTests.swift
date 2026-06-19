import XCTest
import CryptoKit
@testable import AgePonyCore

final class OAEPTests: XCTestCase {
    /// MGF1 vectors computed offline with Python's `hashlib`:
    ///   MGF1(zeros_32, 32) = SHA-256(zeros_32 || 0x00000000) = 6db65fd5...
    func testMGF1_zeros_32() {
        let seed = Data(repeating: 0, count: 32)
        let out = OAEP.mgf1(seed: seed, length: 32)
        XCTAssertEqual(out.map { String(format: "%02x", $0) }.joined(),
                       "6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e")
    }

    func testMGF1_zeros_64() {
        let seed = Data(repeating: 0, count: 32)
        let out = OAEP.mgf1(seed: seed, length: 64)
        XCTAssertEqual(out.map { String(format: "%02x", $0) }.joined(),
                       "6db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e"
                       + "2158a8906d5e2c2be001bac943ab9cab4063536e1c546b40221fdf8db031a4bb")
    }

    func testMGF1_short_seed() {
        let seed = Data([0x01, 0x02, 0x03, 0x04])
        let out = OAEP.mgf1(seed: seed, length: 16)
        XCTAssertEqual(out.map { String(format: "%02x", $0) }.joined(),
                       "e25f9f0a2c2664632d1be5e2f25b2794")
    }

    func testMGF1_acrossBlocks() {
        // Multi-block output: length 65 (3 SHA-256 calls, take 65 of 96 bytes)
        let seed = Data([0x01, 0x02, 0x03, 0x04])
        let out = OAEP.mgf1(seed: seed, length: 65)
        XCTAssertEqual(out.count, 65)
        XCTAssertEqual(out.map { String(format: "%02x", $0) }.joined(),
                       "e25f9f0a2c2664632d1be5e2f25b2794c371091b61eb762ad98861da3a2221ee"
                       + "366dcb38806a930d052d8b7bac72a4e59bbe8a78792b4d975ed944dc0f64f6e5c3")
    }

    func testRoundTrip_shortMessage() throws {
        let message = Data("hello age".utf8)
        let label = Data("age-encryption.org/v1/ssh-rsa".utf8)
        let em = try OAEP.encode(message: message, label: label, k: 256)
        XCTAssertEqual(em.count, 256)
        let recovered = try OAEP.decode(encoded: em, label: label)
        XCTAssertEqual(recovered, message)
    }

    func testRoundTrip_fileKeySize() throws {
        // age file_key is 16 bytes
        let message = Data(repeating: 0x33, count: 16)
        let label = Data("age-encryption.org/v1/ssh-rsa".utf8)
        let em = try OAEP.encode(message: message, label: label, k: 256)
        let recovered = try OAEP.decode(encoded: em, label: label)
        XCTAssertEqual(recovered, message)
    }

    func testRoundTrip_emptyMessage() throws {
        let label = Data("age-encryption.org/v1/ssh-rsa".utf8)
        let em = try OAEP.encode(message: Data(), label: label, k: 256)
        let recovered = try OAEP.decode(encoded: em, label: label)
        XCTAssertEqual(recovered, Data())
    }

    func testEncode_messageTooLong() {
        let label = Data()
        // For k=256, max message = 256 - 2*32 - 2 = 190 bytes
        let tooLong = Data(repeating: 0, count: 191)
        XCTAssertThrowsError(try OAEP.encode(message: tooLong, label: label, k: 256))
    }

    func testDecode_wrongLabel() throws {
        let message = Data("hello".utf8)
        let labelA = Data("label-a".utf8)
        let labelB = Data("label-b".utf8)
        let em = try OAEP.encode(message: message, label: labelA, k: 256)
        XCTAssertThrowsError(try OAEP.decode(encoded: em, label: labelB))
    }

    func testDecode_corruptedFirstByte() throws {
        let message = Data("hello".utf8)
        let label = Data()
        var em = try OAEP.encode(message: message, label: label, k: 256)
        em[em.startIndex] = 0x01  // should be 0x00
        XCTAssertThrowsError(try OAEP.decode(encoded: em, label: label))
    }

    func testDeterministicEncode_withFixedSeed() throws {
        // Same seed + same inputs → same output (we can use this to compare against Python ref)
        let message = Data("hi".utf8)
        let label = Data("age-encryption.org/v1/ssh-rsa".utf8)
        let seed = Data(repeating: 0x77, count: 32)
        let em1 = try OAEP.encode(message: message, label: label, k: 256, seed: seed)
        let em2 = try OAEP.encode(message: message, label: label, k: 256, seed: seed)
        XCTAssertEqual(em1, em2)
        // And it should still decode
        let recovered = try OAEP.decode(encoded: em1, label: label)
        XCTAssertEqual(recovered, message)
    }
}
