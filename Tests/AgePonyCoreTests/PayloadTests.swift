//
//  PayloadTests.swift
//  AgePonyCoreTests
//

import XCTest
@testable import AgePonyCore

final class PayloadTests: XCTestCase {

    private func makeFileKey() -> Data {
        Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
    }

    // MARK: - Round-trip across sizes including chunk boundaries

    func testRoundTrip_empty() throws {
        let key = makeFileKey()
        let pt = Data()
        let ct = try AgePayload.encrypt(plaintext: pt, fileKey: key)
        let back = try AgePayload.decrypt(bytes: ct, fileKey: key)
        XCTAssertEqual(back, pt)
        // Empty plaintext still emits one chunk with the final-chunk flag,
        // so the ciphertext is noncePrefix(16) + tag(16) = 32 bytes.
        XCTAssertEqual(ct.count, 32)
    }

    func testRoundTrip_tinyPlaintext() throws {
        let key = makeFileKey()
        let pt = Data("hi".utf8)
        let ct = try AgePayload.encrypt(plaintext: pt, fileKey: key)
        XCTAssertEqual(try AgePayload.decrypt(bytes: ct, fileKey: key), pt)
    }

    func testRoundTrip_oneByteUnderChunkSize() throws {
        let key = makeFileKey()
        let pt = Data((0..<AgePayload.chunkSize - 1).map { UInt8($0 % 256) })
        let ct = try AgePayload.encrypt(plaintext: pt, fileKey: key)
        XCTAssertEqual(try AgePayload.decrypt(bytes: ct, fileKey: key), pt)
    }

    func testRoundTrip_exactlyChunkSize() throws {
        // Boundary case: 64 KiB exactly. Should produce one final chunk
        // with the 0x01 flag, not two chunks (which is also spec-legal but
        // not what our encoder does).
        let key = makeFileKey()
        let pt = Data((0..<AgePayload.chunkSize).map { UInt8($0 % 256) })
        let ct = try AgePayload.encrypt(plaintext: pt, fileKey: key)
        XCTAssertEqual(try AgePayload.decrypt(bytes: ct, fileKey: key), pt)
        // ciphertext layout: 16 nonce + 64KiB + 16 tag = 65568 bytes
        XCTAssertEqual(ct.count, 16 + AgePayload.chunkSize + 16)
    }

    func testRoundTrip_oneByteOverChunkSize() throws {
        let key = makeFileKey()
        let pt = Data((0..<AgePayload.chunkSize + 1).map { UInt8($0 % 256) })
        let ct = try AgePayload.encrypt(plaintext: pt, fileKey: key)
        XCTAssertEqual(try AgePayload.decrypt(bytes: ct, fileKey: key), pt)
        // Two chunks: full + 1-byte. Ciphertext layout:
        // 16 nonce + (64KiB + 16) + (1 + 16) = 65585
        XCTAssertEqual(ct.count, 16 + (AgePayload.chunkSize + 16) + (1 + 16))
    }

    func testRoundTrip_multiChunk() throws {
        let key = makeFileKey()
        let pt = Data((0..<(AgePayload.chunkSize * 3 + 17)).map { UInt8($0 % 256) })
        let ct = try AgePayload.encrypt(plaintext: pt, fileKey: key)
        XCTAssertEqual(try AgePayload.decrypt(bytes: ct, fileKey: key), pt)
    }

    // MARK: - Tamper detection

    func testTamperedCiphertextFailsAuth() throws {
        let key = makeFileKey()
        let pt = Data("a moderately long message".utf8)
        var ct = try AgePayload.encrypt(plaintext: pt, fileKey: key)
        // Flip a bit in the middle of the chunk ciphertext.
        ct[AgePayload.noncePrefixSize + 5] ^= 0x01
        XCTAssertThrowsError(try AgePayload.decrypt(bytes: ct, fileKey: key)) { error in
            XCTAssertEqual(error as? AgePayloadError, .decryptFailed)
        }
    }

    func testWrongFileKeyFailsAuth() throws {
        let realKey = makeFileKey()
        let wrongKey = makeFileKey()
        let pt = Data("secret".utf8)
        let ct = try AgePayload.encrypt(plaintext: pt, fileKey: realKey)
        XCTAssertThrowsError(try AgePayload.decrypt(bytes: ct, fileKey: wrongKey)) { error in
            XCTAssertEqual(error as? AgePayloadError, .decryptFailed)
        }
    }

    func testTooShortCiphertextRejected() {
        let key = makeFileKey()
        let tooShort = Data(repeating: 0, count: 20)  // 16 nonce + 4 < 16 tag
        XCTAssertThrowsError(try AgePayload.decrypt(bytes: tooShort, fileKey: key))
    }

    // MARK: - Nonce construction

    func testChunkNonceCounter() throws {
        let n = try AgePayload.chunkNonce(counter: 0, last: false)
        XCTAssertEqual(Data(n).count, 12)
        // counter 0, not last: all zeros
        XCTAssertEqual(Data(n), Data(repeating: 0, count: 12))
    }

    func testChunkNonceLastFlag() throws {
        let n = try AgePayload.chunkNonce(counter: 0, last: true)
        let expected = Data([0,0,0,0,0,0,0,0,0,0,0,0x01])
        XCTAssertEqual(Data(n), expected)
    }

    func testChunkNonceCounterEncoding() throws {
        let n = try AgePayload.chunkNonce(counter: 0x0102030405060708, last: false)
        // Counter lives in bytes 3..10, big-endian.
        let expected = Data([0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00])
        XCTAssertEqual(Data(n), expected)
    }
}
