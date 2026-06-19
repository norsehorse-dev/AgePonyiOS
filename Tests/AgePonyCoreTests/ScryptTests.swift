//
//  ScryptTests.swift
//  AgePonyCoreTests
//
//  Test vectors from RFC 7914 Section 12 (scrypt) and Section 11 (PBKDF2-HMAC-SHA256).
//
//  Vectors 2-4 are SLOW. They are intentionally always-on because correctness
//  matters more than CI time for a crypto primitive. Vector 4 (N=2^20) requires
//  ~1 GiB of RAM and takes ~30-60s on Apple Silicon — only run when manually
//  verifying against the spec.
//

import XCTest
@testable import AgePonyCore

final class ScryptTests: XCTestCase {

    // MARK: - RFC 7914 Section 12 scrypt vectors

    func testRFCVector1_EmptyInputs_N16_r1_p1() throws {
        let result = try Scrypt.scrypt(
            password: [],
            salt: [],
            n: 16, r: 1, p: 1, dkLen: 64
        )
        let expected: [UInt8] = [
            0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20,
            0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
            0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
            0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
            0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
            0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
            0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
            0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06
        ]
        XCTAssertEqual(result, expected)
    }

    func testRFCVector2_Password_NaCl_N1024_r8_p16() throws {
        let result = try Scrypt.scrypt(
            password: Array("password".utf8),
            salt: Array("NaCl".utf8),
            n: 1024, r: 8, p: 16, dkLen: 64
        )
        let expected: [UInt8] = [
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
            0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
            0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
            0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
            0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
            0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
            0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40
        ]
        XCTAssertEqual(result, expected)
    }

    func testRFCVector3_PleaseLetMeIn_SodiumChloride_N16384_r8_p1() throws {
        let result = try Scrypt.scrypt(
            password: Array("pleaseletmein".utf8),
            salt: Array("SodiumChloride".utf8),
            n: 16384, r: 8, p: 1, dkLen: 64
        )
        let expected: [UInt8] = [
            0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48,
            0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
            0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e,
            0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
            0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf,
            0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
            0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40,
            0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87
        ]
        XCTAssertEqual(result, expected)
    }

    // RFC Vector 4 (N=2^20) requires ~1 GiB RAM and ~30-60s.
    // Renamed off the `test` prefix so XCTest skips it by default. To run it,
    // rename to `testRFCVector4_...` and execute manually.
    func _testRFCVector4_PleaseLetMeIn_SodiumChloride_N1048576_r8_p1() throws {
        let result = try Scrypt.scrypt(
            password: Array("pleaseletmein".utf8),
            salt: Array("SodiumChloride".utf8),
            n: 1048576, r: 8, p: 1, dkLen: 64
        )
        let expected: [UInt8] = [
            0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae,
            0xad, 0xdb, 0xbe, 0x09, 0xcf, 0x70, 0xf8, 0x81,
            0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d,
            0xab, 0xe5, 0xee, 0x98, 0x20, 0xad, 0xaa, 0x47,
            0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f,
            0xfa, 0x1c, 0x6d, 0x92, 0x7c, 0x40, 0xf4, 0xc3,
            0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb,
            0xcb, 0xf4, 0x5c, 0x6f, 0xa7, 0x7a, 0x41, 0xa4
        ]
        XCTAssertEqual(result, expected)
    }

    // MARK: - PBKDF2-HMAC-SHA256 vectors (RFC 7914 Section 11)

    func testPBKDF2VectorA_passwd_salt_c1_dkLen64() {
        let result = Scrypt.pbkdf2HmacSha256(
            password: Array("passwd".utf8),
            salt: Array("salt".utf8),
            iterations: 1,
            dkLen: 64
        )
        let expected: [UInt8] = [
            0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
            0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
            0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
            0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
            0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45,
            0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
            0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
            0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83
        ]
        XCTAssertEqual(result, expected)
    }

    func testPBKDF2VectorB_Password_NaCl_c80000_dkLen64() {
        let result = Scrypt.pbkdf2HmacSha256(
            password: Array("Password".utf8),
            salt: Array("NaCl".utf8),
            iterations: 80000,
            dkLen: 64
        )
        let expected: [UInt8] = [
            0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21,
            0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9,
            0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14,
            0xae, 0xff, 0x08, 0x87, 0x6b, 0x34, 0xab, 0x56,
            0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54,
            0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17,
            0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
            0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d
        ]
        XCTAssertEqual(result, expected)
    }

    // MARK: - Parameter validation

    func testInvalidN_NotPowerOfTwo() {
        XCTAssertThrowsError(
            try Scrypt.scrypt(password: [], salt: [], n: 15, r: 1, p: 1, dkLen: 32)
        ) { error in
            XCTAssertEqual(error as? Scrypt.ScryptError, .invalidN)
        }
    }

    func testInvalidN_One() {
        XCTAssertThrowsError(
            try Scrypt.scrypt(password: [], salt: [], n: 1, r: 1, p: 1, dkLen: 32)
        ) { error in
            XCTAssertEqual(error as? Scrypt.ScryptError, .invalidN)
        }
    }

    func testInvalidR_Zero() {
        XCTAssertThrowsError(
            try Scrypt.scrypt(password: [], salt: [], n: 16, r: 0, p: 1, dkLen: 32)
        ) { error in
            XCTAssertEqual(error as? Scrypt.ScryptError, .invalidRP)
        }
    }

    func testInvalidDkLen_Zero() {
        XCTAssertThrowsError(
            try Scrypt.scrypt(password: [], salt: [], n: 16, r: 1, p: 1, dkLen: 0)
        ) { error in
            XCTAssertEqual(error as? Scrypt.ScryptError, .invalidDkLen)
        }
    }

    // MARK: - age wrap key

    func testAgeWrapKeyLength() throws {
        let salt = [UInt8](repeating: 0, count: 16)
        let key = try Scrypt.ageWrapKey(passphrase: "test", stanzaSalt: salt, workFactor: 1)
        XCTAssertEqual(key.count, 32)
    }

    func testAgeWrapKeyRejectsBadSaltLength() {
        XCTAssertThrowsError(
            try Scrypt.ageWrapKey(
                passphrase: "test",
                stanzaSalt: [UInt8](repeating: 0, count: 15),
                workFactor: 1
            )
        ) { error in
            XCTAssertEqual(error as? Scrypt.ScryptError, .invalidRP)
        }
    }

    func testAgeWrapKeyRejectsWorkFactorZero() {
        let salt = [UInt8](repeating: 0, count: 16)
        XCTAssertThrowsError(
            try Scrypt.ageWrapKey(passphrase: "test", stanzaSalt: salt, workFactor: 0)
        ) { error in
            XCTAssertEqual(error as? Scrypt.ScryptError, .invalidN)
        }
    }

    func testAgeWrapKeyDeterministic() throws {
        let salt = [UInt8](repeating: 0x42, count: 16)
        let key1 = try Scrypt.ageWrapKey(passphrase: "hello", stanzaSalt: salt, workFactor: 4)
        let key2 = try Scrypt.ageWrapKey(passphrase: "hello", stanzaSalt: salt, workFactor: 4)
        XCTAssertEqual(key1, key2)
    }

    func testAgeWrapKeyDifferentPassphrases() throws {
        let salt = [UInt8](repeating: 0x42, count: 16)
        let key1 = try Scrypt.ageWrapKey(passphrase: "hello", stanzaSalt: salt, workFactor: 4)
        let key2 = try Scrypt.ageWrapKey(passphrase: "world", stanzaSalt: salt, workFactor: 4)
        XCTAssertNotEqual(key1, key2)
    }

    func testAgeWrapKeyDifferentSalts() throws {
        let salt1 = [UInt8](repeating: 0x01, count: 16)
        let salt2 = [UInt8](repeating: 0x02, count: 16)
        let key1 = try Scrypt.ageWrapKey(passphrase: "hello", stanzaSalt: salt1, workFactor: 4)
        let key2 = try Scrypt.ageWrapKey(passphrase: "hello", stanzaSalt: salt2, workFactor: 4)
        XCTAssertNotEqual(key1, key2)
    }
}
