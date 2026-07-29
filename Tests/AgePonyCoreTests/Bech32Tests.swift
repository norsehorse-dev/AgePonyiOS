//
//  Bech32Tests.swift
//  AgePonyCoreTests
//

import XCTest
@testable import AgePonyCore

final class Bech32Tests: XCTestCase {

    // MARK: - Round-trip

    func testByteRoundTrip() throws {
        // Note: BIP-0173 caps the total encoded string at 90 chars. With a 3-char
        // HRP ("age") + "1" + 6 checksum = 10 overhead chars, the data section
        // holds at most 80 5-bit groups, which encodes ~50 bytes of payload.
        // age never approaches this — recipients/identities are 32 bytes.
        for length in [1, 16, 32, 33, 50] {
            let bytes = (0..<length).map { UInt8($0) }
            let encoded = Bech32.encodeBytes(hrp: "age", bytes: bytes)
            let (hrp, decoded) = try Bech32.decodeBytes(encoded)
            XCTAssertEqual(hrp, "age", "length=\(length)")
            XCTAssertEqual(decoded, bytes, "length=\(length)")
        }
    }

    func testAllZeroRoundTrip() throws {
        let bytes = [UInt8](repeating: 0, count: 32)
        let encoded = Bech32.encodeBytes(hrp: "age", bytes: bytes)
        let (_, decoded) = try Bech32.decodeBytes(encoded)
        XCTAssertEqual(decoded, bytes)
    }

    func testAllOnesRoundTrip() throws {
        let bytes = [UInt8](repeating: 0xff, count: 32)
        let encoded = Bech32.encodeBytes(hrp: "age", bytes: bytes)
        let (_, decoded) = try Bech32.decodeBytes(encoded)
        XCTAssertEqual(decoded, bytes)
    }

    // MARK: - Case handling

    func testLowercaseHRPProducesLowercaseOutput() {
        let encoded = Bech32.encodeBytes(hrp: "age", bytes: [0x00, 0x01, 0x02])
        XCTAssertEqual(encoded, encoded.lowercased())
        XCTAssertTrue(encoded.hasPrefix("age1"))
    }

    func testUppercaseHRPProducesUppercaseOutput() {
        let encoded = Bech32.encodeBytes(hrp: "AGE-SECRET-KEY-", bytes: [0x00, 0x01, 0x02])
        XCTAssertEqual(encoded, encoded.uppercased())
        XCTAssertTrue(encoded.hasPrefix("AGE-SECRET-KEY-1"))
    }

    func testMixedCaseRejected() {
        XCTAssertThrowsError(
            try Bech32.decode("Age1qpzry9x8gf2tvdw0s3jn54khce6mua7l")
        ) { error in
            XCTAssertEqual(error as? Bech32Error, .mixedCase)
        }
    }

    // MARK: - BIP-0173 valid vectors

    func testValidBIP0173Strings() {
        let valid = [
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl"
        ]
        for s in valid {
            XCTAssertNoThrow(try Bech32.decode(s), "should accept \(s)")
        }
    }

    // MARK: - BIP-0173 invalid vectors

    func testInvalidBIP0173Strings() {
        let invalid = [
            " 1nwldj5",                                         // HRP char < 33
            "abc1\u{007F}",                                     // body char out of charset
            "pzry9x0s0muk",                                     // no separator
            "1pzry9x0s0muk",                                    // empty HRP
            "x1b4n0q5v",                                        // invalid character in body
            "li1dgmt3",                                         // too short
            "A1G7SGD8",                                         // checksum mismatch
            "10a06t8",                                          // empty HRP
            "1qzzfhee"                                          // empty HRP
        ]
        for s in invalid {
            XCTAssertThrowsError(try Bech32.decode(s), "should reject: \(s)")
        }
    }

    /// BIP-0173 lists this vector as invalid, and AgePony deliberately accepts it.
    ///
    /// It is well-formed in every other respect — legal HRP characters, valid
    /// checksum — and is rejected by the spec purely because the whole string is
    /// 91 characters, one past BIP-0173's 90-character cap. age applies no such
    /// cap: a post-quantum `age1pq1...` recipient encodes 1216 bytes and runs to
    /// 1959 characters, so honouring the cap would make post-quantum recipients
    /// undecodable. `Bech32.maxLength` is a sanity bound on pathological input,
    /// not a spec limit. The Android implementation makes the same choice.
    func testAcceptsStringsPastTheBIP0173LengthCap() {
        let past90 = "an84characterslonghumanreadablepartthatcontainsthenumber1"
            + "andtheexcludedcharactersbio1569pvx"
        XCTAssertEqual(past90.count, 91)
        XCTAssertNoThrow(try Bech32.decode(past90))
    }

    /// The sanity bound is still enforced.
    func testRejectsStringsPastTheSanityCap() {
        let absurd = "age1" + String(repeating: "q", count: Bech32.maxLength)
        XCTAssertThrowsError(try Bech32.decode(absurd)) { error in
            XCTAssertEqual(error as? Bech32Error, .stringTooLong)
        }
    }

    // MARK: - convertBits

    func testConvertBitsRoundTrip() throws {
        let original: [UInt8] = (0..<64).map { UInt8($0) }
        let fiveBit = try Bech32.convertBits(original, fromBits: 8, toBits: 5, pad: true)
        let back = try Bech32.convertBits(fiveBit, fromBits: 5, toBits: 8, pad: false)
        XCTAssertEqual(back.count, original.count)
        XCTAssertEqual(back, original)
    }

    // MARK: - age recipients

    func testAgeRecipientPrefix() {
        let pub = [UInt8](repeating: 0xAB, count: 32)
        let recipient = Bech32.encodeAgeRecipient(pub)
        XCTAssertTrue(recipient.hasPrefix("age1"))
    }

    func testAgeRecipientRoundTrip() throws {
        let pub: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...UInt8.max) }
        let recipient = Bech32.encodeAgeRecipient(pub)
        let decoded = try Bech32.decodeAgeRecipient(recipient)
        XCTAssertEqual(decoded, pub)
    }

    func testAgeIdentityPrefix() {
        let sec = [UInt8](repeating: 0xCD, count: 32)
        let identity = Bech32.encodeAgeIdentity(sec)
        XCTAssertTrue(identity.hasPrefix("AGE-SECRET-KEY-1"))
    }

    func testAgeIdentityRoundTrip() throws {
        let sec: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...UInt8.max) }
        let identity = Bech32.encodeAgeIdentity(sec)
        let decoded = try Bech32.decodeAgeIdentity(identity)
        XCTAssertEqual(decoded, sec)
    }

    func testAgeRecipientRejectsWrongLength() {
        let badShort = Bech32.encodeBytes(hrp: "age", bytes: [UInt8](repeating: 0, count: 16))
        XCTAssertThrowsError(try Bech32.decodeAgeRecipient(badShort))
        let badLong = Bech32.encodeBytes(hrp: "age", bytes: [UInt8](repeating: 0, count: 64))
        XCTAssertThrowsError(try Bech32.decodeAgeRecipient(badLong))
    }

    func testAgeRecipientRejectsWrongHRP() {
        let wrongHRP = Bech32.encodeBytes(hrp: "abc", bytes: [UInt8](repeating: 0, count: 32))
        XCTAssertThrowsError(try Bech32.decodeAgeRecipient(wrongHRP))
    }

    // MARK: - Known fixed vectors

    func testKnownAllZeroRecipientShape() {
        // 32 zero bytes → padded 5-bit groups → 52 chars data + 6 chars checksum + "age1" prefix.
        let pub = [UInt8](repeating: 0, count: 32)
        let recipient = Bech32.encodeAgeRecipient(pub)
        XCTAssertTrue(recipient.hasPrefix("age1"))
        XCTAssertEqual(recipient.count, 4 + 52 + 6)
    }
}
