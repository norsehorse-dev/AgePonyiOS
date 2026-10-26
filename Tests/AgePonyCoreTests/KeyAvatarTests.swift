//
//  KeyAvatarTests.swift
//  AgePonyCoreTests
//
//  Pins the FNV-1a hue and the initials rule to Android's `KeyAvatar.kt`, so the
//  same seed produces the same hue on both platforms. Golden values computed by
//  tools/... the same 32-bit FNV-1a Android uses.
//

import XCTest
@testable import AgePonyCore

final class KeyAvatarTests: XCTestCase {

    func testHueMatchesAndroidFNV1a() {
        XCTAssertEqual(KeyAvatar.hue(seed: ""), 61)
        XCTAssertEqual(KeyAvatar.hue(seed: "AAAA"), 17)
        XCTAssertEqual(KeyAvatar.hue(seed: "age1qexamplekey"), 259)
        XCTAssertEqual(KeyAvatar.hue(seed: "n2t7Yg9k3Fh0"), 25)
        XCTAssertEqual(KeyAvatar.hue(seed: "hello world key"), 212)
    }

    func testHueIsStableAndInRange() {
        for seed in ["a", "somekey", "age1yubikey1qtscft5p2gtxe0"] {
            let h = KeyAvatar.hue(seed: seed)
            XCTAssertTrue((0..<360).contains(h))
            XCTAssertEqual(h, KeyAvatar.hue(seed: seed)) // deterministic
        }
    }

    func testInitials() {
        XCTAssertEqual(KeyAvatar.initials(name: "Work"), "WO")
        XCTAssertEqual(KeyAvatar.initials(name: "Ada Lovelace"), "AL")
        XCTAssertEqual(KeyAvatar.initials(name: "primary key"), "PK")
        XCTAssertEqual(KeyAvatar.initials(name: "   "), "?")
        XCTAssertEqual(KeyAvatar.initials(name: ""), "?")
        XCTAssertEqual(KeyAvatar.initials(name: "x"), "X")
    }
}
