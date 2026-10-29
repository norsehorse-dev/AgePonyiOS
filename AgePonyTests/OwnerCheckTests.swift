//
//  OwnerCheckTests.swift
//  AgePonyTests
//
//  5.1.1 (H-1): the first app password needs a Face ID or passcode check.
//  The UI asks through `requireOwner`; the vault refuses on its own when no
//  prompt succeeded recently. These pin the window and the refusal message.
//

import XCTest
@testable import AgePony

@MainActor
final class OwnerCheckTests: XCTestCase {

    func testNoOwnerCheckAfterLock() {
        BiometricGate.forgetRecentContext()
        XCTAssertFalse(BiometricGate.ownerConfirmed(withinMillis: 3 * 60_000))
    }

    func testZeroWindowNeverConfirms() {
        BiometricGate.forgetRecentContext()
        XCTAssertFalse(BiometricGate.ownerConfirmed(withinMillis: 0))
    }

    func testRefusalMessageNamesTheCheck() {
        let text = UserMessage.text(for: VaultError.ownerCheckNeeded, fallback: "fallback")
        XCTAssertNotEqual(text, "fallback")
        XCTAssertTrue(text.contains("passcode"))
    }
}
