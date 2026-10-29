//
//  BiometricEnrolmentTests.swift
//  AgePonyTests
//
//  5.1.1 (M-3): in Face ID only mode an in-app prompt passes only when the
//  enrolment matches the one kept when the vault opened. These pin the
//  comparison and the kept state's lifetime; the LocalAuthentication side
//  (adding an appearance, then a prompt) needs a device.
//

import XCTest
import Foundation
@testable import AgePony

@MainActor
final class BiometricEnrolmentTests: XCTestCase {

    private let a = Data([0x01, 0x02, 0x03, 0x04])
    private let b = Data([0x01, 0x02, 0x03, 0x05])

    override func tearDown() {
        BiometricGate.forgetUnlockEnrolment()
        super.tearDown()
    }

    func testSameEnrolmentPasses() {
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: a, current: Data(a)), .unchanged)
    }

    func testChangedEnrolmentFails() {
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: a, current: b), .changed)
    }

    func testMissingStateNeverPasses() {
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: nil, current: a), .unknown)
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: a, current: nil), .unknown)
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: nil, current: nil), .unknown)
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: Data(), current: Data()), .unknown)
    }

    func testKeptStateLastsUntilLock() {
        BiometricGate.recordUnlockEnrolment(a)
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: BiometricGate.recordedEnrolment(), current: a), .unchanged)
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: BiometricGate.recordedEnrolment(), current: b), .changed)
        // Vault.lock() calls this.
        BiometricGate.forgetUnlockEnrolment()
        XCTAssertNil(BiometricGate.recordedEnrolment())
        XCTAssertEqual(BiometricGate.compareEnrolment(recorded: BiometricGate.recordedEnrolment(), current: a), .unknown)
        XCTAssertFalse(BiometricGate.takeEnrolmentChangeNotice())
    }

    func testChangedTextNamesTheSecretAndTheCheck() {
        let text = BiometricGate.enrolmentChangedText(noun: "password")
        XCTAssertTrue(text.contains("changed on this iPhone"))
        XCTAssertTrue(text.contains("password"))
        XCTAssertTrue(text.contains("& Passcode"))
    }
}
