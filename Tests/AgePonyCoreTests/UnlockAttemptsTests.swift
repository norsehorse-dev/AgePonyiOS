//
//  UnlockAttemptsTests.swift
//  AgePonyCoreTests
//
//  The failed-attempt backoff (audit M-1): waits, persistence, and the clock
//  and reboot rules. Same policy as Android's UnlockAttemptsTest.
//

import XCTest
import Foundation
@testable import AgePonyCore

final class UnlockAttemptsTests: XCTestCase {

    var dir: URL!
    var clock: UInt64 = 1_000_000
    var boot: Int64 = 1_700_000_000

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ua-\(UUID().uuidString)")
    }

    override func tearDown() { try? FileManager.default.removeItem(at: dir) }

    func make() -> UnlockAttempts {
        UnlockAttempts(file: dir.appendingPathComponent("unlock.attempts"), now: { self.clock }, bootTime: { self.boot })
    }

    func test_lockoutSchedule() {
        XCTAssertEqual((0..<5).map { UnlockAttempts.lockout(for: $0) }, [0, 0, 0, 0, 0])
        XCTAssertEqual(UnlockAttempts.lockout(for: 5), 30_000)
        XCTAssertEqual(UnlockAttempts.lockout(for: 6), 60_000)
        XCTAssertEqual(UnlockAttempts.lockout(for: 11), 1_920_000)
        XCTAssertEqual(UnlockAttempts.lockout(for: 12), 3_600_000)
        XCTAssertEqual(UnlockAttempts.lockout(for: 9_999), 3_600_000)
    }

    func test_waitsBeginAfterFive_andSuccessResets() {
        let a = make()
        for _ in 0..<4 { a.recordAttempt() }
        XCTAssertEqual(a.remainingLockoutMillis(), 0)
        XCTAssertEqual(a.recordAttempt(), 5)
        XCTAssertEqual(a.remainingLockoutMillis(), 30_000)
        clock += 10_000
        XCTAssertEqual(a.remainingLockoutMillis(), 20_000)
        clock += 20_000
        XCTAssertEqual(a.remainingLockoutMillis(), 0)
        a.reset()
        XCTAssertEqual(a.failures, 0)
        XCTAssertEqual(make().failures, 0)
    }

    func test_countSurvivesARestartOfTheApp() {
        let a = make()
        for _ in 0..<6 { a.recordAttempt() }
        clock += 5_000
        let b = make()
        XCTAssertEqual(b.failures, 6)
        XCTAssertEqual(b.remainingLockoutMillis(), 55_000)
    }

    func test_rebootRestartsTheWait_clockBehind() {
        let a = make()
        for _ in 0..<5 { a.recordAttempt() }
        clock = 2_000 // the monotonic clock restarted
        let b = make()
        XCTAssertEqual(b.remainingLockoutMillis(), 30_000)
        clock += 30_000
        XCTAssertEqual(b.remainingLockoutMillis(), 0)
    }

    func test_rebootRestartsTheWait_bootTimeMoved_butSmallShiftsDoNot() {
        let a = make()
        for _ in 0..<5 { a.recordAttempt() }
        clock += 20_000
        boot += 60 // wall-clock adjustment, same boot
        XCTAssertEqual(make().remainingLockoutMillis(), 10_000)
        boot += 10_000 // a new boot whose clock happens to be ahead
        XCTAssertEqual(make().remainingLockoutMillis(), 30_000)
    }

    func test_damagedFileIsIgnored() throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("zz 9 9 9".utf8).write(to: dir.appendingPathComponent("unlock.attempts"))
        XCTAssertEqual(make().failures, 0)
    }

    func test_wording() {
        XCTAssertEqual(UnlockAttempts.describeWait(millis: 30_000), "30 seconds")
        XCTAssertEqual(UnlockAttempts.describeWait(millis: 1), "1 second")
        XCTAssertEqual(UnlockAttempts.describeWait(millis: 240_000), "4 minutes")
        XCTAssertEqual(UnlockAttempts.describeWait(millis: 3_600_000), "1 hour")
        XCTAssertEqual(UnlockAttempts.lockoutMessage(millis: 30_000), "Too many wrong attempts. Try again in 30 seconds.")
    }
}

final class MonotonicClockTests: XCTestCase {
    func test_clockMovesForward() {
        let a = MonotonicClock.millis()
        Thread.sleep(forTimeInterval: 0.02)
        XCTAssertGreaterThanOrEqual(MonotonicClock.millis() - a, 15)
    }
}
