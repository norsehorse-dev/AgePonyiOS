//
//  UnlockAttempts.swift
//  AgePonyCore
//
//  Persisted failed-attempt counter for the app password/PIN (audit M-1).
//  Mirrors Android `security/UnlockAttempts.kt`.
//
//  After `backoffAfter` wrong attempts in a row every further try waits: 30 s,
//  then doubling, capped at one hour. A success resets it. The duress secret
//  counts as a success (its wipe resets the counter too), so the counter never
//  tells a decoy from the real thing. Face ID attempts don't count here; the
//  system has its own lockout for those.
//
//  Stored in the vault directory (unlock.attempts) so it lives and dies with the
//  blobs it protects: reset and the duress wipe clear it with them, and the
//  directory's backup exclusion covers it. An attempt is counted before it is
//  checked (`recordAttempt`), so killing the app mid-attempt doesn't make a
//  guess free.
//
//  Time is a monotonic clock that keeps running while the phone sleeps (the app
//  passes CLOCK_MONOTONIC_RAW), not the wall clock, so changing the date doesn't
//  skip a wait. That clock restarts at boot, so a reboot (the clock being behind
//  the last attempt, or the boot time having moved) restarts the current wait
//  rather than ending it. After a reboot the clock can only under-count the time
//  since the last attempt, never over-count it, so the boot-time check is a
//  second line, with a tolerance because the kernel's boot time shifts when the
//  wall clock is set.
//
//  Pure apart from the injected clock and boot time, so it is unit-tested
//  directly.
//

import Foundation

public final class UnlockAttempts {

    /// Wrong attempts allowed before waits begin.
    public static let backoffAfter = 5
    /// Wrong attempts after which the optional erase setting wipes the vault.
    public static let eraseAfter = 10
    static let firstWaitMillis: UInt64 = 30_000
    static let maxWaitMillis: UInt64 = 60 * 60 * 1000
    static let maxCount = 10_000
    static let format = "a1"
    /// Boot times this far apart (seconds) count as different boots.
    static let bootTolerance: Int64 = 120

    private let file: URL
    private let now: () -> UInt64
    private let bootTime: () -> Int64

    private var loaded = false
    private var failureCount = 0
    private var lastAttemptAt: UInt64 = 0
    private var boot: Int64 = -1

    /// - Parameters:
    ///   - file: where the counter lives.
    ///   - now: milliseconds on a monotonic clock that counts sleep and restarts at boot.
    ///   - bootTime: the kernel's boot time in seconds, or -1 when unknown.
    public init(file: URL, now: @escaping () -> UInt64, bootTime: @escaping () -> Int64) {
        self.file = file
        self.now = now
        self.bootTime = bootTime
    }

    /// Attempts counted since the last success (including one in progress).
    public var failures: Int {
        load()
        return failureCount
    }

    /// Milliseconds until the next attempt is allowed; 0 when it may go ahead now.
    public func remainingLockoutMillis() -> UInt64 {
        load()
        let wait = Self.lockout(for: failureCount)
        guard wait > 0 else { return 0 }
        let t = now()
        let end = lastAttemptAt &+ wait
        return t >= end ? 0 : min(end - t, wait)
    }

    /// Count one attempt, before it is checked, and persist it. Returns the new
    /// count. A success must follow with `reset()`.
    @discardableResult
    public func recordAttempt() -> Int {
        load()
        failureCount = min(failureCount + 1, Self.maxCount)
        lastAttemptAt = now()
        boot = bootTime()
        save()
        return failureCount
    }

    /// Forget every counted attempt (a success, a reset, or a wipe).
    public func reset() {
        failureCount = 0
        lastAttemptAt = 0
        boot = -1
        loaded = true
        try? FileManager.default.removeItem(at: file)
    }

    // MARK: - Persistence

    private func load() {
        guard !loaded else { return }
        loaded = true
        guard let text = try? String(contentsOf: file, encoding: .utf8) else { return }
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ").map(String.init)
        guard parts.count == 4, parts[0] == Self.format, let n = Int(parts[1]) else { return }
        failureCount = max(0, min(n, Self.maxCount))
        lastAttemptAt = UInt64(parts[2]) ?? 0
        boot = Int64(parts[3]) ?? -1
        guard failureCount > 0 else { return }
        let t = now()
        let currentBoot = bootTime()
        let bootMoved = boot >= 0 && currentBoot >= 0 && abs(boot - currentBoot) > Self.bootTolerance
        if t < lastAttemptAt || bootMoved {
            lastAttemptAt = t
            boot = currentBoot
            save()
        }
    }

    private func save() {
        let line = "\(Self.format) \(failureCount) \(lastAttemptAt) \(boot)\n"
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(line.utf8).write(to: file, options: .atomic)
    }

    // MARK: - Policy and wording

    /// The wait imposed after `failures` wrong attempts: 0, then 30 s doubling up to 1 h.
    public static func lockout(for failures: Int) -> UInt64 {
        guard failures >= backoffAfter else { return 0 }
        let doublings = UInt64(min(failures - backoffAfter, 10))
        return min(firstWaitMillis << doublings, maxWaitMillis)
    }

    /// "30 seconds", "4 minutes", "1 hour": a wait for display, rounded up.
    public static func describeWait(millis: UInt64) -> String {
        let seconds = max((millis + 999) / 1000, 1)
        if seconds < 90 { return seconds == 1 ? "1 second" : "\(seconds) seconds" }
        if seconds < 3600 { return "\((seconds + 59) / 60) minutes" }
        return "1 hour"
    }

    /// The message shown when an attempt is refused because of the backoff.
    public static func lockoutMessage(millis: UInt64) -> String {
        "Too many wrong attempts. Try again in \(describeWait(millis: millis))."
    }
}
