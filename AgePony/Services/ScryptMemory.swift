//
//  ScryptMemory.swift
//  AgePony
//
//  What a passphrase costs in memory, and whether this device can pay it.
//
//  scrypt's whole design is to be expensive in memory: at work factor N with
//  r = 8 it allocates 128 * 2^N * 8 bytes, which is 2^(N+10) — 64 MiB at 2^16,
//  1 GiB at 2^20. That allocation is the same size whether the file being
//  encrypted is one kilobyte or one gigabyte, which is exactly why an
//  out-of-memory failure during a passphrase operation must not be reported as
//  a file-size problem. Suggesting a smaller file would be useless advice.
//
//  So the cost is computed up front and checked against what the app can
//  actually get, and the user is told which allocation would fail rather than
//  being left to guess.
//

import Foundation

public enum ScryptMemory {

    /// The range AgePony exposes. Below 2^16 the brute-force resistance gets
    /// thin; 2^20 is 1 GiB and will fail on most phones, but it is reachable
    /// deliberately rather than by accident, and the precheck explains why when
    /// it does not fit.
    public static let minimumWorkFactor = 16
    public static let maximumWorkFactor = 20

    /// AgePony's default.
    ///
    /// Deliberately lower than the age CLI's 18, and lower than the Android
    /// app's 18. AgePonyCore's scrypt is pure Swift, where the CLI and the
    /// Android build both call into native implementations, so the same work
    /// factor costs materially more time here: 2^18 runs 20-60 seconds on an
    /// iPhone, long enough for the watchdog to become a concern, against 2-5
    /// seconds at 2^16. 2^16 is still 65,536 iterations and 64 MiB, which is
    /// substantial brute-force resistance for any reasonable passphrase.
    ///
    /// The factor is written into the file, so anything produced here stays
    /// readable by any age implementation, and files from other tools at any
    /// factor stay readable here.
    public static let defaultWorkFactor = 16

    /// Bytes scrypt allocates at `workFactor`, for age's parameters (r = 8, p = 1).
    ///
    /// 128 * N * r with N = 2^workFactor, which reduces to 2^(workFactor + 10).
    public static func bytesRequired(workFactor: Int) -> Int64 {
        let clamped = max(1, min(workFactor, 40))
        return Int64(1) << Int64(clamped + 10)
    }

    /// A short human label, e.g. "256 MB".
    public static func memoryLabel(workFactor: Int) -> String {
        ByteCountFormatter.string(
            fromByteCount: bytesRequired(workFactor: workFactor),
            countStyle: .memory
        )
    }

    /// "2^18 · 256 MB", for pickers and file summaries.
    public static func describe(workFactor: Int) -> String {
        "2^\(workFactor) · \(memoryLabel(workFactor: workFactor))"
    }

    /// Memory this process can still allocate, or nil if the OS will not say.
    ///
    /// `os_proc_available_memory` reports what remains of the app's allowance
    /// before iOS starts killing it, which is the number that actually matters
    /// here — total device RAM says nothing about what this process may have.
    public static var availableBytes: Int64? {
        let available = os_proc_available_memory()
        return available > 0 ? Int64(available) : nil
    }

    /// Whether scrypt at `workFactor` is likely to fit.
    ///
    /// Requires headroom beyond the allocation itself: scrypt's buffer is the
    /// bulk of it, but not all of it, and landing exactly at the limit is a
    /// crash rather than a failure. Returns true when the OS declines to report
    /// available memory, since refusing to proceed on missing information would
    /// be worse than trying.
    public static func fits(workFactor: Int) -> Bool {
        guard let available = availableBytes else { return true }
        let needed = bytesRequired(workFactor: workFactor)
        return available > needed + headroom
    }

    /// Slack left for everything that is not the scrypt buffer.
    private static let headroom: Int64 = 32 * 1024 * 1024

    /// The largest work factor expected to fit right now, or nil if none does.
    public static func largestFittingWorkFactor() -> Int? {
        for factor in stride(from: maximumWorkFactor, through: minimumWorkFactor, by: -1)
        where fits(workFactor: factor) {
            return factor
        }
        return nil
    }

    /// Why a passphrase operation cannot start, phrased so the user knows what
    /// to change. Nil when it can.
    ///
    /// Note what this deliberately does not say: nothing about file size. The
    /// allocation below is identical for a 1 KB file and a 1 GB one.
    public static func blockingReason(workFactor: Int) -> String? {
        guard !fits(workFactor: workFactor) else { return nil }
        let needed = memoryLabel(workFactor: workFactor)
        let availableText = availableBytes.map {
            ByteCountFormatter.string(fromByteCount: $0, countStyle: .memory)
        }

        var message = "A passphrase at 2^\(workFactor) needs \(needed) of memory"
        if let availableText { message += ", and about \(availableText) is available" }
        message += "."

        if let smaller = largestFittingWorkFactor(), smaller < workFactor {
            message += " Lower the work factor to 2^\(smaller) (\(memoryLabel(workFactor: smaller)))"
            message += " in Settings, or close other apps and try again."
        } else {
            message += " Close other apps and try again."
        }
        message += " This is the cost of the passphrase itself and does not depend on the file's size."
        return message
    }
}
