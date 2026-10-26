//
//  MonotonicClock.swift
//  AgePonyCore
//
//  Time sources for the failed-attempt backoff and the auto-lock grace period
//  (audit M-1, M-4). Neither may use the wall clock, which the user can set:
//  winding it back would end a wait early or keep an unlocked vault open.
//
//  `millis()` keeps counting while the phone sleeps and restarts at boot
//  (CLOCK_MONOTONIC_RAW on Apple platforms, which is mach_continuous_time).
//  `bootTime()` is the kernel's boot time, used only to notice a restart. It
//  moves a little when the wall clock is set, so callers compare it with a
//  tolerance.
//

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum MonotonicClock {

    /// Milliseconds since boot, sleep included.
    public static func millis() -> UInt64 {
        #if canImport(Darwin)
        return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1_000_000
        #else
        var ts = timespec()
        clock_gettime(CLOCK_BOOTTIME, &ts)
        return UInt64(ts.tv_sec) * 1000 + UInt64(ts.tv_nsec) / 1_000_000
        #endif
    }

    /// The kernel's boot time in seconds since 1970, or -1 when unknown.
    public static func bootTime() -> Int64 {
        #if canImport(Darwin)
        var tv = timeval()
        var size = MemoryLayout<timeval>.size
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        guard sysctl(&mib, 2, &tv, &size, nil, 0) == 0 else { return -1 }
        return Int64(tv.tv_sec)
        #else
        return -1
        #endif
    }
}

extension UnlockAttempts {
    /// The counter on the system clocks.
    public convenience init(file: URL) {
        self.init(file: file, now: { MonotonicClock.millis() }, bootTime: { MonotonicClock.bootTime() })
    }
}
