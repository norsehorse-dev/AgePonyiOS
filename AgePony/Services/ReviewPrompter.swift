//
//  ReviewPrompter.swift
//  AgePony
//
//  Implements the testers' "Rate Your App" request. Two paths:
//
//    1. Contextual prompt — after the user has completed a few successful
//       operations (encrypt / decrypt), AgePony asks the system to show
//       the native StoreKit review sheet via @Environment(\.requestReview).
//       We gate this ourselves on top of Apple's own throttling so we only
//       ever ask at a genuinely good moment, and never twice for the same
//       shipped version.
//
//    2. Manual prompt — a "Rate AgePony" row in Settings opens the App
//       Store review page directly. This always works and isn't subject to
//       StoreKit's silent-no-op behavior.
//
//  Nothing here is monetization. The review prompt is free and ships now;
//  it doesn't touch the November-2026 paid-feature gate.
//
//  State lives in UserDefaults (no vault access needed — these counters
//  aren't sensitive and we want them to survive a locked vault):
//    • successfulOps     — running count of encrypt/decrypt successes.
//    • lastPromptVersion — the CFBundleShortVersionString we last prompted
//                          on, so an update is required before we ask again.
//    • lastPromptDate    — wall-clock of the last prompt, for the cooldown.
//

import Foundation
import StoreKit
import SwiftUI

enum ReviewPrompter {

    // MARK: - Configuration

    /// App Store numeric ID for AgePony. Fill this in from App Store
    /// Connect (App Information → "Apple ID"). The contextual prompt works
    /// without it, but the manual "Rate AgePony" / "View on App Store"
    /// links need it to deep-link correctly.
    static let appStoreID = "6774821172"

    /// Minimum successful operations before the contextual prompt is even
    /// considered. Three keeps us from asking a first-time user who hasn't
    /// gotten value from the app yet.
    private static let minOpsBeforeAsking = 3

    /// Cooldown between contextual prompts, regardless of version. Apple
    /// already caps the native sheet at 3/year; this is belt-and-suspenders
    /// so we don't burn one of those on someone who just declined.
    private static let minSecondsBetweenPrompts: TimeInterval = 60 * 60 * 24 * 90

    // MARK: - Recording usage

    /// Call once after any user-visible success (a file or text encrypt /
    /// decrypt that the user completed). Cheap and idempotent-per-event.
    static func recordSuccessfulOperation() {
        let d = UserDefaults.standard
        let next = d.integer(forKey: Key.successfulOps) + 1
        d.set(next, forKey: Key.successfulOps)
    }

    // MARK: - Contextual prompt

    /// Whether the contextual review sheet is worth requesting right now.
    static var shouldRequestReview: Bool {
        let d = UserDefaults.standard

        guard d.integer(forKey: Key.successfulOps) >= minOpsBeforeAsking else {
            return false
        }

        // Only ask once per shipped version — if we already asked on this
        // version, wait for an update before asking again.
        if d.string(forKey: Key.lastPromptVersion) == currentVersion {
            return false
        }

        // Honor the cooldown even across versions.
        if let last = d.object(forKey: Key.lastPromptDate) as? Date,
           Date().timeIntervalSince(last) < minSecondsBetweenPrompts {
            return false
        }

        return true
    }

    /// Request the native review sheet if our own gating says it's a good
    /// moment. Safe to call from anywhere; it no-ops when inappropriate.
    @MainActor
    static func requestReviewIfAppropriate(using action: RequestReviewAction) {
        guard shouldRequestReview else { return }
        markPrompted()
        action()
    }

    private static func markPrompted() {
        let d = UserDefaults.standard
        d.set(currentVersion, forKey: Key.lastPromptVersion)
        d.set(Date(), forKey: Key.lastPromptDate)
    }

    // MARK: - Manual prompt

    /// Deep link that opens the App Store straight to the "write a review"
    /// composer. Used by the Settings "Rate AgePony" row.
    static var writeReviewURL: URL? {
        URL(string: "https://apps.apple.com/app/id\(appStoreID)?action=write-review")
    }

    /// Plain App Store product page, for a "View on the App Store" affordance.
    static var appStoreURL: URL? {
        URL(string: "https://apps.apple.com/app/id\(appStoreID)")
    }

    /// True once a real App Store ID has been wired in, so the UI can hide
    /// the manual links until the placeholder is replaced.
    static var hasAppStoreID: Bool {
        !appStoreID.isEmpty && appStoreID != "REPLACE_WITH_APP_STORE_ID"
    }

    // MARK: - Reset

    /// Clears all review-prompt bookkeeping. Wired into Vault.reset() so a
    /// fresh start really is fresh.
    static func resetState() {
        let d = UserDefaults.standard
        d.removeObject(forKey: Key.successfulOps)
        d.removeObject(forKey: Key.lastPromptVersion)
        d.removeObject(forKey: Key.lastPromptDate)
    }

    // MARK: - Helpers

    private static var currentVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }

    private enum Key {
        static let successfulOps     = "com.agepony.app.review.successfulOps"
        static let lastPromptVersion = "com.agepony.app.review.lastPromptVersion"
        static let lastPromptDate    = "com.agepony.app.review.lastPromptDate"
    }
}
