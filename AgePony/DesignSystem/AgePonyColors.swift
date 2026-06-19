//
//  AgePonyColors.swift
//  AgePony
//
//  Brand palette derived from the AgePony app icon. The cool teal range is
//  the sibling counterpart to PGPony's warm violet — both apps share spacing
//  and component patterns, but AgePony reads as the cooler / more modern of
//  the two on a home screen.
//

import SwiftUI

public enum AgePonyColors {

    // MARK: - Brand ramp

    /// Bright cyan — gradient top, decorative accents.
    public static let cyanLight = Color(red: 0x38 / 255.0, green: 0xCF / 255.0, blue: 0xE8 / 255.0)

    /// Vibrant teal — the primary brand color. Buttons, links, key blocks,
    /// active tab tint, the horse silhouette in the icon.
    public static let tealCore = Color(red: 0x14 / 255.0, green: 0xB8 / 255.0, blue: 0xB0 / 255.0)

    /// Deep teal — gradient bottom, pressed states, secondary accents.
    public static let tealDeep = Color(red: 0x0E / 255.0, green: 0x7D / 255.0, blue: 0x7A / 255.0)

    /// Near-black teal — branded headlines on light surfaces.
    public static let tealInk = Color(red: 0x0A / 255.0, green: 0x4F / 255.0, blue: 0x4D / 255.0)

    // MARK: - Semantic aliases

    /// Primary action color (buttons, focused controls, active tab).
    public static let primary = tealCore

    /// Subtle accent for backgrounds and dividers.
    public static let accent = cyanLight

    /// Color used for "dangerous" or destructive UI affordances.
    public static let destructive = Color(red: 0xC0 / 255.0, green: 0x46 / 255.0, blue: 0xDC / 255.0)
        // (PGPony's primary magenta — chosen so that destructive actions visually
        // borrow the sibling palette, signaling "different mode" without
        // introducing red, which clashes with the cool teal range.)

    // MARK: - Background gradients

    /// The marketing gradient (top-left cyan → mid teal → bottom-right deep teal)
    /// used in the app icon and in onboarding hero backgrounds.
    public static let brandGradient = LinearGradient(
        colors: [cyanLight, tealCore, tealDeep],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
}
