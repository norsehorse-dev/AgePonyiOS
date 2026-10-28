//
//  AgePonyColors.swift
//  AgePony
//
//  Color roles. The accent lives in the asset catalog (AccentColor: #0E7D7A in
//  light mode, #38CFE8 in dark mode) and is for the primary action, selection,
//  links and focus only. Surfaces are system colors. Status colors are the
//  system red, green and orange, used on the icon and status word that carry
//  the state.
//

import SwiftUI

public enum AgePonyColors {

    /// Brand accent from the asset catalog (also the app's global tint).
    public static let accent = Color.accentColor

    /// Text and icons on an accent fill: white in light mode, near-black in dark
    /// mode, where the accent is a light cyan.
    public static let onAccent = Color("AccentForeground")

    /// Failure and destructive actions.
    public static let destructive = Color.red

    /// A match or a completed check.
    public static let success = Color.green

    /// Something missing or worth a second look.
    public static let warning = Color.orange
}
