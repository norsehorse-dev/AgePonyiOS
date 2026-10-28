//
//  AgePonyButton.swift
//  AgePony
//
//  Thin wrappers over the system button styles so call sites keep one name.
//  Primary is `.borderedProminent` tinted with the accent, secondary is
//  `.bordered`. Destructive actions use `role: .destructive` on the button
//  itself. Both are full width so stacked actions line up.
//

import SwiftUI

// MARK: - Primary

public struct AgePonyPrimaryButtonStyle: PrimitiveButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        Button(role: configuration.role) {
            configuration.trigger()
        } label: {
            configuration.label
                // White on the light-mode accent, near-black on the dark-mode cyan.
                .foregroundStyle(configuration.role == .destructive ? Color.white : AgePonyColors.onAccent)
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .tint(configuration.role == .destructive ? AgePonyColors.destructive : AgePonyColors.accent)
    }
}

// MARK: - Secondary

public struct AgePonySecondaryButtonStyle: PrimitiveButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        Button(role: configuration.role) {
            configuration.trigger()
        } label: {
            configuration.label
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
        .controlSize(.large)
        .tint(configuration.role == .destructive ? AgePonyColors.destructive : AgePonyColors.accent)
    }
}

public extension PrimitiveButtonStyle where Self == AgePonyPrimaryButtonStyle {
    static var agePonyPrimary: AgePonyPrimaryButtonStyle { AgePonyPrimaryButtonStyle() }
}

public extension PrimitiveButtonStyle where Self == AgePonySecondaryButtonStyle {
    static var agePonySecondary: AgePonySecondaryButtonStyle { AgePonySecondaryButtonStyle() }
}
