//
//  AgePonyButton.swift
//  AgePony
//
//  Primary + Secondary buttons. Sizing mirrors PGPony.
//

import SwiftUI

// MARK: - Primary

public struct AgePonyPrimaryButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(AgePonyTypography.bodyEmph)
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .frame(minHeight: 50)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(configuration.isPressed ? AgePonyColors.tealDeep : AgePonyColors.tealCore)
            )
            .opacity(configuration.isPressed ? 0.92 : 1.0)
            .animation(.easeOut(duration: 0.08), value: configuration.isPressed)
    }
}

// MARK: - Secondary

public struct AgePonySecondaryButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(AgePonyTypography.bodyEmph)
            .foregroundStyle(AgePonyColors.tealCore)
            .frame(maxWidth: .infinity)
            .frame(minHeight: 50)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(AgePonyColors.tealCore.opacity(configuration.isPressed ? 0.18 : 0.12))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(AgePonyColors.tealCore.opacity(0.35), lineWidth: 1)
            )
            .animation(.easeOut(duration: 0.08), value: configuration.isPressed)
    }
}

// MARK: - Destructive

public struct AgePonyDestructiveButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(AgePonyTypography.bodyEmph)
            .foregroundStyle(AgePonyColors.destructive)
            .frame(maxWidth: .infinity)
            .frame(minHeight: 50)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(AgePonyColors.destructive.opacity(configuration.isPressed ? 0.18 : 0.10))
            )
            .animation(.easeOut(duration: 0.08), value: configuration.isPressed)
    }
}

public extension ButtonStyle where Self == AgePonyPrimaryButtonStyle {
    static var agePonyPrimary: AgePonyPrimaryButtonStyle { AgePonyPrimaryButtonStyle() }
}

public extension ButtonStyle where Self == AgePonySecondaryButtonStyle {
    static var agePonySecondary: AgePonySecondaryButtonStyle { AgePonySecondaryButtonStyle() }
}

public extension ButtonStyle where Self == AgePonyDestructiveButtonStyle {
    static var agePonyDestructive: AgePonyDestructiveButtonStyle { AgePonyDestructiveButtonStyle() }
}
