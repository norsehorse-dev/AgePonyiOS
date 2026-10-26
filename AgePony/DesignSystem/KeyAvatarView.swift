//
//  KeyAvatarView.swift
//  AgePony
//
//  A small circular avatar for an identity or recipient: name initials on a
//  two-tone disc whose hue is derived from the key material. Gives each key a
//  stable visual fingerprint so two `age1...` entries are easy to tell apart.
//  The derivation (hue + initials) lives in AgePonyCore's `KeyAvatar` and
//  matches the Android implementation.
//

import SwiftUI
import AgePonyCore

struct KeyAvatarView: View {
    let seed: String
    let name: String
    var size: CGFloat = 40

    var body: some View {
        Circle()
            .fill(
                LinearGradient(
                    colors: [topColor, bottomColor],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .frame(width: size, height: size)
            .overlay(
                Text(KeyAvatar.initials(name: name))
                    .font(.system(size: size * 0.38, weight: .semibold))
                    .foregroundStyle(.white)
                    .minimumScaleFactor(0.6)
            )
            .accessibilityHidden(true)
    }

    private var hueDegrees: Double { Double(KeyAvatar.hue(seed: seed)) }

    private var topColor: Color {
        Color(hue: hueDegrees / 360.0, saturation: 0.55, brightness: 0.85)
    }

    private var bottomColor: Color {
        Color(hue: (hueDegrees + 24).truncatingRemainder(dividingBy: 360) / 360.0,
              saturation: 0.65, brightness: 0.62)
    }
}
