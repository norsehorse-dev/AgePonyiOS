//
//  KeyAvatarView.swift
//  AgePony
//
//  A small circular avatar for an identity or recipient: name initials on a
//  flat disc whose hue is derived from the key material. Gives each key a
//  stable visual fingerprint so two `age1...` entries are easy to tell apart.
//  The derivation (hue + initials) lives in AgePonyCore's `KeyAvatar` and
//  matches the Android implementation. The disc scales with Dynamic Type.
//

import SwiftUI
import AgePonyCore

struct KeyAvatarView: View {
    let seed: String
    let name: String
    @ScaledMetric private var size: CGFloat

    init(seed: String, name: String, size: CGFloat = 40) {
        self.seed = seed
        self.name = name
        _size = ScaledMetric(wrappedValue: size, relativeTo: .body)
    }

    var body: some View {
        Circle()
            .fill(Color(hue: hueDegrees / 360.0, saturation: 0.55, brightness: 0.5))
            .frame(width: size, height: size)
            .overlay(
                Text(KeyAvatar.initials(name: name))
                    .font(AgePonyTypography.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
            )
            .accessibilityHidden(true)
    }

    private var hueDegrees: Double { Double(KeyAvatar.hue(seed: seed)) }
}
