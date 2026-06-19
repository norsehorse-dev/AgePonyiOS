//
//  PlaceholderView.swift
//  AgePony
//
//  Stand-in content for the tabs whose real implementations land in later
//  sub-phases. Keeps the tab bar visually anchored without faking
//  functionality.
//

import SwiftUI

struct PlaceholderView: View {
    let icon: String
    let title: String
    let message: String
    let accent: Color

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: icon)
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(accent)
            Text(title)
                .font(AgePonyTypography.title)
            Text(message)
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
            Spacer()
        }
    }
}
