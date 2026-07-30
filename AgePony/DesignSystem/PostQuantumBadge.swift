//
//  PostQuantumBadge.swift
//  AgePony
//
//  A small "quantum-safe" marker for identities, recipients, and files.
//
//  Worth showing rather than leaving implicit: an `age1pq1…` string looks like
//  any other opaque key, only much longer, so without a marker the one property
//  a user chose it for is invisible everywhere it matters.
//

import SwiftUI

struct PostQuantumBadge: View {
    /// Compact drops the wording and shows the glyph alone, for dense rows.
    var compact: Bool = false

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "atom")
                .font(.system(size: compact ? 11 : 10, weight: .semibold))
            if !compact {
                Text("Quantum-safe")
                    .font(AgePonyTypography.caption)
            }
        }
        .foregroundStyle(AgePonyColors.tealCore)
        .padding(.horizontal, compact ? 5 : 7)
        .padding(.vertical, compact ? 2 : 3)
        .background(
            Capsule().fill(AgePonyColors.tealCore.opacity(0.12))
        )
        .accessibilityLabel("Quantum-safe")
    }
}
