//
//  PostQuantumBadge.swift
//  AgePony
//
//  A "Quantum-safe" marker for identities, recipients, and files: an icon
//  and a word, no capsule.
//
//  Worth showing rather than leaving implicit: an `age1pq1…` string looks like
//  any other opaque key, only much longer, so without a marker the one property
//  a user chose it for is invisible everywhere it matters.
//

import SwiftUI

struct PostQuantumBadge: View {
    /// Compact uses the smaller text style, for dense rows.
    var compact: Bool = false

    var body: some View {
        Label("Quantum-safe", systemImage: "atom")
            .font(compact ? AgePonyTypography.footnote : AgePonyTypography.subheadline)
            .foregroundStyle(.secondary)
    }
}
