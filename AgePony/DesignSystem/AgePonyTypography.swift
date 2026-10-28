//
//  AgePonyTypography.swift
//  AgePony
//
//  Type tokens, all system text styles so they follow Dynamic Type. Rows are
//  regular body text, section headings are headline, secondary text is
//  subheadline or footnote. SF Mono only for real data: keys, fingerprints,
//  digests, file names and codes. Never for labels, buttons or headings.
//

import SwiftUI

public enum AgePonyTypography {

    // MARK: - Sans

    public static let largeTitle  = Font.system(.largeTitle, design: .default, weight: .bold)
    public static let title       = Font.system(.title2,     design: .default, weight: .semibold)
    public static let headline    = Font.headline
    public static let body        = Font.body
    public static let subheadline = Font.subheadline
    public static let footnote    = Font.footnote
    public static let caption     = Font.caption

    // MARK: - Monospace (data only)

    /// `age1...` recipients, `AGE-SECRET-KEY-1...` identities, SSH public-key
    /// blobs, stanza tags, digests, file names and transfer codes.
    public static let monoBody    = Font.system(.body,     design: .monospaced, weight: .regular)
    public static let monoSmall   = Font.system(.footnote, design: .monospaced, weight: .regular)
    public static let monoCaption = Font.system(.caption2, design: .monospaced, weight: .regular)
}
