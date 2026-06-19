//
//  AgePonyTypography.swift
//  AgePony
//
//  Type tokens. Hybrid direction per spec §13.1: PGPony-style component sizing
//  (system sans for body / titles / labels) with SF Mono dedicated to crypto
//  strings — age recipient/identity strings, SSH public-key blobs, file
//  headers, recipient tags. The monospace token is the only place AgePony
//  visually departs from PGPony, and it should appear ONLY around crypto
//  primitives, never in chrome.
//

import SwiftUI

public enum AgePonyTypography {

    // MARK: - Body sans (matches PGPony)

    public static let largeTitle  = Font.system(.largeTitle, design: .default, weight: .semibold)
    public static let title       = Font.system(.title2,    design: .default, weight: .semibold)
    public static let headline    = Font.system(.headline,  design: .default, weight: .semibold)
    public static let body        = Font.system(.body,      design: .default, weight: .regular)
    public static let bodyEmph    = Font.system(.body,      design: .default, weight: .medium)
    public static let footnote    = Font.system(.footnote,  design: .default, weight: .regular)
    public static let caption     = Font.system(.caption,   design: .default, weight: .regular)

    // MARK: - Monospace (crypto strings only)

    /// Use for `age1...` recipient strings, `AGE-SECRET-KEY-1...` identity
    /// strings, base64 SSH public-key blobs, age stanza tags, and similar
    /// machine-readable strings the user may copy.
    public static let monoBody    = Font.system(.body,     design: .monospaced, weight: .regular)
    public static let monoSmall   = Font.system(.footnote, design: .monospaced, weight: .regular)
    public static let monoCaption = Font.system(.caption2, design: .monospaced, weight: .regular)
}
