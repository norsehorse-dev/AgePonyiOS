//
//  StatusText.swift
//  AgePony
//
//  One status line for validation and failure messages (5.1.0, UI plan U2):
//  the symbol carries the status colour and the words stay in the normal text
//  colour, instead of a whole paragraph in red or orange.
//

import SwiftUI

public struct StatusText: View {
    public enum Kind: Sendable {
        case failure
        case warning
        case success
    }

    private let text: Text
    private let kind: Kind
    /// A short verdict ("Decrypted", "Signed"): the word takes the status colour too.
    private let verdict: Bool

    /// A message that is already a localized `String` (error descriptions, built messages).
    @_disfavoredOverload
    public init<S: StringProtocol>(_ message: S, kind: Kind = .failure, verdict: Bool = false) {
        self.text = Text(message)
        self.kind = kind
        self.verdict = verdict
    }

    /// A literal, extracted to the String Catalog.
    public init(_ key: LocalizedStringKey, kind: Kind = .failure, verdict: Bool = false) {
        self.text = Text(key)
        self.kind = kind
        self.verdict = verdict
    }

    public var body: some View {
        Label {
            if verdict {
                text.foregroundStyle(color).fontWeight(.semibold)
            } else {
                text
            }
        } icon: {
            Image(systemName: symbol)
                .foregroundStyle(color)
        }
    }

    private var symbol: String {
        switch kind {
        case .failure: return "xmark.octagon"
        case .warning: return "exclamationmark.triangle"
        case .success: return "checkmark.circle"
        }
    }

    private var color: Color {
        switch kind {
        case .failure: return AgePonyColors.destructive
        case .warning: return AgePonyColors.warning
        case .success: return AgePonyColors.success
        }
    }
}
