//
//  AgePonyKeyBlock.swift
//  AgePony
//
//  A read-only block for displaying crypto strings (`age1...`,
//  `AGE-SECRET-KEY-1...`, SSH public-key lines, stanza tags). Renders in
//  SF Mono and provides a Copy button that auto-clears the pasteboard after
//  60 seconds via UIPasteboard.setItems options.
//

import SwiftUI
import UIKit

public struct AgePonyKeyBlock: View {
    public let label: String?
    public let value: String
    public let isSensitive: Bool
    public var pasteboardExpiry: TimeInterval = 60

    @State private var copied: Bool = false
    @State private var revealed: Bool = false

    public init(label: String? = nil, value: String, isSensitive: Bool = false) {
        self.label = label
        self.value = value
        self.isSensitive = isSensitive
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let label = label {
                Text(label)
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(.secondary)
            }

            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(AgePonyColors.tealCore.opacity(0.06))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .strokeBorder(AgePonyColors.tealCore.opacity(0.18), lineWidth: 1)
                    )

                Text(displayValue)
                    .font(AgePonyTypography.monoSmall)
                    .foregroundStyle(AgePonyColors.tealInk)
                    .textSelection(.enabled)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .blur(radius: (isSensitive && !revealed) ? 6 : 0)
                    .animation(.easeInOut(duration: 0.18), value: revealed)
            }
            .onTapGesture {
                if isSensitive {
                    revealed.toggle()
                }
            }

            HStack(spacing: 12) {
                Button(action: copy) {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(AgePonyTypography.footnote)
                }
                .foregroundStyle(AgePonyColors.tealCore)

                if isSensitive {
                    Button(action: { revealed.toggle() }) {
                        Label(revealed ? "Hide" : "Reveal", systemImage: revealed ? "eye.slash" : "eye")
                            .font(AgePonyTypography.footnote)
                    }
                    .foregroundStyle(AgePonyColors.tealCore)
                }

                Spacer()
            }
        }
    }

    private var displayValue: String {
        // Even when blurred we still render the real value so the layout
        // is stable and the blur radius covers the text uniformly.
        value
    }

    private func copy() {
        let pasteboard = UIPasteboard.general
        let expiry = Date().addingTimeInterval(pasteboardExpiry)
        pasteboard.setItems(
            [[UIPasteboard.typeAutomatic: value]],
            options: [
                .expirationDate: expiry,
                .localOnly: true
            ]
        )
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { copied = false }
    }
}
