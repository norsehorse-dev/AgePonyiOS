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
    public var showsQR: Bool = false

    @State private var copied: Bool = false
    @State private var revealed: Bool = false
    @State private var showingQR: Bool = false

    public init(label: String? = nil, value: String, isSensitive: Bool = false, showsQR: Bool = false) {
        self.label = label
        self.value = value
        self.isSensitive = isSensitive
        self.showsQR = showsQR
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
                    // A private key can't be selected (and so dragged or copied
                    // by a stray long-press); the Copy button is the way (L-23).
                    .modifier(SelectableUnlessSensitive(sensitive: isSensitive))
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

                if showsQR && !isSensitive {
                    Button { showingQR = true } label: {
                        Label("QR", systemImage: "qrcode")
                            .font(AgePonyTypography.footnote)
                    }
                    .foregroundStyle(AgePonyColors.tealCore)
                }

                Spacer()
            }
        }
        .sheet(isPresented: $showingQR) {
            QRCodeView(value: value)
        }
    }

    private var displayValue: String {
        // Even when blurred we still render the real value so the layout
        // is stable and the blur radius covers the text uniformly.
        value
    }

    private func copy() {
        // Flip the button state first so it responds instantly, then write to the
        // pasteboard off the main thread (UIPasteboard.setItems can block).
        copied = true
        DispatchQueue.global(qos: .userInitiated).async {
            ClipboardPreferences.copy(value)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { copied = false }
    }
}

/// Text selection on, except for sensitive values.
private struct SelectableUnlessSensitive: ViewModifier {
    let sensitive: Bool

    func body(content: Content) -> some View {
        if sensitive {
            content.textSelection(.disabled)
        } else {
            content.textSelection(.enabled)
        }
    }
}
