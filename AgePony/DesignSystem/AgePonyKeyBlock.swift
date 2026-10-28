//
//  AgePonyKeyBlock.swift
//  AgePony
//
//  Read-only content for a Form row that shows a crypto string (`age1...`,
//  `AGE-SECRET-KEY-1...`, SSH public-key lines, stanza tags) in SF Mono, with
//  Copy (the pasteboard auto-clears via ClipboardPreferences), Reveal for
//  sensitive values and an optional QR button. No card of its own: the Form
//  row is the container. The buttons are `.borderless` so a tap fires only the
//  button under the finger, not every button in the row.
//

import SwiftUI
import UIKit

public struct AgePonyKeyBlock: View {
    public let label: LocalizedStringKey?
    public let value: String
    public let isSensitive: Bool
    public var pasteboardExpiry: TimeInterval = 60
    public var showsQR: Bool = false

    @State private var copied: Bool = false
    @State private var revealed: Bool = false
    @State private var showingQR: Bool = false

    public init(label: LocalizedStringKey? = nil, value: String, isSensitive: Bool = false, showsQR: Bool = false) {
        self.label = label
        self.value = value
        self.isSensitive = isSensitive
        self.showsQR = showsQR
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let label {
                Text(label)
                    .font(AgePonyTypography.subheadline)
                    .foregroundStyle(.secondary)
            }

            Text(value)
                .font(AgePonyTypography.monoSmall)
                .foregroundStyle(.primary)
                // A private key can't be selected (and so dragged or copied
                // by a stray long-press); the Copy button is the way (L-23).
                .modifier(SelectableUnlessSensitive(sensitive: isSensitive))
                .frame(maxWidth: .infinity, alignment: .leading)
                // Hides the value until Reveal; the real text stays so the
                // layout doesn't jump.
                .blur(radius: (isSensitive && !revealed) ? 6 : 0)
                .animation(.easeInOut(duration: 0.18), value: revealed)
                .onTapGesture {
                    if isSensitive {
                        revealed.toggle()
                    }
                }

            HStack(spacing: 16) {
                Button(action: copy) {
                    if copied {
                        Label("Copied", systemImage: "checkmark")
                    } else {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                }

                if isSensitive {
                    Button {
                        revealed.toggle()
                    } label: {
                        if revealed {
                            Label("Hide", systemImage: "eye.slash")
                        } else {
                            Label("Reveal", systemImage: "eye")
                        }
                    }
                }

                if showsQR && !isSensitive {
                    Button {
                        showingQR = true
                    } label: {
                        Label("QR code", systemImage: "qrcode")
                    }
                }

                Spacer()
            }
            .buttonStyle(.borderless)
            .font(AgePonyTypography.subheadline)
        }
        .padding(.vertical, 4)
        .sheet(isPresented: $showingQR) {
            QRCodeView(value: value)
        }
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
