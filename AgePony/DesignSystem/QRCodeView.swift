//
//  QRCodeView.swift
//  AgePony
//
//  Renders a string (an `age1...` / `ssh-*` public key) as a QR code so it can
//  be scanned into another device's AgePony — the display counterpart to the
//  camera scanner in AddRecipientView. Generation is CoreImage, run OFF the main
//  thread so the sheet opens instantly and shows a spinner while it renders; the
//  code sits on a forced-white card so it scans in light or dark mode.
//

import SwiftUI
import UIKit
import CoreImage.CIFilterBuiltins

struct QRCodeView: View {
    let value: String

    @Environment(\.dismiss) private var dismiss
    @State private var image: UIImage?
    @State private var generating = true

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let image {
                    Image(uiImage: image)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 300, maxHeight: 300)
                        .padding(16)
                        .background(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                        .accessibilityLabel("QR code")
                } else if generating {
                    ProgressView()
                        .controlSize(.large)
                        .frame(maxWidth: 300, maxHeight: 300)
                        .accessibilityLabel("Generating QR code")
                } else {
                    ContentUnavailableView("Couldn't make a QR code",
                                           systemImage: "qrcode",
                                           description: Text("The key is too long to encode."))
                }

                Text(value)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .padding(.horizontal)

                Text("Scan this from another device's Add Recipient screen.")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            .padding()
            .frame(maxHeight: .infinity, alignment: .center)
            .navigationTitle("QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                let rendered = await Self.generateAsync(value)
                image = rendered
                generating = false
            }
        }
    }

    /// Render off the main thread so presenting the sheet never blocks on CoreImage.
    private static func generateAsync(_ string: String) async -> UIImage? {
        await Task.detached(priority: .userInitiated) {
            generate(string)
        }.value
    }

    /// Generate a QR image for `string`, scaled up with nearest-neighbor so the
    /// modules stay crisp. Returns nil if CoreImage can't encode it. Called off
    /// the main thread from `generateAsync`, so the CIContext is built here.
    static func generate(_ string: String) -> UIImage? {
        generate(string, correctionLevel: "M")
    }

    /// As `generate(_:)`, with the error-correction level ("L", "M", "Q", "H"). The key
    /// transfer invite uses "L", as Android does: about 2,000 characters, which CoreImage
    /// encodes in byte mode as a version 33 code at L and version 38 at M.
    static func generate(_ string: String, correctionLevel: String) -> UIImage? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = correctionLevel
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
