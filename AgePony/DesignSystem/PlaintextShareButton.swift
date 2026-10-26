//
//  PlaintextShareButton.swift
//  AgePony
//
//  Sharing a decrypted file out of AgePony (5.0.1, matching Android). Ciphertext
//  shares freely; plaintext asks first, because once it leaves the app it's an
//  ordinary unencrypted file in whatever app receives it.
//

import SwiftUI
import UIKit

struct PlaintextShareButton: View {
    let url: URL
    var title: String = "Share decrypted file"

    @State private var confirming = false
    @State private var sharing = false

    var body: some View {
        Button {
            confirming = true
        } label: {
            Text(title).frame(maxWidth: .infinity)
        }
        .buttonStyle(.agePonyPrimary)
        .confirmationDialog("Share the decrypted file?", isPresented: $confirming, titleVisibility: .visible) {
            Button("Share") { sharing = true }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("It leaves AgePony unencrypted. The app you share it with can keep a copy, back it up or sync it.")
        }
        .sheet(isPresented: $sharing) {
            ActivitySheet(items: [url])
                .presentationDetents([.medium, .large])
        }
    }
}

/// UIActivityViewController for SwiftUI.
struct ActivitySheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
