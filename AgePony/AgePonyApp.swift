//
//  AgePonyApp.swift
//  AgePony
//
//  Created by NorseHorse on 5/27/26.
//
//  App entry. `.onOpenURL` now handles two distinct URL shapes:
//
//    file:// URLs        — incoming .age files from Files.app, Mail
//                          attachments, share sheets from any other app
//                          that hands us a file directly. Posts
//                          .agePonyOpenAgeFile, picked up by HomeView and
//                          routed to the Files tab's Decrypt flow. (1d)
//
//    agepony://share?…   — payloads handed off by the share extension
//                          (1g). The extension wrote the actual bytes to
//                          the App Group container. Posts the token (a UUID,
//                          checked here) as .agePonyShareIncoming; RootView
//                          claims the payload at once (5.0.1, M-7) and holds
//                          it until the vault is unlocked, or offers it to
//                          passphrase mode.
//

import SwiftUI
import UIKit

@main
struct AgePonyApp: App {
    @UIApplicationDelegateAdaptor(AgePonyAppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            RootView()
                .onOpenURL { url in
                    handleIncomingURL(url)
                }
        }
    }

    private func handleIncomingURL(_ url: URL) {
        if url.scheme == "agepony" {
            handleAgePonyScheme(url)
        } else {
            // Treat as a file URL. The existing 1d/1f behavior keeps working.
            NotificationCenter.default.post(
                name: .agePonyOpenAgeFile,
                object: nil,
                userInfo: ["url": url]
            )
        }
    }

    private func handleAgePonyScheme(_ url: URL) {
        guard url.host == "share" else { return }
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        guard let token = components?.queryItems?.first(where: { $0.name == "token" })?.value,
              UUID(uuidString: token) != nil else {
            return
        }
        NotificationCenter.default.post(
            name: .agePonyShareIncoming,
            object: nil,
            userInfo: ["token": token]
        )
    }
}

// MARK: - App delegate

/// Only the system keyboard inside AgePony (5.0.1, L-23): a third-party
/// keyboard sees every key typed, passwords and note text included, and some
/// send it off the device.
final class AgePonyAppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        extensionPointIdentifier != .keyboard
    }
}

// MARK: - Notification names

extension Notification.Name {
    /// Posted when iOS hands AgePony a file via `.onOpenURL` — typically
    /// a `.age` file opened from outside the app. HomeView listens for
    /// this and routes to the Files-tab Decrypt flow.
    static let agePonyOpenAgeFile = Notification.Name("com.agepony.app.openAgeFile")

    /// Posted when the share extension hands us a payload via the
    /// `agepony://share?token=<uuid>` URL scheme. RootView claims it and
    /// HomeView presents the matching flow once the vault is open.
    static let agePonyShareIncoming = Notification.Name("com.agepony.app.shareIncoming")
}
