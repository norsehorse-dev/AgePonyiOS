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
//                          the App Group container and is asking us to
//                          process them with full vault access. Reads the
//                          payload via SharedContainer.readPayload(token:)
//                          and posts .agePonyShareIncoming with the
//                          payload as userInfo for HomeView to consume.
//

import SwiftUI

@main
struct AgePonyApp: App {
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
              !token.isEmpty else {
            return
        }
        do {
            let payload = try SharedContainer.readPayload(token: token)
            NotificationCenter.default.post(
                name: .agePonyShareIncoming,
                object: nil,
                userInfo: ["payload": payload]
            )
        } catch {
            // Couldn't load the payload — likely an abandoned token or a
            // malformed manifest. Silently drop; the user will notice the
            // share didn't show up and retry.
        }
    }
}

// MARK: - Notification names

extension Notification.Name {
    /// Posted when iOS hands AgePony a file via `.onOpenURL` — typically
    /// a `.age` file opened from outside the app. HomeView listens for
    /// this and routes to the Files-tab Decrypt flow.
    static let agePonyOpenAgeFile = Notification.Name("com.agepony.app.openAgeFile")

    /// Posted when the share extension hands us a payload via the
    /// `agepony://share?token=<uuid>` URL scheme. HomeView listens for
    /// this and presents the appropriate flow (encrypt or decrypt, file
    /// or text) with the input preloaded.
    static let agePonyShareIncoming = Notification.Name("com.agepony.app.shareIncoming")
}
