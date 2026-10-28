//
//  PrivacyShield.swift
//  AgePony
//
//  App-switcher and screen-recording privacy (5.0.1, audit M-5). iOS has no
//  FLAG_SECURE, so AgePony covers itself instead:
//
//    - whenever the scene is not active, so the snapshot iOS takes for the app
//      switcher shows a neutral screen rather than vault contents or a revealed
//      key;
//    - whenever the screen is being recorded, mirrored or AirPlayed
//      (`sceneCaptureState`), so a recording shows nothing.
//
//  The cover is its own window above everything, alerts included. Before 5.0.1
//  it was a SwiftUI overlay on the root view, which sheets and full-screen
//  covers sat on top of, so a sheet showing a key stayed visible in the switcher.
//
//  Screenshots can't be blocked or blanked on iOS; that remains a documented
//  platform limit.
//

import SwiftUI
import UIKit

@MainActor
final class PrivacyShield {

    static let shared = PrivacyShield()

    private var window: UIWindow?
    private weak var observedScene: UIWindowScene?
    private var sceneInactive = false

    private init() {}

    /// Called from RootView on every scene phase change.
    func setSceneActive(_ active: Bool) {
        sceneInactive = !active
        update()
    }

    private func currentScene() -> UIWindowScene? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.first(where: { $0.activationState == .foregroundActive })
            ?? scenes.first(where: { $0.activationState == .foregroundInactive })
            ?? scenes.first
    }

    private func update() {
        guard let scene = currentScene() else { return }
        if observedScene !== scene {
            observedScene = scene
            _ = scene.registerForTraitChanges([UITraitSceneCaptureState.self]) { (_: UIWindowScene, _: UITraitCollection) in
                PrivacyShield.shared.update()
            }
        }
        let recording = scene.traitCollection.sceneCaptureState == .active
        let cover = sceneInactive || recording
        if cover {
            let w = window ?? makeWindow(scene)
            w.isHidden = false
        } else {
            window?.isHidden = true
        }
    }

    private func makeWindow(_ scene: UIWindowScene) -> UIWindow {
        let w = UIWindow(windowScene: scene)
        w.windowLevel = .alert + 1
        let host = UIHostingController(rootView: PrivacyCoverView())
        host.view.backgroundColor = .clear
        w.rootViewController = host
        w.accessibilityViewIsModal = true
        window = w
        return w
    }
}

/// The neutral screen the shield shows.
struct PrivacyCoverView: View {
    var body: some View {
        // A plain system background (5.1.0, U4): nothing to read in the app
        // switcher, and no decorative symbol.
        Color(.systemBackground)
            .ignoresSafeArea()
        .accessibilityLabel("AgePony is hidden")
    }
}
