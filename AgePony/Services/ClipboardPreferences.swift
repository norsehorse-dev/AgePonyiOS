//
//  ClipboardPreferences.swift
//  AgePony
//
//  Central pasteboard writer that honors the user's clipboard auto-clear
//  preference (4.0.0). Every copy path in the app goes through `copy(_:)` so the
//  setting is applied uniformly and a plain, non-expiring copy can never slip in.
//

import UIKit

enum ClipboardPreferences {

    static let enabledKey = "com.agepony.app.settings.clipboardAutoClearEnabled"
    static let intervalKey = "com.agepony.app.settings.clipboardClearInterval"

    /// Auto-clear defaults on, at 60 seconds, matching the pre-4.0.0 behavior.
    static var autoClearEnabled: Bool {
        UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true
    }

    static var clearInterval: TimeInterval {
        UserDefaults.standard.object(forKey: intervalKey) as? Double ?? 60
    }

    /// Copy `text` to the general pasteboard, honoring the auto-clear preference.
    static func copy(_ text: String) {
        let pasteboard = UIPasteboard.general
        if autoClearEnabled {
            pasteboard.setItems(
                [[UIPasteboard.typeAutomatic: text]],
                options: [
                    .expirationDate: Date().addingTimeInterval(clearInterval),
                    .localOnly: true
                ]
            )
        } else {
            pasteboard.setItems(
                [[UIPasteboard.typeAutomatic: text]],
                options: [.localOnly: true]
            )
        }
    }
}
