//
//  AppTheme.swift
//  AgePony
//
//  User-selectable appearance override (4.0.0). System follows the device;
//  Light and Dark force a scheme. Stored as an app preference and applied at
//  the root via `.preferredColorScheme`.
//

import SwiftUI

enum AppTheme: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .system: return "System"
        case .light:  return "Light"
        case .dark:   return "Dark"
        }
    }

    /// The SwiftUI color scheme to force, or nil to follow the system.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light:  return .light
        case .dark:   return .dark
        }
    }

    static let storageKey = "com.agepony.app.settings.theme"
}
