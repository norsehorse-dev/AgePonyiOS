//
//  LockMode.swift
//  AgePony
//
//  How the OS gate protects the vault (4.0.0). Orthogonal to the app-owned
//  password/PIN (PasswordKeyBlob): when a password is set it is its own gate,
//  whatever this mode is.
//
//  `.deviceOwnerAuthentication` already gives device-passcode fallback for free,
//  so there is no separate "device credential" mode as on Android: biometric
//  covers the no-fingerprint-device case at the OS layer.
//
//    - .biometric: the Keychain master key sits behind a system prompt
//      (`.biometryCurrentSet .or .devicePasscode`, or a lower step of the 5.1.0
//      setup ladder). Face ID / Touch ID, or the device passcode as fallback,
//      is required at every unlock. Today's default and the pre-4.0.0 behavior.
//    - .biometricOnly (5.1.0, E6): "Face ID only". The master key sits behind
//      `.biometryCurrentSet` alone, so the device passcode can't open it. It
//      needs the app password: a reset of Face ID or a new face invalidates
//      the item, and the password (PasswordKeyBlob v2) is the way back in,
//      after which a fresh item is written. Not part of the setup ladder, and
//      not available while a duress password is set (H-1).
//    - .none: no OS prompt. The master key is stored under a plain
//      `WhenUnlockedThisDeviceOnly` accessibility with no access control, so it
//      loads with no prompt. If an app password is set, that password is the
//      real gate; with neither, the vault opens unprotected (still inside the
//      app sandbox + device passcode at the OS storage layer).
//

import Foundation

public enum LockMode: String, Codable, CaseIterable, Sendable {
    case biometric = "biometric"
    case biometricOnly = "biometricOnly"
    case none = "none"

    /// Parse a stored key; unknown values fall back to the default gate, which
    /// always has a way in.
    public static func fromKey(_ key: String) -> LockMode {
        LockMode(rawValue: key) ?? .biometric
    }

    /// Whether the Keychain copy of the vault key sits behind a system prompt.
    public var requiresBiometricACL: Bool { self == .biometric || self == .biometricOnly }

    /// Whether the device passcode can open the vault in this mode.
    public var acceptsDevicePasscode: Bool { self == .biometric }

    /// Whether this mode can't be used without an app password (E6: the
    /// password is how the vault opens after a Face ID reset).
    public var needsAppPassword: Bool { self == .biometricOnly }

    /// The mode to use instead when this one can't stand as stored, or nil when
    /// it can. Face ID only without an app password (an older version removed
    /// it) becomes the default lock (E6 review).
    public func normalized(hasAppPassword: Bool) -> LockMode? {
        needsAppPassword && !hasAppPassword ? .biometric : nil
    }

    /// Whether the mode can be chosen now. A duress password makes the vault
    /// password-only (H-1), and Face ID only needs Face ID or Touch ID set up.
    public func isAvailable(duressSet: Bool, biometryEnrolled: Bool) -> Bool {
        switch self {
        case .biometric:     return !duressSet
        case .biometricOnly: return !duressSet && biometryEnrolled
        case .none:          return true
        }
    }
}

/// Which input the app password uses. Cosmetic only — a PIN is a password with
/// a numeric keyboard; the crypto path (constant-time comparison, scrypt KDF) is
/// identical, which is what keeps duress comparison one code path.
public enum UnlockSecretKind: String, Codable, CaseIterable, Sendable {
    case password
    case pin

    public var displayNoun: String {
        switch self {
        case .password: return String(localized: "password")
        case .pin:      return String(localized: "PIN")
        }
    }
}
