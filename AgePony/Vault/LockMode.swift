//
//  LockMode.swift
//  AgePony
//
//  How the OS gate protects the vault (4.0.0). Orthogonal to the app-owned
//  password/PIN (PasswordKeyBlob): when a password is set it is its own gate,
//  whatever this mode is.
//
//  iOS has two OS-gate modes, not Android's three. `.deviceOwnerAuthentication`
//  already gives device-passcode fallback for free, so there is no separate
//  "device credential" mode to add — biometric already covers the
//  no-fingerprint-device case at the OS layer.
//
//    - .biometric: the Keychain master key sits behind a biometric ACL
//      (`.biometryCurrentSet .or .devicePasscode`). Face ID / Touch ID, or the
//      device passcode as fallback, is required at every unlock. Today's
//      default and the pre-4.0.0 behavior.
//    - .none: no OS prompt. The master key is stored under a plain
//      `WhenUnlockedThisDeviceOnly` accessibility with no access control, so it
//      loads with no prompt. If an app password is set, that password is the
//      real gate; with neither, the vault opens unprotected (still inside the
//      app sandbox + device passcode at the OS storage layer).
//

import Foundation

public enum LockMode: String, Codable, CaseIterable, Sendable {
    case biometric = "biometric"
    case none = "none"

    /// Parse a stored key; unknown values fall back to the safest gate.
    public static func fromKey(_ key: String) -> LockMode {
        LockMode(rawValue: key) ?? .biometric
    }

    public var requiresBiometricACL: Bool { self == .biometric }
}

/// Which input the app password uses. Cosmetic only — a PIN is a password with
/// a numeric keyboard; the crypto path (constant-time comparison, scrypt KDF) is
/// identical, which is what keeps duress comparison one code path.
public enum UnlockSecretKind: String, Codable, CaseIterable, Sendable {
    case password
    case pin

    public var displayNoun: String {
        switch self {
        case .password: return "password"
        case .pin:      return "PIN"
        }
    }
}
