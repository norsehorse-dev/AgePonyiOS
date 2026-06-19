//
//  BiometricGate.swift
//  AgePony
//
//  Thin LocalAuthentication wrapper used for the launch gate. The Vault's
//  own Keychain ACL provides the actual cryptographic gating — this is the
//  app-level prompt that lets us show a friendly UI on top of (or instead
//  of) the system prompt for cases where the master key is already in
//  memory but we still want to re-confirm (e.g. revealing a private key,
//  decrypting a sensitive file, returning from background).
//

import Foundation
import LocalAuthentication

public enum BiometricGateError: Error, Equatable {
    case unavailable
    case userCancelled
    case failed(String)
}

public enum BiometricType {
    case faceID
    case touchID
    case opticID
    case none
}

public enum BiometricGate {

    /// What biometric is available on this device, if any. Used for copy
    /// ("Use Face ID" vs "Use Touch ID") and for hiding the toggle in
    /// Settings on devices without biometrics.
    public static func availableBiometric() -> BiometricType {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else {
            return .none
        }
        switch ctx.biometryType {
        case .faceID:  return .faceID
        case .touchID: return .touchID
        case .opticID: return .opticID
        default:       return .none
        }
    }

    /// Evaluate biometry with passcode fallback. Suitable for "unlock vault"
    /// and "reveal sensitive material" prompts.
    public static func authenticate(reason: String) async throws {
        let ctx = LAContext()
        ctx.localizedFallbackTitle = "Use Passcode"
        var err: NSError?
        let policy: LAPolicy = .deviceOwnerAuthentication  // biometric + passcode
        guard ctx.canEvaluatePolicy(policy, error: &err) else {
            throw BiometricGateError.unavailable
        }
        do {
            let ok = try await ctx.evaluatePolicy(policy, localizedReason: reason)
            if !ok { throw BiometricGateError.failed("evaluatePolicy returned false") }
        } catch let laError as LAError {
            switch laError.code {
            case .userCancel, .systemCancel, .appCancel:
                throw BiometricGateError.userCancelled
            default:
                throw BiometricGateError.failed(laError.localizedDescription)
            }
        } catch {
            throw BiometricGateError.failed(error.localizedDescription)
        }
    }
}
