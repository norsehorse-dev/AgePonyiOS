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
import AgePonyCore

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

    // MARK: - Recent context (5.0.1)
    //
    // A Secure Enclave key made with `.userPresence` asks for Face ID on every
    // use. The flows that use one have already prompted through `authenticate`,
    // so the context that prompt evaluated is kept for a few seconds and handed
    // to the Enclave, which then doesn't ask again. One prompt per operation.

    private nonisolated(unsafe) static var recent: (context: LAContext, at: UInt64)?
    private nonisolated static let recentLock = NSLock()
    private nonisolated static let recentLifetimeMillis: UInt64 = 30_000

    /// The context of a prompt that succeeded in the last 30 seconds, if any.
    public nonisolated static func recentContext() -> LAContext? {
        recentLock.lock()
        defer { recentLock.unlock() }
        guard let r = recent else { return nil }
        let now = MonotonicClock.millis()
        guard now >= r.at, now - r.at <= recentLifetimeMillis else {
            recent = nil
            return nil
        }
        return r.context
    }

    /// Drop the kept context (on lock).
    public nonisolated static func forgetRecentContext() {
        recentLock.lock()
        recent?.context.invalidate()
        recent = nil
        recentLock.unlock()
    }

    private nonisolated static func remember(_ context: LAContext) {
        recentLock.lock()
        recent = (context, MonotonicClock.millis())
        recentLock.unlock()
    }

    /// Whether this device has a passcode (5.0.1, plan 2.8). Without one, iOS
    /// refuses a Keychain item behind Face ID / Touch ID / the passcode, so the
    /// Biometric lock can't be used. Only `passcodeNotSet` counts as "no": any
    /// other reason the check fails (biometry locked out, say) still has a
    /// passcode behind it.
    public static func devicePasscodeIsSet() -> Bool {
        var err: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) { return true }
        return err?.code != LAError.Code.passcodeNotSet.rawValue
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
            remember(ctx)
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
