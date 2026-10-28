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
//  Face ID only (5.1.0, E6): while the vault uses that lock, every prompt here
//  is Face ID or Touch ID alone, with no passcode button. That covers the lock
//  screen and the in-app prompts, so the context a decrypt hands to a Secure
//  Enclave key never comes from the passcode either.
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

    /// The name of this device's biometric, whether or not anything is enrolled
    /// right now (5.1.0, E6). `biometryType` is filled in by `canEvaluatePolicy`
    /// even when it fails, so this still says "Face ID" after a Face ID reset.
    public static func biometryName() -> String {
        let ctx = LAContext()
        var err: NSError?
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
        switch ctx.biometryType {
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default:       return "Face ID"
        }
    }

    /// Whether in-app prompts must leave the passcode out: the vault is set to
    /// Face ID only.
    static var biometryOnly: Bool { Vault.storedLockMode == .biometricOnly }

    /// Why Face ID or Touch ID can't be used right now, if it can't (E6 review).
    public enum BiometryState: Equatable {
        case available
        /// Too many failed tries; the device passcode turns it back on.
        case lockedOut
        /// The hardware is there but nothing is enrolled.
        case notEnrolled
        /// Any other reason (no hardware, AgePony not allowed to use it, no
        /// passcode).
        case unavailable
    }

    public static func biometryState() -> BiometryState {
        var err: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) { return .available }
        switch err?.code ?? 0 {
        case LAError.Code.biometryLockout.rawValue:      return .lockedOut
        case LAError.Code.biometryNotEnrolled.rawValue:  return .notEnrolled
        default:                                         return .unavailable
        }
    }

    /// The fallback sentence when a prompt fails, worded for the lock mode:
    /// the passcode isn't mentioned in Face ID only mode.
    static var didNotConfirmText: String {
        if biometryOnly {
            let name = biometryName()
            return String(localized: "\(name) didn't confirm it's you.")
        }
        return String(localized: "Face ID or the passcode didn't confirm it's you.")
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
    /// and "reveal sensitive material" prompts. In Face ID only mode (E6) this
    /// is Face ID or Touch ID alone.
    public static func authenticate(reason: String) async throws {
        if biometryOnly {
            _ = try await biometricOnlyContext(reason: reason)
            return
        }
        let ctx = LAContext()
        ctx.localizedFallbackTitle = String(localized: "Use passcode")
        var err: NSError?
        let policy: LAPolicy = .deviceOwnerAuthentication  // biometric + passcode
        guard ctx.canEvaluatePolicy(policy, error: &err) else {
            throw BiometricGateError.unavailable
        }
        let failure = String(localized: "Face ID or the passcode didn't confirm it's you.")
        do {
            let ok = try await ctx.evaluatePolicy(policy, localizedReason: reason)
            if !ok { throw BiometricGateError.failed(failure) }
            remember(ctx)
        } catch let gateError as BiometricGateError {
            throw gateError
        } catch let laError as LAError {
            switch laError.code {
            case .userCancel, .systemCancel, .appCancel:
                throw BiometricGateError.userCancelled
            default:
                // A plain sentence for the code, never the system's own text (5.1.0, U5).
                throw BiometricGateError.failed(UserMessage.text(for: laError, fallback: failure))
            }
        } catch {
            throw BiometricGateError.failed(UserMessage.text(for: error, fallback: failure))
        }
    }

    /// Face ID or Touch ID alone, with no passcode button (5.1.0, E6). Returns
    /// the evaluated context, which the Face ID only unlock hands to the
    /// Keychain and a Secure Enclave key takes instead of asking again.
    ///
    /// When biometrics can't be evaluated at all (none enrolled, not allowed,
    /// locked out) this throws `.unavailable`, so callers that have the app
    /// password fall back to it (`OwnerCheck.authenticate`, the lock screen).
    ///
    /// `remember: false` keeps the context out of `recentContext()`. The lock
    /// screen passes it: the default lock never shared its unlock prompt with
    /// Secure Enclave keys, and Face ID only doesn't either.
    public static func biometricOnlyContext(reason: String, remember keep: Bool = true) async throws -> LAContext {
        let ctx = LAContext()
        // An empty title hides the fallback button, so the sheet offers no way
        // to the passcode.
        ctx.localizedFallbackTitle = ""
        var err: NSError?
        let policy: LAPolicy = .deviceOwnerAuthenticationWithBiometrics
        let name = biometryName()
        guard ctx.canEvaluatePolicy(policy, error: &err) else {
            throw BiometricGateError.unavailable
        }
        let failure = String(localized: "\(name) didn't confirm it's you.")
        do {
            let ok = try await ctx.evaluatePolicy(policy, localizedReason: reason)
            if !ok { throw BiometricGateError.failed(failure) }
            if keep { remember(ctx) }
            return ctx
        } catch let gateError as BiometricGateError {
            throw gateError
        } catch let laError as LAError {
            switch laError.code {
            case .userCancel, .systemCancel, .appCancel, .userFallback:
                throw BiometricGateError.userCancelled
            case .biometryLockout, .biometryNotEnrolled, .biometryNotAvailable:
                throw BiometricGateError.unavailable
            default:
                throw BiometricGateError.failed(UserMessage.text(for: laError, fallback: failure))
            }
        } catch {
            throw BiometricGateError.failed(UserMessage.text(for: error, fallback: failure))
        }
    }
}
