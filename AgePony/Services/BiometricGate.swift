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
//  In that mode an in-app prompt also has to see the same enrolled faces or
//  fingers the vault was opened under (5.1.1, M-3). A new enrolment makes it
//  throw `.unavailable`, and the caller asks for the app password instead.
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
        lastOwnerCheck = nil
        recentLock.unlock()
    }

    private nonisolated static func remember(_ context: LAContext) {
        recentLock.lock()
        let now = MonotonicClock.millis()
        recent = (context, now)
        lastOwnerCheck = now
        recentLock.unlock()
    }

    // MARK: - Enrolment the vault was opened under (5.1.1, M-3)
    //
    // The Face ID only Keychain item is tied to what was enrolled when it was
    // written, so a new face can't open the vault at the lock screen. An in-app
    // prompt evaluates a fresh context, which any face enrolled now passes. So
    // the biometric state is kept when the vault opens in that mode (or the item
    // is written again), and each in-app prompt is compared against it. Lock
    // clears it. Only the opaque state hash is kept, never a context.

    private nonisolated(unsafe) static var unlockEnrolment: Data?
    private nonisolated(unsafe) static var enrolmentChangeSeen = false

    /// How an in-app prompt's enrolment compares with the one kept at unlock.
    nonisolated enum EnrolmentCheck: Equatable {
        case unchanged
        /// Something was enrolled or removed since the vault opened.
        case changed
        /// Nothing kept, or nothing to compare: not a pass.
        case unknown
    }

    /// The comparison itself. Only `.unchanged` lets a prompt pass.
    nonisolated static func compareEnrolment(recorded: Data?, current: Data?) -> EnrolmentCheck {
        guard let recorded, let current, !recorded.isEmpty, !current.isEmpty else { return .unknown }
        return recorded == current ? .unchanged : .changed
    }

    /// The enrolment state `context` saw. Set once the context has evaluated a
    /// biometric policy, or `canEvaluatePolicy` succeeded for one.
    nonisolated static func enrolmentState(of context: LAContext) -> Data? {
        if #available(iOS 18.0, *) {
            return context.domainState.biometry.stateHash
        }
        return context.evaluatedPolicyDomainState
    }

    /// Keep `state` as the enrolment the vault was opened under.
    nonisolated static func recordUnlockEnrolment(_ state: Data?) {
        recentLock.lock()
        unlockEnrolment = state
        enrolmentChangeSeen = false
        recentLock.unlock()
    }

    /// Keep what is enrolled right now, for when the Face ID only item has just
    /// been written again (it binds the same set).
    nonisolated static func recordCurrentEnrolment() {
        let ctx = LAContext()
        var err: NSError?
        let state = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
            ? enrolmentState(of: ctx) : nil
        recordUnlockEnrolment(state)
    }

    /// Drop the kept enrolment (on lock).
    nonisolated static func forgetUnlockEnrolment() {
        recordUnlockEnrolment(nil)
    }

    nonisolated static func recordedEnrolment() -> Data? {
        recentLock.lock()
        defer { recentLock.unlock() }
        return unlockEnrolment
    }

    private nonisolated static func noteEnrolmentChange() {
        recentLock.lock()
        enrolmentChangeSeen = true
        recentLock.unlock()
    }

    /// Whether the last in-app prompt failed because the enrolment changed.
    /// Reading it clears it, so the note shows once per prompt.
    nonisolated static func takeEnrolmentChangeNotice() -> Bool {
        recentLock.lock()
        defer { recentLock.unlock() }
        let seen = enrolmentChangeSeen
        enrolmentChangeSeen = false
        return seen
    }

    /// What the app password sheet says after a changed enrolment, worded like
    /// the lock screen's.
    static func enrolmentChangedText(noun: String) -> String {
        let name = biometryName()
        let changed = String(localized: "\(name) changed on this iPhone, so AgePony asks for your \(noun) here instead. After you next unlock the vault with your \(noun), \(name) works again.")
        let check = name == "Touch ID"
            ? String(localized: "If you didn't change \(name) yourself, check Settings > \(name) & Passcode for a fingerprint you didn't add before you enter your \(noun).")
            : String(localized: "If you didn't change \(name) yourself, check Settings > \(name) & Passcode for an appearance you didn't add before you enter your \(noun).")
        return changed + " " + check
    }

    // MARK: - Owner check window (5.1.1, H-1)
    //
    // Setting the first app password needs a Face ID or passcode check first.
    // Typing and confirming a password can take longer than the 30 second
    // context lifetime above, so the time of the last successful in-app prompt
    // is kept separately. It is only a time, never a context, and lock clears it.

    private nonisolated(unsafe) static var lastOwnerCheck: UInt64?

    /// Whether an in-app Face ID or passcode prompt succeeded within `window`.
    public nonisolated static func ownerConfirmed(withinMillis window: UInt64) -> Bool {
        recentLock.lock()
        defer { recentLock.unlock() }
        guard let at = lastOwnerCheck else { return false }
        let now = MonotonicClock.millis()
        return now >= at && now - at <= window
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
    ///
    /// `checkEnrolment` (5.1.1, M-3): an in-app prompt passes only when the
    /// enrolment matches the one kept at unlock; otherwise it throws
    /// `.unavailable`. The lock screen passes false: the Keychain item does that
    /// check there.
    public static func biometricOnlyContext(reason: String, remember keep: Bool = true,
                                            checkEnrolment: Bool = true) async throws -> LAContext {
        if checkEnrolment { _ = takeEnrolmentChangeNotice() }
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
        // Nothing recorded at unlock (the item rewrite failed, say): no Face ID
        // prompt could count, so go straight to the password (5.1.1, M-3).
        if checkEnrolment, recordedEnrolment() == nil {
            ctx.invalidate()
            throw BiometricGateError.unavailable
        }
        // Known to have changed already: go straight to the password instead of
        // a Face ID prompt that can't count (5.1.1, M-3).
        if checkEnrolment,
           compareEnrolment(recorded: recordedEnrolment(), current: enrolmentState(of: ctx)) == .changed {
            ctx.invalidate()
            noteEnrolmentChange()
            throw BiometricGateError.unavailable
        }
        let failure = String(localized: "\(name) didn't confirm it's you.")
        do {
            let ok = try await ctx.evaluatePolicy(policy, localizedReason: reason)
            if !ok { throw BiometricGateError.failed(failure) }
            // Checked again on what the prompt itself saw; only this one counts.
            if checkEnrolment {
                let check = compareEnrolment(recorded: recordedEnrolment(), current: enrolmentState(of: ctx))
                guard check == .unchanged else {
                    // A face or finger the vault wasn't opened under: never hand
                    // this context on (5.1.1, M-3).
                    ctx.invalidate()
                    if check == .changed { noteEnrolmentChange() }
                    throw BiometricGateError.unavailable
                }
            }
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
