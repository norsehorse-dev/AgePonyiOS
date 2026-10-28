# AgePony iOS 5.1.0 RC2b: E6 Face ID only lock

Status: code done Oct 26 2026, not built yet. Needs `xcodebuild test` and the device list below.
Decisions followed: E6 in `AgePony_5.1.0_Evaluation_Requests.md`, Q2 and Q3 (decided Oct 26).

## Design as built

**New lock mode.** `LockMode.biometricOnly` (raw value `"biometricOnly"`), shown as "Face ID only",
"Touch ID only" or "Optic ID only" from `BiometricGate.biometryName()`. Existing raw values
(`biometric`, `none`) are unchanged, so a 5.0.1 vault opens as before in either mode. An unknown
stored value still reads as `.biometric`, never as Face ID only.

**Vault key in the Keychain.** In this mode the master key is stored behind
`[.biometryCurrentSet]` only (`BiometryOnlyKeyProtection.flags`): no `.devicePasscode`, no
`.userPresence`, no `.or`, and never `.biometryAny`. It uses the same staging order as the C1
path (staging copy first, then the real item), so a refusal at the staging copy changes nothing.
`vault.keyProtection` records `"biometryCurrentSetOnly"`, which `MasterKeyProtection` does not
parse, so the C1 ladder, `storedProtection` and the passcode-only upgrade in `unlock` are
untouched. The ladder and onboarding's keychainRefused path are still only for the default lock;
Face ID only has no ladder. If iOS refuses the item, `KeychainError.biometryOnlyRefused(status)`
is thrown, `setLockMode` puts the previous mode back and rewrites its item, and Lock settings
shows "iOS wouldn't store the vault key behind Face ID or Touch ID alone (code N). The lock is
unchanged."

**Unlock.** `Vault.unlock` in Face ID only mode calls `loadBiometryOnlyKey`:

1. If the Keychain item doesn't carry the Face ID only tag, it doesn't read the item at all
   (throws `notFound`, so the password field is the way in). A copy the passcode could open is
   never used in this mode. (Review fix 3: the tag is on the item, not in preferences.)
2. `BiometricGate.biometricOnlyContext` evaluates `.deviceOwnerAuthenticationWithBiometrics` with
   `localizedFallbackTitle = ""`, so the sheet has no passcode button. Cancel and fallback map to
   `userCancelled`; lockout and nothing enrolled give `.unavailable` (review fix 1), and the
   lock screen words the lockout case itself.
3. The Keychain read gets that context (`kSecUseAuthenticationContext`), so there is one prompt.
4. A missing item, `errSecAuthFailed` or `errSecInteractionNotAllowed` after Face ID said yes is
   what a Face ID reset or a new face leaves: `KeychainError.biometryChanged`.

**Recovery.** The mode needs an app password (`LockMode.needsAppPassword`). `setLockMode` refuses
it without one (`VaultError.noAppPassword`), `removeAppPassword` refuses while it is set
(`VaultError.passwordIsOnlyUnlock`), and `enforceKeychainPolicy` falls back to the default lock if
the two ever disagree, rather than leave a vault nothing opens. Every password unlock already runs
`enforceKeychainPolicy`, which now writes a fresh biometry-only item in this mode, so Face ID works
again after one password unlock. Best effort: with nothing enrolled at that moment the add fails
quietly and the password keeps working.

**Device passcode.** No path opens the vault with it in this mode: the item's ACL has no passcode,
the lock-screen prompt has no passcode button, the guard in step 1 skips any item stored another
way, and L-15 re-auth uses the app password (always set in this mode). In-app prompts
(`BiometricGate.authenticate`: decrypt, reveal key, sign, key transfer) are also Face ID or Touch ID
alone while the vault is on Face ID only, so the context a decrypt hands to a Secure Enclave key
never comes from the passcode.

**Lock screen.** In Face ID only mode it starts Face ID by itself on launch and on return. The
screen shows "Use Face ID" as the primary button and "Use password" (or "Use PIN") under it, with
the footer "The device passcode doesn't open AgePony." After `biometryChanged`, `.unavailable`, a
failed match or a lockout, the password field comes up at once with a sentence saying why, and
Face ID stops starting by itself until the next successful unlock.

**Duress.** Unchanged H-1: setting a duress password sets the mode to No lock. `setLockMode`
refuses any mode but No lock while duress is set (before it only checked `.biometric`), and Face ID
only isn't listed in the picker while duress is set.

**Lock settings.**

- The picker lists Face ID only when Face ID or Touch ID is enrolled and no duress password is set,
  and always while it is the current mode.
- Choosing it opens a dialog that says what it means. With a password set: "Use Face ID only" or
  Cancel, no re-auth (not a weakening). Without one: "Set a password or PIN", which opens the
  existing password sheet and then switches the mode once the password is saved.
- Leaving Face ID only (to Face ID or No lock) asks for the app password first (L-15).
- Remove password is refused in Face ID only mode with a sentence saying why.
- Footers say what each mode accepts:
  - Face ID: "Face ID, or your device passcode, unlocks the vault. Any app password you set below
    also works." plus, when it can be chosen, a sentence that Face ID only leaves the passcode out
    and uses an app password or PIN as the way back in.
  - Face ID only: only Face ID or the app password opens the vault, the device passcode doesn't,
    and after a reset or change in Settings the password once brings Face ID back. When the vault
    holds Secure Enclave decryption keys, it adds that keys made before the switch keep the
    protection they were made with, and one that asks on each use still accepts the passcode.
  - No lock: unchanged.

**Hardware keys (Q3).** `SecureEnclaveKeyAgreement.generate(protection:)` takes
`SecureEnclaveKeyProtection` (`.noPrompt`, `.userPresence`, `.biometryCurrentSet`, flags
`[.privateKeyUsage]` plus nothing, `.userPresence` or `.biometryCurrentSet`).
`generate(requirePresence:)` stays and forwards, so existing callers are unchanged. Generate
identity > Hardware key offers "Require Face ID (no passcode)" only while the vault is on Face ID
only. When on, "Ask for Face ID each time" shows on and greyed out, the footer says the passcode
doesn't work for this key, and a warning says a reset of Face ID or anything added to it destroys
the key for good and points to Settings > Also encrypt to. Nothing is recorded in the vault:
`requirePresence` was never stored either, the Enclave enforces the access control on every use,
and decrypt doesn't need to know. Existing keys are unchanged.

## Per-file changes

| File | Change |
|---|---|
| `AgePony/Vault/LockMode.swift` | `.biometricOnly` case; `requiresBiometricACL` covers it; new `acceptsDevicePasscode`, `needsAppPassword`, `isAvailable(duressSet:biometryEnrolled:)`. |
| `AgePony/Vault/KeychainStore.swift` | `KeychainError.biometryOnlyRefused(OSStatus)` and `.biometryChanged` with messages; `BiometryOnlyKeyProtection` (flags, stored name); `storeBiometryOnlyMasterKey`; `storedIsBiometryOnly`; `loadMasterKey(prompt:context:)` (context optional, old calls unchanged). Ladder untouched. |
| `AgePony/Vault/Vault.swift` | `storedLockMode` (static); `bootstrap` never starts in Face ID only; `unlock` reads through `loadBiometryOnlyKey` in that mode and skips the C1 upgrade there; `removeAppPassword` refused in the mode; `setLockMode` duress check covers every mode but No lock, requires a password for Face ID only, and restores the old item on failure; `enforceKeychainPolicy` stores the biometry-only item. No new `VaultError` cases. |
| `AgePony/Services/BiometricGate.swift` | `biometryName()`; `biometricOnlyContext(reason:)`; `authenticate` goes biometric-only while the vault is on Face ID only. |
| `AgePony/Features/Home/RootView.swift` | Face ID first on the lock screen, "Use password" second, auto-start, `passwordFallback`, messages for `biometryChanged` and unavailable biometrics. |
| `AgePony/Features/Settings/LockSettingsView.swift` | Picker entry, confirm dialog, password-first flow, L-15 when leaving the mode, remove-password guard, footers. |
| `AgePony/Features/Onboarding/GenerateIdentityView.swift` | "Require Face ID (no passcode)" toggle, warning, `generate(protection:)`. |
| `Sources/AgePonyCore/Hardware/SecureEnclaveKeyAgreement.swift` | `SecureEnclaveKeyProtection`, `generate(protection:)`, header comment. |
| `AgePonyTests/BiometricOnlyLockTests.swift` | New, see below. |

OnboardingView needed no change: setup always uses the default lock.

## Tests

`AgePonyTests/BiometricOnlyLockTests.swift` (Swift Testing, `@MainActor`, like
`KeyPortabilityTests`):

- LockMode raw values stable, round trip through `fromKey` and Codable, unknown values fall back
  to `.biometric`.
- Only `.biometric` accepts the passcode; only `.biometricOnly` needs a password; both biometric
  modes keep a prompted Keychain copy.
- Availability: Face ID only is off with duress and without enrolled biometrics; Face ID is off
  with duress; No lock is always available.
- `BiometryOnlyKeyProtection.flags == [.biometryCurrentSet]` and contains none of
  `.devicePasscode`, `.userPresence`, `.or`, `.biometryAny`.
- Face ID only is not a ladder step: its stored name isn't a `MasterKeyProtection` value and no
  ladder step has its flags.
- The refusal message carries the OSStatus.
- Secure Enclave protection flags for all three options; `.biometryCurrentSet` has no passcode
  or user presence.

`KeychainProtectionTests.swift` is unchanged and should still pass: `MasterKeyProtection` has no
new case.

## Compile-uncertain spots

1. `KeychainProtectionTests` (C1, not built yet either) is an `XCTestCase` in a test target without
   default MainActor isolation, calling `MasterKeyProtection` members that are MainActor-isolated
   under the app's default isolation. If Xcode reports "call to main actor-isolated ... in a
   synchronous nonisolated context", add `@MainActor` to that class. Not changed here because it
   isn't part of E6.
2. `BiometricGate.biometryOnly` reads `Vault.storedLockMode`; both are MainActor (default
   isolation), and `authenticate` is too. Should be fine; flagging because it is a new
   cross-type static.
3. `KeychainError` cases are matched in `catch` patterns with a `where` clause on the OSStatus
   (`Vault.loadBiometryOnlyKey`). Standard Swift, but it is the first such pattern in the file.
4. `String(localized:)` with `\(String(status))` in `KeychainError.errorDescription`: converted to
   String on purpose so the interpolation doesn't depend on `Int32` support in `LocalizationValue`.

## Behavior to confirm on a device (not checkable in the simulator)

- Which status `SecItemCopyMatching` returns for a `.biometryCurrentSet` item after an enrolment
  change. The code treats `errSecItemNotFound`, `errSecAuthFailed` and
  `errSecInteractionNotAllowed` as "Face ID changed". If it is something else, the lock screen shows
  the generic Keychain message and the password still works; add the code to that catch.
- That a context evaluated with `.deviceOwnerAuthenticationWithBiometrics` satisfies the item
  without a second sheet.

## Device test list

Run on a phone with a passcode and Face ID (and once on a Touch ID phone for the wording). Watch the
system sheet each time: it must never show "Enter Passcode" in this mode.

1. **Face ID only on.** Lock settings > Lock > Face ID only. With a password set: dialog, then the
   mode switches with no password prompt. Without one: dialog > Set a password or PIN > save; the
   mode switches after the sheet closes. Footer text matches the mode.
2. **Lock and unlock.** Leave the app past the grace period, come back: Face ID starts by itself and
   opens the vault. Kill and relaunch: same.
3. **Wrong face.** Cover the face or use another person: the sheet retries, then fails with no
   passcode button. The lock screen shows the password field and a sentence; the password opens
   the vault.
4. **Lockout.** Fail Face ID until it locks out: the message says to lock and unlock the iPhone
   with the passcode to turn Face ID back on. The password still opens AgePony. After that, Face ID
   works again.
5. **Face ID changed then recovery.** Settings > Face ID & Passcode > Set Up an Alternate
   Appearance (or Reset Face ID and enrol again). Open AgePony: Face ID succeeds at the sheet but
   the lock screen says Face ID changed and shows the password field. Enter the password: the vault
   opens. Lock again: Face ID opens it with no password.
6. **Face ID reset, nothing enrolled.** Reset Face ID and don't enrol: the lock screen says Face ID
   isn't available and shows the password field; the password opens the vault. Enrol again, enter
   the password once, then Face ID works.
7. **Passcode never opens it.** In every case above there is no path to the passcode: no sheet
   button, no fallback after failures, nothing in Settings > Lock (leaving the mode asks for the app
   password, not the passcode). Also check reveal private key and decrypt: only Face ID is offered.
8. **Duress disables the mode.** Set a duress password: the mode becomes No lock, Face ID only is no
   longer in the picker, the lock screen shows only the password. Remove duress: Face ID only is
   listed again.
9. **Switching away asks to confirm.** From Face ID only, choose Face ID or No lock: the app
   password sheet comes first; Cancel leaves Face ID only. After confirming Face ID, the device
   passcode works at the sheet again.
10. **Remove password refused.** In Face ID only, Remove password shows the sentence and does
    nothing.
11. **New hardware key without the toggle.** Vault on Face ID only, Generate identity > Hardware key,
    "Require Face ID (no passcode)" off, "Ask for Face ID each time" on: decrypt a file to it works
    with one Face ID prompt. Switch the vault back to Face ID: decrypt still works, and the passcode
    is accepted when Face ID is skipped.
12. **New hardware key with the toggle.** Toggle on: the warning shows, "Ask for Face ID each time"
    is hidden; turning the toggle off shows it again as it was. Save, encrypt a file to it, decrypt with Face ID: works, one prompt.
    Switch the vault to Face ID and decrypt using the passcode at the app prompt: the Enclave either
    asks for Face ID itself or the decrypt fails for that key; the passcode never opens it. Add an alternate appearance: decrypt fails for this
    key for good (expected); a file also encrypted to the "Also encrypt to" key still opens.
13. **Toggle not offered elsewhere.** Vault on Face ID or No lock: the toggle isn't shown.
14. **Refusal path.** If any test phone refuses the item, the alert shows the code and the previous
    mode still unlocks.
15. **Upgrade.** A 5.0.1 vault in Face ID mode and one in No lock plus password still open as before
    (E6 acceptance 5), and the C1 device matrix still passes.

## For the files owned by the YubiKey item

Superseded by the review fixes below: both suggestions are now done.

- **SettingsView:** there is no lock-mode summary in Settings today ("Lock & password" is a plain
  link), so no wording change is needed. One suggestion: the "In-app biometric prompts" toggle
  treats `BiometricGateError.unavailable` as "nothing to check" and turns prompts off. In Face ID
  only mode, `.unavailable` now also means "Face ID isn't enrolled right now", so turning prompts off
  there could ask for the app password when `vault.hasAppPassword` (as `OwnerCheck` in
  `PortabilityCommon.swift` already does) instead of skipping the check.
- **UserMessage:** no new case needed. No `VaultError` case was added, and the new `KeychainError`
  cases carry their own `errorDescription`, which `UserMessage.text(for:)` already returns. Optional:
  `biometricGate(.unavailable)` says "Face ID, Touch ID and the passcode aren't available on this
  device.", which is slightly off when Face ID only's prompt can't run because nothing is enrolled.
  A wording such as "Face ID or Touch ID isn't available right now." would fit both.

## Build

```
xcodebuild test -project AgePony.xcodeproj -scheme AgePony -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Review fixes

From the independent RC2b review. Same rules: not built yet, no commits.

### Security

1. **Face ID unavailable or locked out, in-app prompts.** `OwnerCheck` (`PortabilityCommon.swift`)
   gained `authenticate(_ vault:, reason:)`: `BiometricGate.authenticate` first, and in Face ID only
   mode, when that throws `.unavailable`, the existing app password sheet, awaited through a
   continuation (closing the sheet throws `userCancelled`, so every caller's existing catch works).
   `biometricOnlyContext` now throws `.unavailable` for lockout and nothing enrolled, both before
   and during the prompt, so both cases reach the password. Used in DecryptFlow, TextDecryptView,
   MigrateFlow, EncryptFlow (signing), SignFileView, IdentityDetailView (reveal) and SettingsView
   (turning in-app prompts off), each with `@State ownerCheck` and `.ownerCheck(ownerCheck, vault:)`.
   Outside Face ID only mode nothing changes. The passcode is never offered in that mode.
   A password confirm hands no context to Secure Enclave keys: a key made with "Require Face ID"
   then can't decrypt until Face ID works; software keys and YubiKeys still do. A key made before
   the switch with per-use confirmation asks for itself and accepts the passcode, as the Lock
   settings help already says.

   Compile note: `OwnerCheck.authenticate` waits on the sheet with `withCheckedContinuation` inside
   a MainActor `@Observable` class (`waiting` is `@ObservationIgnored`). The sheet's `onDismiss`
   resumes it with false; a success resumes it first, so the dismissal does nothing.
2. **Face ID only with no password.** `LockMode.normalized(hasAppPassword:)` returns `.biometric`
   for that case. Applied in `migrateLegacySettings` (on launch) and at the top of `Vault.unlock`.
   After an unlock under the default lock, an item still tagged Face ID only is rewritten through
   the C1 ladder, so the passcode is a way back in again.
3. **Item tag, not preferences.** `addBiometryOnlyMasterKey` sets `kSecAttrDescription =
   "biometryCurrentSetOnly"` (`KeychainStore.biometryOnlyItemAttributes`).
   `storedIsBiometryOnly` is an attribute-only query filtered on that tag
   (`biometryOnlyTagQuery`: no data, `kSecUseAuthenticationUIFail`), on the real item or the staging
   copy when there's no real item. `errSecInteractionNotAllowed` counts as "tagged" since the filter
   already matched. A 5.0.1 rewrite has no tag, so 5.1.0 skips the item, asks for the password, and
   the password unlock writes a tagged one.
4. **No passcode UI from the Keychain read.** `context.interactionNotAllowed = true` after the
   Face ID prompt and before the read; a failure there is already mapped to `biometryChanged`.
5. **Unlock context not kept.** `biometricOnlyContext(reason:remember:)`; the lock screen passes
   `remember: false`, so the unlock prompt isn't handed to Secure Enclave keys for 30 seconds.
6. **Face ID changed text** adds: "If you didn't change Face ID yourself, check Settings > Face ID &
   Passcode for an appearance you didn't add before you enter your password." (Touch ID: "a
   fingerprint"). A lockout at the lock screen has its own sentence.
7. **No lock with a password to an OS lock** (Face ID only or Face ID / passcode) now asks for the
   app password first (L-15). For Face ID only, the explanation dialog follows the check.

### Behavior

8. **Password change in Face ID only mode** with Face ID not enrolled: the Keychain step after
   saving the password is `try?` in that mode, so the change reports success; the next password
   unlock writes the Face ID item.
9. **YubiKey PIN length** is checked before any tap: `DecryptIdentities.pinLengthIsValid` (6 to 8
   UTF-8 bytes); otherwise the prompt comes back with "A YubiKey PIN is 6 to 8 characters." and no
   try is spent.
10. **`parseIdentityFile`** reads `PIN policy:` only before the first stub, so a multi-identity
    file gets the first identity's policy.
11. **PIN cleared at the top** of `runDecrypt`, `runMigrate` and `startDecrypt`
    (`let pinEntry = yubiKeyPIN; yubiKeyPIN = nil`), so no early return leaves it set.
12. **Lock settings: lockout vs not enrolled.** `BiometricGate.biometryState()` (available, lockedOut,
    notEnrolled, unavailable). Face ID only is listed whenever the phone has Face ID or Touch ID and
    no duress is set; choosing it while locked out says to unlock the iPhone with the passcode to turn
    Face ID back on and choose it again; with nothing enrolled it says where to set Face ID up.
13. **Wording per mode.** `BiometricGate.didNotConfirmText` replaces "Face ID or the passcode didn't
    confirm it's you." in TextDecryptView, MigrateFlow, EncryptFlow, SignFileView and OwnerCheck.
    SettingsView says "Face ID isn't available right now. AgePony asks for your app password
    instead, never the device passcode." in Face ID only mode. `UserMessage` for
    `BiometricGateError.unavailable` says "Face ID isn't available right now." in that mode.
14. **"Ask for Face ID each time"** is hidden, not overridden, while "Require Face ID (no passcode)"
    is on, so turning the latter off shows it with the value the user left.
15. **Refusals vs save failures.** Lock settings refusals (Face ID only can't be chosen, no device
    passcode, Remove password refused) use a "Can't change the lock" alert; "Couldn't save" is
    only for failed saves.

### Tests added

- `BiometricOnlyLockTests`: `normalized(hasAppPassword:)`; the item attributes carry the tag and no
  separate accessibility; the tag query reads attributes only with UI fail; YubiKey PIN length
  (5, 6, 8, 9 characters, and multibyte counted as bytes).
- `YubiKeyPivTests.test_identityFile_pinPolicyFromFirstStubOnly` (core): two-identity files in both
  orders take the first identity's policy.

### Device checks added

- Face ID only, Face ID locked out (fail it until it locks): decrypt, reveal key, sign and turning
  in-app prompts off each ask for the app password, never the passcode.
- Face ID only, Face ID reset with nothing enrolled: same as above.
- Most important: with `interactionNotAllowed` set, a normal Face ID unlock must still open the
  vault in one prompt. If every unlock instead says Face ID changed, remove that line in
  `Vault.loadBiometryOnlyKey` (the item's own ACL still keeps the passcode out).
- Downgrade check, if a 5.0.1 build is at hand: Face ID only on 5.1.0, install 5.0.1, remove the
  password there, reinstall 5.1.0: the vault opens on the default lock and the passcode works again.
- No lock with a password, choose Face ID: the app password is asked first.
