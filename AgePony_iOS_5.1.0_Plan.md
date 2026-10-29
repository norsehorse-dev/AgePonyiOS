# AgePony iOS 5.1.0 plan (Rev 1)

Joint release with Android 5.1.0 (versionCode 18), same number on both stores. The shared design
for each item is in `AgePony_5.1.0_Plan.md` in the Android repo; that file and its Kotlin are the
reference. This file covers the iOS side: what's different, which files, and iOS-only carryovers.
Item numbers match the Android plan.

Starting point: iOS 5.0.1 (built, store metadata committed in `a4c31e5`). The repo has no `5.0.1`
tag yet; tag it from the build that App Review accepts before any 5.1.0 work lands.

Last updated: 2026-10-16 (Rev 1, drafted). Nothing below is decided except where it says so.

---

## Status

| Item | State |
| --- | --- |
| C1. Setup fails with a passcode set (critical) | Code done Oct 26 (KeychainStore ladder, onboarding fallback, tests). Needs build, tests and the device matrix below. First item of RC1. |
| 1. YubiKey PIN before the tap | Planned. |
| 2. YubiKey PIV over USB-C | Planned, blocked on hardware (Android plan 2.4). |
| 3. Picker rows show key material | Planned (`PLANNED_FEATURES.md` item 1). |
| 5. iOS carryovers | Listed, not triaged. |
| U1 to U9 | UI restyle (no generated look), see `AgePony_5.1.0_UI_Plan.md`. Inventory done Oct 26. |
| E1 to E9 | Evaluation requests, see `AgePony_5.1.0_Evaluation_Requests.md`. E6 and E7 proposed for RC1; E8 (CryptoKit + Enclave ML-KEM) spike then its own RC. |

Item 4 (GitHub issue housekeeping) is Android repo only.

RC breakdown follows Android: RC1 = items 1 and 3, RC2 = item 2. One RC at a time.

---

## C1. Setup fails on some iPhones with a passcode set (critical)

### Report

Oct 26 2026, by email: on 4.0.1 setup stopped with "The operation couldn't be completed.
(AgePony.KeychainError error 0.)". After updating to 5.0.1 as asked, it stops with "The Keychain
refused the request (-25293: The username or passphrase you entered is not correct.)". The phone
has a passcode, runs iOS 27.0.1, and no prompt appears before the error. The user has never been
able to open the app. -25293 is errSecAuthFailed, returned by `SecItemAdd` in
`KeychainStore.addMasterKey` during `Vault.bootstrap()`.

### Why it survived 4.0.1 and the 5.0.1 fix

1. **One path, no way forward.** Every version stored the vault key at setup behind
   `[.biometryCurrentSet, .or, .devicePasscode]`. If iOS refused that, the only thing on screen
   was an alert. Android has always offered "Use a password instead" next to the biometric option,
   so the same kind of refusal there can't trap anyone. iOS had no equivalent.
2. **The code was hidden.** Up to 4.0.1 the alert showed the enum position ("error 0", which is
   `.unhandled`), not the OSStatus, so no report could say what iOS refused.
3. **5.0.1 fixed an assumed cause.** Plan 2.8 came from an App Store review on 4.0.1 ("I keep
   getting a keychain error"). With no code to go on, it named "likely cause: no device passcode"
   and checked only that a fresh install works on a phone with a passcode, on a phone that also has
   Face ID enrolled. The 5.0.1 work handled the no-passcode case and made the code visible, but
   left the single path in place for every other refusal. The device test in 2.8 tested the fix
   for the assumed cause, not the reported failure.
4. **Nothing tests it.** `KeychainStore` lives in the app target with no tests, the simulator is
   unreliable for access-controlled Keychain items, and the device passes only ever ran on one
   phone in one state (passcode plus Face ID enrolled).

### Cause on the device (to confirm)

Confirmed by a user report: passcode on, Face ID off. With no biometrics available,
iOS refuses an item whose access control includes `.biometryCurrentSet`, even with
`.or .devicePasscode`, because there is no current set to bind to. The ladder skips that step when
`BiometricGate.availableBiometric()` reports none, so this phone starts at `.userPresence`. Device
matrix case 2 (Face ID reset or turned off, passcode on) reproduces it.

Closed Oct 26: an earlier no-passcode attempt was on 4.0.1, which had no other path through
setup, so it failed the same way. No second bug.

### Fix (done Oct 26, needs build and device pass)

- `KeychainStore`: a protection ladder (`MasterKeyProtection`). With biometrics enrolled it tries
  `[.biometryCurrentSet, .or, .devicePasscode]` (what every earlier version used), then
  `.userPresence`, then `.devicePasscode` alone. Without enrolled biometrics it starts at
  `.userPresence`. Every step keeps a system prompt in front of the key. The staging copy decides
  the protection and the real item gets the same one. The one used is recorded in UserDefaults
  (`vault.keyProtection`).
- If iOS refuses every step: `KeychainError.protectionRefused([OSStatus])`, whose message lists
  the codes.
- Onboarding: a `KeychainError` from bootstrap no longer ends in an alert. It goes to the same
  screen as the no-passcode case, worded for a refusal, with the message and codes, "Use an AgePony
  password or PIN" and "Try again". Bootstrap stores the key before writing anything else, so a
  refusal leaves nothing behind.
- `Vault.unlock`: a key stored as passcode-only moves up to Face ID or Touch ID once biometrics are
  enrolled (best effort).
- Lock settings use the same ladder when switching to the Face ID lock.
- Tests: `AgePonyTests/KeychainProtectionTests.swift` (ladder order, every step keeps a prompt,
  first step unchanged, refusal message carries the codes, stored names stable).

### Device matrix (new, required for every release from 5.1.0)

Fresh install, setup through to the first identity, then lock and unlock, on each:

1. Passcode and Face ID enrolled (the case that always worked; must still get
   `currentBiometryOrPasscode`).
2. Passcode, Face ID turned off or reset (Settings > Face ID & Passcode; the reporter's case).
3. No passcode (plan 2.8 path).
4. The newest iOS major available (iOS 27 now).
5. Upgrade: a 5.0.1 vault set up in case 1 still unlocks with no change of protection.

Also check case 2 then enrolling Face ID: the next unlock moves the key up to Face ID.

### Release note and reply

Release note wording: setup no longer stops on some iPhones with a "Keychain refused the request"
error; if iOS won't use Face ID or the passcode for the vault, setup offers an AgePony password.
Tell the reporter when it ships.

## 1. YubiKey: ask for the PIN before the tap

**Source:** user email, Oct 16 2026 (credit as "a user report").

### What happens now (worse than Android)

`PivSession.keyAgreements` runs with `pin: nil` first. On `.pinRequired`,
`DecryptIdentities.prepare` returns `.needsPIN`, the flow shows the PIN sheet and calls
`prepare` again, which taps again. Then `yubiKeyPIN` is set back to nil. Nothing is remembered,
so every YubiKey decrypt on iOS is two taps, not just the first one per process as on Android.

Three callers share this: `Features/Files/DecryptFlow.swift:344`,
`Features/Text/TextDecryptView.swift:241`, `Features/Files/MigrateFlow.swift:308`.

### Change (same design as Android item 1)

- `StoredIdentity` gets an optional `pinPolicy` (`unknown`, `required`, `notRequired`) for
  `.yubikey`. `JSONDecoder` ignores unknown keys, so a 5.0.1 build reading a 5.1.0 vault is fine.
  Confirm the vault decoder isn't strict before relying on that.
- Core: `YubiKeyStub.parseIdentityFile` also returns the `PIN policy:` comment value
  (`Tests/AgePonyCoreTests/YubiKeyPivTests.swift:227` already has a fixture line to test
  against). `Piv` gains GET METADATA (INS `F7`); `PivSession.readKey` reads it on firmware 5.3+
  and returns the policy alongside the key.
- Import (`Features/Onboarding/ImportIdentityView.swift:285`): store the policy from the comment,
  or from metadata when the import taps (no `# Recipient:` line).
- `DecryptIdentities.prepare` decides before the tap: `required`/`unknown` asks for the PIN
  first (with "This key has no PIN" for `unknown`), `notRequired` taps without. Learned results
  are written back to the vault. The `.needsPIN` retry stays as the safety net. Do it once in
  `prepare` so the three callers don't each grow their own copy.
- Key transfer (`Services/Portability/KeyPortability.swift`): read and write the optional field
  exactly as Android's `agepony.json` does.

### Acceptance

As Android item 1, plus: PIN first and one tap in all three callers (file, text, migrate), and
from a share-extension hand-off.

## 2. YubiKey PIV over USB-C

**Source:** same email. Oct 1 decision Q3 (NFC only, USB-C on both platforms later).

- `PivCard` is a protocol and `BlockPivCard` wraps any transmit closure, so `PivSession` doesn't
  change. Add a USB-C transport next to `runPiv`'s CoreNFC one.
- Reuse PGPony iOS's USB-C smart-card transport (built for 8.1.0) instead of writing one. Carry
  its entitlements and Info.plist entries over exactly as PGPony has them.
- Prompt covers both: tap or plug in. Today the NFC sheet is the prompt, so the plug-in path needs
  its own in-app sheet, and the NFC session has to be cancelled when the USB key answers first.
- USB-C iPhones (15 and later) and USB-C iPads only. Lightning (YubiKey 5Ci) is out.
- FIDO over USB isn't possible here (no raw CTAP over USB on iOS), so this is PIV only regardless
  of what Android decides (Android Q4).
- Blocked on a working USB-C YubiKey, same as Android.

## 3. Picker rows show key material

`PLANNED_FEATURES.md` item 1 has the full write-up and acceptance. Line numbers have moved since
it was written:

| Surface | File | Row today |
| --- | --- | --- |
| Active identity | `Features/Settings/SettingsView.swift:179` | `Text(id.name)` |
| Encrypt to self | `Features/Files/EncryptFlow.swift:340` | `Text(identity.name)` |
| Signing key | `Features/Sign/SignFileView.swift:201` | `Text(id.name)` |
| Recipient picker, promote to signer | `RecipientPickerView.swift`, `SignersView.swift` | re-survey |

Android has the same gap (active-identity dropdown, encrypt-to-self rows). Same rule on both:
name, type in words, existing short public string.

## 5. iOS carryovers (to triage)

- **Evaluation requests:** Face ID only lock, CCTV vectors, the CryptoKit and Enclave ML-KEM
  spike, store wording and release tagging are planned in `AgePony_5.1.0_Evaluation_Requests.md`
  (items E1 to E9).

From the 5.0.1 plan and its phase notes:

- **Signer options:** iOS `StoredSigner` has no `options`, so transferred signers that carry
  allowed_signers options (namespaces=, valid-before=, ...) are skipped. Android imports the ones
  it can enforce. Adding `options` closes L-6 on the app side.
- **Small ssh-rsa keys in the transfer preview:** keys under 2048 bits drop out silently; Android
  lists them unticked with a warning.
- **C2SP CCTV testkit:** now E7 in `AgePony_5.1.0_Evaluation_Requests.md`.
- **Tor (Q9):** the tree still ships the HTTP-only proxy (`NetworkSettingsView.swift`). Record
  what the spike found, or schedule it.
- **CryptoKit on iOS 26 and Secure Enclave ML-KEM:** now E8 in
  `AgePony_5.1.0_Evaluation_Requests.md`.
- **Clipboard:** `PLANNED_FEATURES.md` item 3 regression test, if not done.
- **5.0.1 device checks that need two phones:** QR cross-scan (iPhone byte mode vs Android
  alphanumeric), hotspot transfer in both directions, copy/QR lag on a Secure Enclave key. Move
  any that weren't covered before release into the RC1 device pass.

## 6. Build and test

```
swift test
xcodebuild test -project AgePony.xcodeproj -scheme AgePony -destination 'platform=iOS Simulator,name=iPhone 17'
```

RC1 device pass: item 1 acceptance with an NFC YubiKey (default key, `Never` key, 4.x/5.0.1
identity upgraded in place, wrong PIN), all three decrypt callers plus a share hand-off; item 3
with two same-named identities. Version: `MARKETING_VERSION 5.1.0` on the app and the share
extension together.

## 7. Open questions

Shared with Android (answers go in both plans): Q1 USB-C timing, Q2 unknown-policy default, Q3
GET METADATA on import. iOS only:

- **Q5. Tor:** what came of the 5.0.1 spike, and does anything ship in 5.1.0?

## 8. Credit

User reports by email (Aug 1 and Oct 16 2026). No personal names in anything shipped or
committed.
