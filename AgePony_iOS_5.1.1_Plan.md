# AgePony iOS 5.1.1 plan (Rev 1)

A security release fixing the findings of the internal 5.1.0 review
(`AgePony_Security_Review_2026-10-28.md`, private until 5.1.1 ships). Finding IDs below are that
report's. Line numbers are at `3516d7d`.

This plan is synced to the public repo with the release. Keep reporter correspondence out of it.

## Status

| Item | Finding | RC | State |
| --- | --- | --- | --- |
| 1. Owner check before the first app password | H-1 | RC1 | Done |
| 2. ssh-ed25519 small-order keys | M-1, I-1, I-3 | RC1 | Done |
| 3. Shortcuts file name | M-5 | RC1 | Done |
| 4. Repo hygiene | L-15, L-16 | RC1 | Done |
| 5. Plaintext left in tmp | M-2, L-13 | RC2 | Done |
| 6. Dead Enclave key hides the YubiKey | M-4 | RC2 | Done |
| 7. Face ID only in-app prompts and enrolment changes | M-3, L-11 | RC2 | Done |
| 8. Decrypt screen Lows | L-1, L-2, L-3, L-14 | RC2 | Done |
| 9. Hardware loop and NFC retries | L-7, L-8 | RC2 | Done |
| Deferred to 5.2.0 | L-4, L-5, L-6, L-9, L-10, L-12 | | See "Not in 5.1.1" |

RC1 is the small, high-value set: three code changes with unit tests and one doc cleanup. RC2 is
the larger set that needs device checks. One RC at a time; RC2 starts after RC1 is built and tested.

## RC1

### 1. Owner check before the first app password (H-1)

**Now.** "Set a password or PIN" in Lock settings (`LockSettingsView.swift:282`) and the same offer
in the Face ID only dialog (`:129-132`) open the password sheet with no check. Once a password
exists, `requireOwner` (`:426-430`) and `OwnerCheck.confirm` (`PortabilityCommon.swift:69-72`) accept
it, so whoever holds the unlocked app can set one, switch to No lock with it, and export keys
through Paper backup or Send keys.

**Change.**
- Wrap both entry points: `requireOwner { showSetPassword = true }` and
  `requireOwner { biometricOnlyAfterPassword = true; showSetPassword = true }`. With no password
  set, `requireOwner` already falls through to Face ID or the device passcode.
- Defense in depth: `Vault.setAppPassword` (`Vault.swift:667-702`) takes an `LAContext` that was
  evaluated in the last few seconds when `!hasAppPassword`, and refuses without one, so a future
  caller can't skip the check.
- Audit every other `hasAppPassword` / `passwordIsOnlyUnlock` gate for the same pattern (setting
  duress, changing the password, turning in-app prompts off) and list the result in the RC1 notes.

**Tests.** A Vault test that `setAppPassword` without an evaluated context fails when no password
exists and succeeds when one does (changing it still goes through `requireOwner`).

**Device.** Default lock, no password: Set a password asks for Face ID first; cancel leaves nothing
set. Face ID only dialog: same. With a password: changing it asks for the current password as
before.

### 2. ssh-ed25519 small-order keys (M-1, I-1, I-3)

**Now.** `Ed25519Conversion.isValidPublicKey` has no subgroup check, so `EC FF..FF 7F` (y = p-1) and
32 zero bytes are accepted and convert to low-order Montgomery points. CryptoKit returns an all-zero
shared secret for them without throwing, and `SSHEd25519Stanza.swift` wrap (`:81-96`) and unwrap
(`:174-187`) don't check, so a file encrypted to such a key can be opened by anyone who has it.

**Change.**
- Wrap: after the key agreement, `guard !X25519Identity.isAllZero(shared) else { throw
  SSHEd25519Error.lowOrderPublicKey }` (new case, with a UserMessage line).
- Unwrap: return nil for an all-zero shared secret.
- `SSHEd25519Recipient.init`: one trial agreement with a random scalar; refuse an all-zero result,
  so the vault, GitHub fetch and paste paths never store such a key. Same for the identity side.
- I-1: the hybrid check in `HpkeMlkem768X25519.swift:117-118` uses the shared constant-time
  `isAllZero` instead of `contains(where:)`.
- I-3: fix the comment at `HpkeMlkem768X25519.swift:104-112`, and correct `AgePony_5.1.0_RC3_Spike.md:268`
  (CryptoKit's `Curve25519.KeyAgreement` returns zeros for a low-order point; it does not throw).
  Note the correction to the September L-14 premise in the review file.

**Tests.** In `HardeningTests` (or a new `SSHEd25519LowOrderTests`):
- `EC FF..FF 7F`, 32 zero bytes and one order-8 encoding are refused by `SSHEd25519Recipient.init`.
- Wrap refuses and unwrap returns nil when forced past init (test-only initializer if needed).
- One test that records what CryptoKit returns for the all-zero point, so a future CryptoKit change
  shows up.
- A normal ssh-ed25519 round trip and the age CLI interop test still pass.

**Android.** Not affected (`X25519Crypto.keyExchangeOrNull` refuses an all-zero result). Add the
same three keys to the Kotlin tests in the Android 5.1.0 RC2 so both cores pin the behavior.

### 3. Shortcuts file name (M-5)

**Device check first.** In Shortcuts: Get File (or Text, Make Text File) > Set Name to
`../x.txt` and to `a/b.txt` > Encrypt with passphrase (AgePony). Note whether the action receives
the name with the slash. This decides the rating (Medium if it arrives, Low if not), not whether
to fix it.

**Change (either way).**
- `AgePonyIntentSupport.swift:37-48`: `let name = URL(fileURLWithPath: file.filename).lastPathComponent`,
  falling back to "input" for an empty result, ".", ".." or anything with "/". Or reuse
  `SharedContainer.sanitizedFilename`.
- Staging returns its own folder, and cleanup (`:52-55`) removes that folder, never a path derived
  from the file name. Check the standardized path is still under the `AgePonyIntent-` folder
  before deleting.
- Write the input with `.completeFileProtection`; remove the output's folder after the intent reads
  the result.

**Tests.** Unit tests for the name sanitizer (`../../x`, `a/b`, `..`, empty, a normal name) and for
cleanup deleting only the staging folder.

### 4. Repo hygiene (L-15, L-16)

- `Tests/AgePonyCoreTests/SSHKeyTests.swift:114,116`: replace the key comment with a neutral one
  (for example `user@example`). Update any expected value that includes it.
- `AgePony_iOS_5.1.0_Plan.md:64-73`: cut the sentence that ties the reporter to a store review and
  the device-setup detail; say "a user report" as the other sections do.
- Both changes land in the private repo and go public with the 5.1.1 sync.
- History: both texts stay in public history at `v5.1.0`. Rewriting public history is not planned
  (Q3).

## RC2

### 5. Plaintext left in tmp (M-2, L-13)

**Change.**
- Launch (RootView `.task`) and `lockNow`: sweep `AgePonyShare-*`, `AgePonyBatch-*`,
  `AgePonyFlatten-*`, `AgePonyIntent-*` and `AgePonySigners-*`. Simplest is `TempFileCleanup.sweepAll()`
  at launch, plus the same sweep in `lockNow` for folders no screen holds open.
- `FileEncryptor.freshTempURL` / `protectFile` (`:594-616`): create the output file with protection
  before streaming (`FileManager.createFile(atPath:contents:attributes:)` with
  `.completeUnlessOpen`), then open the `OutputStream`. Q4: `.complete` instead.
- `PassphraseModeView`: add the `FlowLifetime` pattern from DecryptFlow, and delete the result in the
  callback if the view has gone.
- L-13: `HomeView` share hand-off, discard the claimed share in the presented view's `onDisappear`
  (the current `onDismiss` path is dead code).
- Done-screen wording stays ("deleted when you close this screen"); it's true once the sweep exists.

**Device.** Decrypt a file, force-quit with the result on screen, relaunch, then check the app's
tmp folder (Xcode > Devices > Download Container). Same in passphrase mode with Close during a
large decrypt.

### 6. Dead Enclave key hides the YubiKey (M-4)

**Change.** In `DecryptIdentities.prepare` / `YubiKeyDecrypt.need` (`:42-53`), only software
identities can make the YubiKey tap unnecessary: leave Secure Enclave identities out of `others`
when deciding `need`. If the Enclave key works, the decrypt never reaches the tap; if it fails,
the tap is offered. Also offer the tap after a decrypt that fails with a Secure Enclave or
LocalAuthentication error when the file is also addressed to a YubiKey.

**Device.** RC3 device test 5 with a YubiKey also in the file (needs a working YubiKey; if there is
still none, this ships on unit tests like 5.1.0 item 1).

### 7. Face ID only in-app prompts (M-3, L-11)

**Change.**
- On unlock in Face ID only mode (`Vault.loadBiometryOnlyKey`), keep the context's
  `evaluatedPolicyDomainState` (`domainState.biometry.stateHash` on iOS 18+) in memory.
- In `BiometricGate.biometricOnlyContext` (`:225-262`), compare after evaluation. On a mismatch,
  throw `.unavailable` so `OwnerCheck.authenticate` falls back to the app password, and show the
  same "Face ID changed" wording as the lock screen.
- L-11: `OwnerCheck.authenticate` (`PortabilityCommon.swift:43-50`) follows the same rule as
  `confirm`: when `vault.passwordIsOnlyUnlock`, use the app password sheet, not the device passcode.

**Device.** Face ID only, unlocked: add an alternate appearance, return within the grace period,
try reveal, decrypt, sign and Paper backup: each asks for the app password. Password-only vault:
reveal asks for the app password, not the passcode.

### 8. Decrypt screen Lows (L-1, L-2, L-3, L-14)

- L-1: TextDecryptView uses `Age.decryptAndRecoverSignature` and `FileVerifier.verify` like
  DecryptFlow, and shows the verified badge. If that's too big for 5.1.1, show "This text carries a
  signature that isn't checked here; decrypt it as a file to verify." when a signature stanza or
  bundle is present (Q5).
- L-2: before deriving, DecryptFlow, TextDecryptView and MigrateFlow refuse a work factor that
  `ScryptMemory.fits` rejects, with the passphrase-mode message. Or in `FileEncryptor.decrypt`, so
  every caller is covered.
- L-3: tint the summary text for `.invalid` in `VerifiedBadge.swift:130-141`, and make the headline
  "Decrypted, signature failed" when trust is `.invalid`.
- L-14: turn text selection off for decrypted text in TextDecryptView and PassphraseModeView; the
  Copy button (local-only, expiry) stays.

### 9. Hardware loop and NFC retries (L-7, L-8)

- L-7: in `Age.unwrapFileKey` (`:178-189`), after a hardware identity throws, skip it for the rest
  of the file, and cap tag-matching stanzas per identity at 4. Same cap in
  `YubiKeyIdentity.peerPoints`.
- L-8: `SecurityKeyTransport.transmitBlocking` never resends VERIFY or CTAP clientPIN; it asks the
  user to hold the key again instead. Other commands keep the retry.
- Tests: a crafted header with 100 matching tag stanzas makes at most 4 Enclave calls (mock
  identity); a transient error on VERIFY surfaces instead of resending.

## Not in 5.1.1 (5.2.0)

| Finding | Why it waits |
| --- | --- |
| L-4 picker short key | Needs a fingerprint format for hybrid keys, shared with Android |
| L-5 password-only onboarding window | Touches the C1 setup path that just shipped; wants its own tests |
| L-6 master-key replace double failure | Same area as L-5; do them together |
| L-9 RSA-OAEP constant time | No practical oracle; a careful rewrite with test vectors |
| L-10 PIV PIN to any NFC device | No full fix without SCP11b; the partial fix needs a YubiKey to test |
| L-12 allowed_signers import review | Needs a review screen; pair with the Android signers work |

The YubiKey device pass from 5.1.0 item 1 also stays open until there's a working key.

## Release

- `MARKETING_VERSION` 5.1.1 for the app and the share extension, build number up.
- What's New: plain list of fixes, no exploit detail. Draft:
  "Security fixes from an internal review of 5.1.0. Setting the first app password now asks for
  Face ID or your passcode. ssh-ed25519 keys that can't be used safely are refused. Decrypted copies
  are cleaned up even if the app is closed unexpectedly. A hardware key that stops working no
  longer hides a YubiKey the file is also encrypted to. In Face ID only mode, adding a face asks for
  the app password before keys can be used. Plus smaller fixes to signature display and NFC
  retries."
- Promotional text unchanged.
- At submission: sync AgePonyiOS, signed `v5.1.1` tag (as for 5.1.0).
- After 5.1.1 is live: publish a redacted `SECURITY_REVIEW_2026-10-28.md` in AgePonyiOS, like the
  September one (Q2).

## Android follow-ups (for the Android 5.1.0 RC2)

- H-1 pattern: check whether Android lets the first app password be set without an owner check,
  and whether its owner re-checks then trust it.
- M-2 pattern: check Android's decrypted temp files are swept at launch and lock.
- M-1: add the three small-order ssh-ed25519 keys to the Kotlin tests (Android already refuses them).
- M-4 pattern: check whether a dead Keystore key hides the YubiKey tap.

## Decisions and open questions

- **Q1. Scope split.** RC1 = items 1 to 4, RC2 = items 5 to 9, rest in 5.2.0 as above. Proposed.
- **Q2. Publishing the 5.1.0 review.** Proposed: keep it private until 5.1.1 is live, then publish a
  redacted copy in AgePonyiOS.
- **Q3. Public history.** Proposed: don't rewrite AgePonyiOS history for L-15/L-16; fix them going
  forward.
- **Q4. File protection for decrypted output.** `.completeUnlessOpen` (works if the screen locks
  mid-write) or `.complete` (stricter; a long decrypt fails if the phone locks). Proposed:
  `.completeUnlessOpen`.
- **Q5. Text decrypt signatures.** Full verification in 5.1.1, or the notice now and verification in
  5.2.0. Proposed: full verification, since the core already has the function.
