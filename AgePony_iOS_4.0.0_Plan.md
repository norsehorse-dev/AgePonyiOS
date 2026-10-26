# AgePony iOS 4.0.0 — parity plan

Working document for the 4.0.0 release: bringing iOS from 3.1.x up to feature
parity with Android 4.2.0. Companion to `PLANNED_FEATURES.md` (items referenced
below) and, on the Android side, `AgePony_4.0.0_Plan.md`, `AgePony_4.1.1_Release.md`,
and `RELEASE_NOTES_4.2.0.md` in the Android tree. Last updated: 2026-08-26.

The headline is not "port the Sign tab." iOS pioneered signing; Android caught up
to it in *its* 4.0.0. Since then Android has run ahead on the pieces iOS never
had: an app-owned unlock secret and the duress wipe that sits on it, a network
key fetch with a proxy, YubiKey recipients, and a run of vault and settings
polish. This release closes that run. Nothing here touches the age format or the
crypto core's guarantees; it is mostly SwiftUI and vault-model work against a core
that is already at parity or ahead.

One version note up front: Android is on `versionName 4.2.0` / `versionCode 15`.
iOS jumps 3.1.x → 4.0.0 rather than matching 4.2.0, because the iOS number tracks
its own cadence and 4.0.0 is the right signal for a major parity leap in one
release. The App Store `MARKETING_VERSION` becomes `4.0.0`; `CURRENT_PROJECT_VERSION`
bumps per the usual build-number rule.

---

## 1. Where the two apps actually stand

| | iOS | Android |
| --- | --- | --- |
| Version | 3.1.x (`MARKETING_VERSION` carries 3.1.1) | 4.2.0 (`versionCode 15`) |
| Shared baseline | age + SSHSIG signing + FIDO NFC + tar + **PQC + streaming** | same, through 3.1.0 |
| Gap | Android 3.2.0, 4.0.0, 4.0.1, 4.0.2, 4.1.0, 4.1.1, 4.2.0 | — |

The shared baseline is real and larger than the old parity doc implies. iOS is
**not** behind on crypto: post-quantum recipients, the migration flow, the file
inspector, payload/armor/tar streaming, the signed bundle, and the full Sign
surface all shipped in iOS 3.x. The gap is entirely app-layer and one core
recipient type.

---

## 2. What iOS already has — do not rebuild

Surveying the iOS tree first, as always, turned up more than the stale docs
suggest. These are done and at parity; touching them is a regression risk, not a
task.

| Capability | iOS home | Notes |
| --- | --- | --- |
| Full Sign surface | `Features/Sign/{SignFileView,VerifyFileView,SignersView,AddSignerView,VerifiedBadge}.swift` | iOS shipped this first; Android copied it. At parity. |
| RSA signing routed | `Services/FileSigner.swift` `case .sshRSA → SSHSigner.signRSA` | The Android 4.0.0 plan's claim that "iOS does not route RSA" is **stale**. iOS already signs RSA. |
| Trusted signers + `allowed_signers` | `Vault/StoredSigner.swift`, `Sources/AgePonyCore/Signing/AllowedSigners.swift` | Android ported these *from* iOS. At parity. |
| Post-quantum identities + badge | `Features/Onboarding/GenerateIdentityView.swift` (`.postQuantum`), `DesignSystem/PostQuantumBadge.swift`, `Stanzas/HybridStanza.swift` | Full ML-KEM-768 + X25519, UI and core. At parity. |
| Migration flow | `Features/Files/MigrateFlow.swift`, `Services/MigrateService.swift` | Batch re-encrypt to a PQ recipient. At parity. |
| File inspector | `Features/Files/InspectFlow.swift`, `Services/AgeFileInspector.swift` | Header-only probe. At parity. |
| Streaming (payload, armor, tar, SSHSIG hash, header probe) | `AgeArmorStream.swift`, `Archive/TarArchiveStream.swift`, `Signing/SSHSigHashStream.swift`, `Archive/SignedBundle.swift` | Bounded-memory everywhere. At parity or ahead. |
| QR **scanning** to import a recipient | `Services/QRScanner.swift`, `Features/Identities/AddRecipientView.swift` | Camera import works. See §3.4 — only QR *display* is missing. |
| Clipboard auto-clear (60s) | `DesignSystem/AgePonyKeyBlock.swift`, `Features/Text/{TextEncryptView,TextDecryptView}.swift` | Already uses expiring pasteboard items. Android added this in 4.1.0; iOS predates it. Needs a regression test, not a build — `PLANNED_FEATURES.md` item 3. |
| Adjustable scrypt work factor + OOM story | `Services/ScryptMemory.swift`, `Features/Settings/SettingsView.swift` | At parity. |

So the whole "Sign / RSA / PQC / streaming" column is closed already. What
remains is the vault-security and settings work Android did after iOS branched
off.

---

## 3. The gap, by Android release

Each item lists the Android source of truth, the iOS counterpart to create or
change, and what "done" means. Grouped by the Android release that introduced it.

### 3.1 — Android 3.2.0: encrypt-flow ergonomics

Android 3.2.0 reworked encrypting a run of files: recipients are chosen on the
encrypt screen itself, armor and passphrase-only are remembered between files and
launches, a passphrase is held until the vault locks, and "Encrypt more files"
keeps every setting. iOS's `EncryptFlow.swift` still opens a `.sheet`
`RecipientPickerView` (a second page) and holds `armor`/mode as plain `@State`
that resets each entry.

| Android | iOS change | Acceptance |
| --- | --- | --- |
| Inline recipient chips on the encrypt screen (`ui/files/EncryptFlow.kt`, `RecipientPicker.kt`) | Fold recipient selection onto the encrypt screen, or keep the sheet but pre-seed and persist the last selection. Decide in review — see open question 5. | Encrypting three files in a row does not reopen the recipient picker for each. |
| Remembered armor + passphrase-only | Back `armor` and passphrase-only mode with `@AppStorage`, not `@State`. | The armor toggle and mode survive relaunch. |
| Passphrase held until lock | Cache the entered passphrase in the vault object (memory only, dropped on lock), mirroring Android's "never written to disk, dropped whenever the vault locks." | A run of passphrase encrypts asks once; the next unlock asks again. |
| "Encrypt more files" | An affordance after a successful encrypt that returns to the picker with settings intact. | One tap re-enters the file picker with recipients and toggles preserved. |
| Add Recipient no longer pre-fills the name with the key | Audit `Features/Identities/AddRecipientView.swift`. | The name field starts empty, not seeded with the pasted key. |

This block is ergonomics, not security; it can ship late in the release or be
split out if 4.0.0 gets heavy. It is grouped here because it is the oldest unclosed
gap.

### 3.2 — Android 4.0.0: app-owned unlock secret + duress wipe

This is the structural heart of the release, and the reason it is a major bump.
`PLANNED_FEATURES.md` item 2 is the full spec; this section sequences it.

Today `Vault.unlock(prompt:)` (`Vault/Vault.swift:135`) goes straight to
`BiometricGate.authenticate`, which evaluates `.deviceOwnerAuthentication` — Face
ID / Touch ID with the device passcode as the OS fallback
(`Services/BiometricGate.swift:54`). AgePony itself never sees a password; the
Keychain ACL is the gate. There is nowhere to type a decoy because there is
nowhere to type a real one. So this ships in two parts.

**A. App-owned password/PIN unlock** (Android `security/PasswordVault.kt`,
`vault/LockMode.kt`, `ui/VaultGate.kt`)

- A password/PIN unlock offered *alongside* the biometric gate, not replacing it.
  Verifier stored as a slow hash — reuse the scrypt already in core rather than
  adding Argon2 — wrapping the same master key the Keychain path wraps.
- Enrollment lets the user choose password or PIN; store the choice as a cosmetic
  `unlockSecretKind` (keyboard type only), keeping one constant-time comparison
  path, exactly as Android settled it (Android open question 7).
- Storage: the iOS vault is Keychain-backed, so the verifier and wrapped key need
  a `StoredSecret` kind of their own rather than a prefs blob. Old vaults hydrate
  with no app secret set (biometric-only, unchanged).

**B. The wipe** (Android `vault/Vault.kt` wipe path)

- One "wipe everything" routine in `Vault.swift` that runs the existing
  `deleteIdentity` / `deleteRecipient` / `deleteNote` / `deleteSigner`
  (lines 177–267) for every entry and calls `KeychainStore.deleteMasterKey()`.
  Do not forget signers. Callable only from the duress branch for now.

**C. Duress behavior** (Android settled spec, `AgePony_4.0.0_Plan.md` §3, open
questions 4 and 6)

- Constant-time comparison against both the real and decoy verifiers, so latency
  does not leak which branch ran.
- No tell: post-wipe state must be indistinguishable from a wrong password.
- **Afterward state — match Android exactly.** Android ships: the wipe silently
  re-bootstraps an empty vault whose real password *is* the decoy just entered.
  The coercer sees a working, empty app that keeps unlocking with the decoy; any
  other secret fails normally. Retry-stable, no tell, and it can demonstrate
  compliance. iOS implements this same spec — a duress feature that differs per
  platform is a worse duress feature (Android open question 6 committed iOS to
  this).

**D. Lock-mode copy** — Android 4.0.0 renamed the biometric toggle so "off"
honestly reads as "no lock at all." iOS should carry the same honest copy in
`SettingsView`. Note iOS already gets device-passcode fallback free from
`.deviceOwnerAuthentication`, so the Android 4.1.0 "device with no fingerprint can
now unlock with the device credential" need does **not** exist on iOS — the OS
covers it. The app-owned secret on iOS exists *for the duress feature*, not to
support no-biometric devices. Keep that framing in the settings copy so it is not
sold as something it isn't.

**Tests** — the four acceptance criteria from `PLANNED_FEATURES.md` item 2
verbatim, including the statistical timing test (decoy vs. wrong password take
statistically the same time), run on a device, not just in the simulator where
timing proves nothing.

### 3.3 — Android 4.0.1 / 4.0.2: robustness to audit

These were Android bug-fix releases. Check whether the same classes of bug exist
on iOS rather than porting blind.

- **4.0.1 lock-screen crash after reinstall/restore** — Android's vault failed to
  open when Keystore material was gone but the encrypted blob remained. iOS analog:
  a restored Keychain reference with no recoverable key. Audit `KeychainStore` /
  `Vault.unlock` for a clean reset path instead of a hard failure. Acceptance: a
  restore-from-backup state resets the vault cleanly and onboards fresh.
- **4.0.2 FIDO enrollment CTAP error** — Android was rejecting newer YubiKey
  firmware during enrollment because it did not enroll the way `ssh-keygen` does.
  iOS shares the FIDO/CTAP2 stack (`Services/FIDO/`, `Sources/AgePonyCore/FIDO/`).
  Verify iOS enrolls sk-keys with the same single-touch flow and does not carry the
  same bug. Acceptance: a recent-firmware YubiKey enrolls over NFC with one touch,
  no CTAP error.

### 3.4 — Android 4.1.0: QR display, screenshot protection

- **QR display** (Android `ui/components/QrCode.kt`). iOS scans but cannot *show*
  a key as a QR to hand across. Add a `CIQRCodeGenerator`-backed view, reachable
  from `RecipientDetailView` / `IdentityDetailView` and the public-key block.
  Acceptance: any public key renders as a QR that AgePony's own scanner (and a
  plain camera app) reads back to the identical string.
- **Screenshot protection on the private-key screen** (Android blocks screenshots
  while a key is on screen). This is a **platform-limited** item: iOS cannot hard-
  block a screenshot the way Android's `FLAG_SECURE` does. The iOS-honest version
  is: blur/blank sensitive key material in the app switcher (`scenePhase`
  `.inactive`), and optionally observe `UIScreen.capturedDidChangeNotification`
  and `userDidTakeScreenshotNotification` to warn. Do not claim a block that iOS
  cannot deliver — see open question 4. Acceptance: private-key material is not
  present in the app-switcher snapshot.

Everything else in 4.1.0 is already true on iOS: clipboard auto-clear (§2, needs a
test only) and device-credential unlock (free from the OS, §3.2 D).

### 3.5 — Android 4.1.1: the vault-key lifecycle bug

Android 4.1.1 fixed a password/PIN vault that sealed its first save under a zeroed
key because `Vault.bootstrap` stored the caller's key array by reference and the
bootstrap paths wiped it for hygiene. This bug is only *reachable* once an app-owned
password path exists — which iOS is adding in §3.2. **Build the iOS password path
to keep its own copy of the vault key from day one**, and port the regression test
(create with password → add identity → lock → unlock → assert no decrypt failure)
so iOS never ships the bug Android had to hotfix. Acceptance: the ported lifecycle
test passes; a password vault reopens cleanly after a lock.

### 3.6 — Android 4.2.0: network fetch, YubiKey, vault polish

The current Android release. Six items.

| Android | iOS work | Acceptance |
| --- | --- | --- |
| **GitHub key fetch + proxy** (`network/HttpClientFactory.kt`, `vault/ProxyConfig.kt`, Settings › Network) | New: a recipient-import source that fetches a user's keys from GitHub, plus a Settings › Network section — Off / Orbot (127.0.0.1:9050) / Custom SOCKS5-HTTP with optional creds. On iOS, route through a `URLSession` with a `connectionProxyDictionary`; resolve the host at the proxy, fail loudly if the proxy is half-set or dead. **This is the one feature that adds network to a currently all-offline app — see open question 1 before starting.** | Fetching a GitHub user's key over a configured Tor proxy works; a blank/dead proxy reports failure rather than falling back to direct. |
| **YubiKey recipients** (`age1yubikey1…`, piv-p256) | New core stanza `Stanzas/PivP256Stanza.swift` (P-256 ECDH via CryptoKit, HKDF-SHA256, ChaCha20-Poly1305) + recipient parsing; encrypt-only, matching Android. This is the only *core* addition in the release. | An `age1yubikey1…` recipient parses and encrypts; the file opens with `age` + the YubiKey; AgePony does not attempt to decrypt it. Cross-impl fixture against Android and `age-plugin-yubikey`. |
| **Configurable auto-lock** (Settings › Auto-lock) | iOS has a fixed 30s `backgroundGrace` in `Features/Home/RootView.swift:37`. Replace with an `@AppStorage` delay: immediately / 15s / 30s (default) / 1m / 5m. | The chosen delay governs when a backgrounded app relocks. |
| **Recently deleted** (`ui/settings/RecentlyDeletedScreen.kt`) | New: soft-delete for identities and recipients into a recycle bin reachable from the Identities screen; restore or purge; 30-day auto-expiry. Matters most for identities, where delete otherwise destroys a private key. Extend `VaultModels` with a `deletedAt` tombstone. | A deleted identity is restorable within 30 days and gone after; the vault blob carries tombstones and old vaults hydrate empty. |
| **Key avatars** (`ui/components/KeyAvatar.kt`) | New: a small deterministic colored avatar derived from the key bytes, shown next to `age1…` entries. iOS has SF Symbols + the PQ badge but no derived avatar. Same derivation as Android so an identity looks identical on both platforms. | The same key draws the same avatar on iOS and Android; two same-named identities are visually distinct in lists *and* pickers (ties into `PLANNED_FEATURES.md` item 1). |
| **In-app Help / Security / Licenses** (`ui/settings/{HelpScreen,SecurityInfoScreen,LicensesScreen}.kt`) | Three new Settings pages: a plain-language FAQ, a "how AgePony protects your files and what it does not do" page, and the open-source notices. iOS currently only has external links. | Each page opens in-app; the Licenses page lists the actual dependencies (CryptoKit/Security are Apple, so this is short — note the difference from Android's Bouncy Castle notices). |
| **Passphrase fields hidden** (Decrypt / Text / Migrate) | Audit the iOS equivalents; mask any passphrase field that shows plaintext and set a password keyboard so autocorrect never sees it. | No passphrase field on Decrypt, Text-decrypt, or Migrate renders in the clear. |

### 3.7 — Carried-over deferral: diceware

The old parity plan deferred the diceware generator + EFF wordlist from iOS 3.1.0;
it still is not present (no `Wordlist.swift`). Android ships `vault/Wordlist.kt`.
Port the same wordlist so generated passphrases are cross-platform reproducible,
and add the EFF long-list attribution (CC BY 3.0 US) to `NOTICE`. Small; fold in
wherever convenient. Acceptance: iOS and Android generate an identical passphrase
from the same word indices.

---

## 4. Platform-specific honesty

Two Android features do not translate one-to-one, and the plan should not pretend
they do:

1. **Screenshot blocking** (§3.4). iOS has no `FLAG_SECURE`. Ship app-switcher
   redaction and optional screenshot *detection*, and word the setting for what
   iOS actually does.
2. **Device-credential unlock** (§3.2 D). iOS already gets passcode fallback from
   `.deviceOwnerAuthentication`, so the Android 4.1.0 no-fingerprint-device fix is
   a no-op here. The app-owned secret exists only to enable duress.

Everything else is a straight port or a genuinely new iOS surface.

---

## 5. Order of work

Core and vault-model first (testable with `swift test` and unit tests alone), then
security, then the settings surface, then ergonomics.

1. **YubiKey piv-p256 stanza** (§3.6) — the only core addition; lands with its own
   KAT and a cross-impl fixture. Independent, gets the crypto risk out early.
2. **App-owned password/PIN unlock** (§3.2 A) — built key-safe from day one per
   §3.5, with the lifecycle regression test.
3. **Wipe path + duress branch + timing/no-tell tests** (§3.2 B/C/D).
4. **Recently deleted** vault-model work (§3.6) — tombstones in `VaultModels`.
5. **Key avatars** (§3.6) — shared derivation, then wire into lists *and* pickers,
   closing `PLANNED_FEATURES.md` item 1's picker gap at the same time.
6. **QR display** (§3.4) and **passphrase-field masking** audit (§3.6).
7. **GitHub key fetch + proxy** (§3.6) — gated on open question 1.
8. **Configurable auto-lock** (§3.6) and **screenshot/app-switcher redaction**
   (§3.4).
9. **In-app Help / Security / Licenses** (§3.6).
10. **Encrypt-flow ergonomics** (§3.1) and **diceware** (§3.7) — the splittable
    tail.
11. **4.0.1/4.0.2 robustness audits** (§3.3) — run alongside, land fixes if the
    bugs reproduce.
12. Clipboard-auto-clear regression test (§2), version bump to 4.0.0, README truth
    pass, `PLANNED_FEATURES.md` updates (close items 1 and 2), release notes.

Steps 1–3 are the load-bearing ones; 4–9 are independent and parallelizable; 10–11
can slip to a point release without holding 4.0.0 if scope runs long — decide at
the §6 open-question 2 checkpoint.

---

## 6. Open questions / decisions

1. **Network at all?** The GitHub key fetch + proxy (§3.6) is the only feature that
   adds a network call to an app that is currently 100% offline, and the README
   sells "no accounts, no servers." Android decided the fetch was worth it and
   scoped a proxy around it. iOS has to make the same call deliberately: ship the
   fetch (with the proxy, so the offline default is preserved and Tor is one tap),
   or hold it and reach 4.0.0 parity on everything else. This is the one decision
   that changes the release's identity. **Needs deciding before step 7.**
2. **One 4.0.0, or 4.0.0 + a fast-follow?** The full list is large. A defensible
   cut: 4.0.0 = duress + YubiKey + recently-deleted + avatars + QR display +
   help/security/licenses (the security and parity-critical set), and a 4.0.x
   fast-follow for the encrypt-flow ergonomics and diceware. Decide before step 10.
3. **Verify namespace.** Android open question 2 was left open on both platforms:
   should the Verify screen also accept the `ssh-keygen -Y` default `file`
   namespace, so signatures from plain OpenSSH users verify in-app? Cheap, and
   worth matching on both at once. iOS currently accepts only `agepony`.
4. **Screenshot feature scope** (§3.4/§4). App-switcher redaction only, or also
   screenshot-taken detection + warning? Pick one and word the settings copy to
   match what iOS actually enforces.
5. **Encrypt-recipient surface** (§3.1). Fully inline the recipient picker onto the
   encrypt screen (closest to Android), or keep the sheet but make it sticky
   (pre-seeded, persisted)? The sticky-sheet path is far less UI churn for the same
   ergonomic win.
6. **Licenses page contents** (§3.6). iOS core is CryptoKit + Security + CommonCrypto
   (Apple frameworks, no third-party crypto lib), so the notices are much shorter
   than Android's Bouncy Castle set. Confirm there is anything to list beyond the
   age/SSHSIG format attributions and the EFF wordlist.

---

## 7. Release mechanics

- `MARKETING_VERSION` → `4.0.0`; bump `CURRENT_PROJECT_VERSION` per the build-number
  rule. Tag `v4.0.0` with the `v`, matching the Android convention.
- Distribution is App Store / TestFlight, not F-Droid, so the reproducible-build
  and flavor machinery from the Android release docs does not apply. The relevant
  gate is a clean `xcodebuild archive` from a clean checkout plus `swift test`
  green.
- Set your own `DEVELOPMENT_TEAM` reminder still holds for contributors; the
  committed team is NorseHorse's.
- NFC (security-key) and the new YubiKey-recipient interop both need a real device;
  neither works in the simulator.
- README truth pass: the iOS README's feature list gains YubiKey recipients, QR
  display, the app-owned lock + duress, recently-deleted, and the network fetch
  *iff* open question 1 lands it. Do not advertise ahead of what ships (the Android
  4.0.0 plan's "README truth pass" lesson).

---

## 8. Verification strategy

`swift test` (AgePonyCore) and `xcodebuild` only run on the Mac; the core is
CryptoKit/Security-bound and does not build in the cloud sandbox, so the crypto is
again the slowest feedback loop. Only §5 step 1 (YubiKey piv-p256) is new crypto;
de-risk it the same way the ML-KEM work was — a structural reference plus golden
vectors — before writing Swift.

Per-phase gate, on the Mac:

    cd ~/Apps/AgePony && swift test
    xcodebuild -project AgePony.xcodeproj -scheme AgePony -destination 'generic/platform=iOS' build

Cross-implementation checks that must pass before 4.0.0 ships:

- **YubiKey piv-p256**: an `age1yubikey1…` file encrypted by iOS opens with `age`
  + `age-plugin-yubikey`, and one produced by Android opens the same; a shared
  fixture pins both directions.
- **Duress**: the four `PLANNED_FEATURES.md` item-2 criteria, including the on-device
  statistical timing test, and byte-verification that the wipe leaves zero
  identities/recipients/notes/signers and no master key in the Keychain.
- **Vault-key lifecycle** (§3.5): the ported create→add→lock→unlock regression
  passes on the password/PIN path.
- **Key avatars**: same key → same avatar bytes on iOS and Android (unit test
  against Android's fixture).
- **Diceware**: same indices → same passphrase on both platforms.
- **No regressions**: files from iOS 3.1.x, from Android, and from the `age` CLI
  (including PQ recipients) all still decrypt; the golden tar-parity checksum is
  unchanged.
- **Clipboard**: a test proves every pasteboard write uses the expiring form and
  fails if a plain `UIPasteboard.general.string =` assignment appears.

Device checklist: a new `AgePony_4.0.0_DeviceTests.md` in the shape of the Android
`AgePony_4.0.0_DeviceTests.md`, covering duress (timing + no-tell), YubiKey encrypt
+ desktop decrypt, QR display round-trip, recently-deleted restore/expire, the
FIDO-enrollment audit against recent firmware, and the app-switcher redaction check.
