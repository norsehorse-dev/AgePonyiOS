# AgePony 5.1.0: requests from a professional evaluation (Rev 1)

In October 2026 a user evaluating AgePony iOS for professional use with post-quantum keys asked
about source availability, build verification, the September review, the Secure Enclave keys and
the crypto core. This file collects every request, what has already been answered or done, and
the work that goes into 5.1.0.

It sits next to `AgePony_iOS_5.1.0_Plan.md` (this repo) and `AgePony_5.1.0_Plan.md` (Android
repo). Items here are numbered E1 to E9 so they don't collide with the shared item numbers 1 to 5
in those plans.

Last updated: 2026-10-26 (Rev 1). Items marked "Decided" were told to the user by email; the rest
is proposed.

---

## What the user was told

By email on Oct 25 and Oct 26 2026:

- The 5.0.1 source is public with a signed tag (done Oct 25).
- The review report is published in both repos (done Oct 25).
- The "security audit" wording in the store notes changes in the next update.
- A Face ID only lock comes in 5.1.0, with a way to recover when Face ID is re-enrolled.
- The C2SP CCTV age vectors go into 5.1.0 on iOS and Android.
- CryptoKit on iOS 26: a spike in 5.1.0 first, nothing in a release until it checks out.
- An independent third-party review once there's funding for it.

## Status

| ID | Request | State |
| --- | --- | --- |
| E1 | Publish the 4.x and 5.x source | Done Oct 25: `v5.0.1` signed tag on AgePonyiOS, README brought up to 5.0.1. |
| E2 | A way to check the App Store build matches the source | Answered (not possible on iOS). Release process item below. |
| E3 | Who did the review, when, and is the report public | Done Oct 25: `SECURITY_REVIEW_2026-09-23.md` in both repos. Store wording still to fix. |
| E4 | Is the PQ hardware key a standard `age1tagpq1` recipient | Answered: yes, `mlkem768p256tag`, tested against age-plugin-tagtest vectors. No work. |
| E5 | Are Secure Enclave decryption keys non-exportable | Answered: the P-256 half is; the ML-KEM half is a vault seed. Moving it into the Enclave is E8. |
| E6 | Disable the passcode fallback for the vault | Decided for 5.1.0 (iOS). |
| E7 | Add the CCTV test vectors | Decided for 5.1.0 (iOS and Android). |
| E8 | Use CryptoKit where iOS 26 offers it, incl. Secure Enclave ML-KEM | Decided Oct 26: spike, then implement both parts in 5.1.0 if it passes. |
| E9 | Independent third-party review | Not a 5.1.0 item. Depends on funding. |

## RC placement (proposed)

- RC1: E7 on both platforms and E6 on iOS, next to shared items 1 and 3. E7 is test-only.
- The E8 spike runs once E7 is in (it needs the vectors). The E8 implementation gets its own RC
  after RC1 is built and tested: RC2 if item 2's USB-C hardware is still blocked, otherwise RC3.
- At release: E3 wording and the E2 tagging step.

One RC at a time, as in the main plans.

---

## E2. Release provenance

**Request:** a way to verify that the App Store build matches the published source.

**Answer given:** App Store binaries are encrypted and re-signed by Apple, so a hash of a local
build can't be compared with what the store installs. Building from the tagged source is the way
to know exactly what you run.

**What 5.1.0 can still do:**

- The 3.1.0 to 5.0.1 gap happened because AgePonyiOS is a copy synced by hand from this working
  tree. Make the sync and a signed `vX.Y.Z` tag on AgePonyiOS part of App Store submission, not
  something done afterwards. Add it to the release steps of `AgePony_iOS_5.1.0_Plan.md`.
- Optional (Q1): show a source identifier in Settings > About. A build phase writes the git tree
  hash of the source (`git rev-parse HEAD^{tree}`) into Info.plist. A tree hash depends only on
  the files, so it matches the public tag even though the two repos have different histories, as
  long as the synced file set is identical. Today it isn't: AgePonyiOS has `LICENSE` and
  `NOTICE`, and this tree has `fastlane/_superseded/`. This shows which source a build claims to
  come from. It doesn't prove the binary, and the About text must not say it does.

## E3. Store and release-note wording

The September review was an internal review done with Claude, not a professional audit. Places
that call it an audit:

- iOS `fastlane/metadata/en-US/release_notes.txt` (the 5.0.1 What's New) and
  `AgePony_iOS_5.0.1_ReleaseNotes.md`. App Store What's New is fixed per version, so the fix is
  the 5.1.0 notes.
- Android `AgePony_5.0.1_ReleaseNotes.md` ("I ran a full security audit"), which is also the
  GitHub release text for `v5.0.1`. The GitHub release can be edited now.
- The Android F-Droid changelog for versionCode 17 doesn't use the word. Nothing to change there.

5.1.0 notes on both stores: say "internal security review" and point to
`SECURITY_REVIEW_2026-09-23.md`. Code comments that cite finding IDs ("audit M-7") can stay; they
refer to the report's IDs.

## E6. Face ID only lock (iOS)

**Request:** a vault lock where only biometrics opens the vault, with no device-passcode
fallback.

**Today:** `.biometric` stores the master key behind `[.biometryCurrentSet, .or, .devicePasscode]`
(`Vault/KeychainStore.swift`), so the phone passcode alone opens the vault. The only way to take
the passcode out of the picture now is No lock plus an AgePony password, or setting a duress
password (H-1 makes the vault password-only).

**Change:**

- New `LockMode` case, shown as "Face ID only" or "Touch ID only" depending on the device.
  Keychain ACL `[.biometryCurrentSet]` with no `.devicePasscode`. The lock-screen prompt uses
  `.deviceOwnerAuthenticationWithBiometrics` (already in `BiometricGate`).
- Recovery: a `.biometryCurrentSet` item is invalidated whenever Face ID or Touch ID is reset or a
  face or finger is added. Proposed (Q2): the mode requires an AgePony password, kept as a
  PasswordKeyBlob v2 wrap (device-bound). The lock screen offers Face ID first and "Use password"
  second. When the biometric item is gone, the password opens the vault and the app writes a fresh
  biometric item.
- Removing the device passcode makes biometric Keychain items unusable; the password covers that
  too.
- Duress: a duress password already makes the vault password-only (H-1), so Face ID only is
  unavailable while duress is set.
- Switching away from Face ID only is a weakening, so it asks for re-auth (L-15). Switching to it
  doesn't.
- Hardware keys: Secure Enclave decryption keys made with per-use confirmation use
  `.userPresence`, which accepts the passcode. An Enclave key's access control is fixed when the
  key is made, so existing keys can't change. A new key made with `.biometryCurrentSet` would be
  destroyed for good by a Face ID re-enrolment, with no recovery possible. Proposed (Q3): leave
  hardware keys on `.userPresence` and say so in Lock settings help.

**Acceptance:**

1. With Face ID only set, a failed Face ID offers no passcode entry, and the device passcode can't
   open the vault by any path.
2. The AgePony password opens the vault.
3. After adding an alternate appearance in Settings > Face ID, Face ID no longer opens the vault,
   the password does, and Face ID works again afterwards.
4. Setting a duress password turns Face ID only off, as it does for `.biometric` today.
5. Upgrading from 5.0.1 in each existing lock mode leaves the vault opening as before.

**Android (Q4):** Android's BIOMETRIC mode allows the device credential on API 30+
(`BiometricGate.kt`). A strong-biometric-only mode is possible with `AUTH_BIOMETRIC_STRONG` alone
on the Keystore key, and the same recovery problem applies since the key is
`invalidatedByBiometricEnrollment`. Not promised to the user. Decide whether it ships in 5.1.0.

## E7. C2SP CCTV age test vectors (iOS and Android)

**Request:** add the CCTV vectors, especially for the hand-written primitives.

**The testkit:** `age/testdata` in github.com/C2SP/CCTV. At commit `50a8ecf` (2026-09-25) it has
147 vectors: 37 armor, 28 stream, 25 scrypt, 18 hybrid (`mlkem768x25519`), 14 x25519, 14 stanza,
8 hmac and a few header and version cases. Expected results: 26 success, 13 no match, 1 HMAC
failure, 62 header failure, 19 payload failure, 26 armor failure. 22 files are zlib-compressed and
19 use `AGE-SECRET-KEY-PQ-1` identities. Licensed 0BSD, CC0 or Unlicense, no attribution needed.
The tag recipients (`p256tag`, `mlkem768p256tag`) aren't in it; the age-plugin-tagtest vectors
keep covering those.

**File format:** a text header of `key: value` lines, a blank line, then the age file. Keys:
`expect`, `payload` (SHA-256 of all plaintext released, even when decryption then fails),
`identity` and `passphrase` (both can repeat), `armored: yes`, `compressed: zlib`, `file key` and
`comment` (both ignorable). Files with unknown keys are to be ignored.

**Vendoring:** copy `age/testdata` with the CCTV commit recorded in a short README next to it.
The testkit README suggests `git subtree`; a pinned copy is simpler and does the same job.

- iOS: `Tests/AgePonyCoreTests/Testkit/`, added to the test target as
  `resources: [.copy("Testkit")]` in `Package.swift` and read through `Bundle.module`.
- Android: `agepony-core/src/test/resources/testkit/`.

**Runner (one per platform):**

- Parse the header, inflate when `compressed: zlib`. Android: `java.util.zip.Inflater`. iOS: the
  Compression framework's `COMPRESSION_ZLIB` is raw DEFLATE, so skip the 2-byte zlib header.
- Decrypt through the streaming API, so the plaintext released before a failure can be hashed and
  compared with `payload`. The whole-buffer API returns nothing on failure.
- Map AgePony's errors onto the six `expect` values. Where AgePony can't tell two apart, alias
  them in the runner and write down which.
- Every vector passes or sits on a short exception list in the runner, each with a reason. No
  silent skips.

**Known cases to look at:**

- `scrypt_work_factor_23` expects `header failure`. AgePony refuses work factors above 20 before
  any KDF work, so that refusal maps to header failure.
- Armor: 5.0.1 made armor parsing strict. Some armor vectors allow CRLF and surrounding
  whitespace. Any armor vector AgePony fails is either a bug or a deliberate divergence and gets
  written up either way.
- `*_grease` vectors: unknown stanzas must be ignored. Worth checking next to the
  `agepony.com/sig` stanza handling.

**Optional:** the round trips the testkit README suggests (header re-encode for anything that
isn't a header failure, armor re-encode, STREAM re-encrypt with the `file key`).

**Acceptance:** `swift test` and `./gradlew :agepony-core:test` run all 147 vectors, and the
exception lists are the same on both platforms or the difference is explained.

## E8. CryptoKit on iOS 26 (spike)

**Request:** use CryptoKit where iOS 26 offers it, including the Secure Enclave ML-KEM, to cut
the amount of custom crypto that has to be trusted.

**What iOS 26 CryptoKit has:** `MLKEM768` (with `init(seedRepresentation:publicKey:)`),
`XWingMLKEM768X25519` (same initializer), `HPKE.KEM.XWingMLKEM768X25519`,
`HPKE.Ciphersuite(kem:kdf:aead:)` for custom suites, and `SecureEnclave.MLKEM768`. Not found:
SHA-3, scrypt, or an MLKEM768-P256 hybrid KEM. AgePony supports iOS 17, so the custom code stays
for 17 to 25 whatever happens.

**What age needs:** `mlkem768x25519` is HPKE SealBase with KEM MLKEM768-X25519
(draft-ietf-hpke-pq-03), KDF HKDF-SHA256, AEAD ChaCha20Poly1305, info
`age-encryption.org/mlkem768x25519`, empty AAD. CryptoKit's built-in post-quantum suite is
AES-GCM, so it can't be used as is. A custom
`HPKE.Ciphersuite(kem: .XWingMLKEM768X25519, kdf: .HKDF_SHA256, aead: .chaChaPoly)` looks
possible. `mlkem768p256tag` uses MLKEM768-P256, which CryptoKit doesn't offer, so AgePony keeps its
own combiner and would only hand the ML-KEM half to CryptoKit or the Enclave.

**Spike questions:**

- S1. Does the custom X-Wing suite open the 18 CCTV hybrid vectors, and does AgePony's own code
  open what CryptoKit seals? Needs E7 first.
- S2. Does `XWingMLKEM768X25519.PrivateKey(seedRepresentation:)` accept the 32-byte seed inside an
  `AGE-SECRET-KEY-PQ-1` identity and give the same `age1pq1` public key? If yes, existing
  post-quantum identities can use CryptoKit on iOS 26.
- S3. Does `MLKEM768.PrivateKey(seedRepresentation:)` take the 64-byte seed the current
  `age1tagpq1` keys keep in the vault, with the same public key?
- S4. `SecureEnclave.MLKEM768`: generate, decapsulate with an `LAContext`, check its access
  control options match the P-256 Enclave key, and plug it into the tag combiner. This is for new
  `age1tagpq1` keys only. Existing keys can't be converted, because an Enclave key can't be built
  from a seed. The vault would hold two Enclave handles and no ML-KEM seed. Transfer and paper
  backup exclusions don't change.
- S5. Both paths (CryptoKit on 26, own code on 17 to 25) run the same vectors. `swift test` on
  macOS 26 covers the CryptoKit side; the device pass covers both.

**Scope (decided Oct 26 2026):** spike, then implement both parts in 5.1.0.

- If S1 to S3 pass: the CryptoKit path for `mlkem768x25519` (and the ML-KEM half of
  `mlkem768p256tag`) ships in 5.1.0 on iOS 26, with the own code kept for iOS 17 to 25.
- If S4 passes: new `age1tagpq1` hardware keys with the ML-KEM half in the Enclave ship in 5.1.0
  as well.
- If either fails, that part moves to 5.2.0 and the reason is written down here. Nothing ships
  with a vector that differs.

**Implementation, if the spike passes:**

- CryptoKit path: one `#available(iOS 26, *)` branch per primitive in the core, behind the same
  types the app already uses, so the app code doesn't change. Both branches run the full vector
  set; `swift test` on macOS 26 covers the CryptoKit side.
- Enclave ML-KEM keys: a new stored identity kind next to `secureEnclaveTagPQ` holding two
  Enclave handles and no seed. It gets the same recipient string, transfer and paper backup
  exclusions, Help and Security text, and Identities badge as the existing hardware key. The
  generate option shows only on iOS 26 and later. Existing `age1tagpq1` keys stay as they are and
  keep working.
- Access control: the same flags as the P-256 Enclave key, so per-use confirmation behaves the
  same, and E6's Q3 answer covers both halves.
- Device pass: an iPhone on iOS 26 or later for the CryptoKit path and Enclave keys, and the iOS
  17 simulator for the fallback path. A file the age CLI 1.3 encrypts to the new recipient opens
  on the phone, and so does one AgePony encrypted to it before an app restart.
- Android: no change in 5.1.0. Android's hardware keys keep the ML-KEM half in the vault, so the
  platforms differ here and the Help text says so. Whether Android Keystore can hold ML-KEM is a
  separate check for a later release.

## E9. Independent third-party review

Not a 5.1.0 item. The apps are free and bring in no money, so a review needs outside funding.
OTF's Security Lab declined a PGPony application: its focus is internet-freedom projects for
people under repressive censorship and surveillance, with a substantial user base and community
buy-in, and the application didn't make that case strongly enough. OTF pointed to its Alternative
Sources of Funding page. E7 and E8 both shrink and test the custom crypto, which is where an
outside reviewer would spend the most time.

---

## Open questions

- **Q1.** Source tree hash in Settings > About (E2): yes, or just the tagging step?
- **Q2 (decided Oct 26).** Face ID only recovery (E6): require an AgePony password. The vault key
  sits behind `[.biometryCurrentSet]` only, and the password wrap is the way back in after a
  Face ID reset. `.biometryAny` was rejected: anyone with the passcode can add a face in Settings
  and then open a `.biometryAny` item, which is exactly what the mode exists to stop.
- **Q3 (decided Oct 26).** Hardware keys under Face ID only (E6): existing keys stay as they are
  (an Enclave key's access control is fixed at creation). When the vault is in Face ID only
  mode, generating a new hardware key offers "Require Face ID (no passcode)", which creates it
  with `.biometryCurrentSet`, with a plain warning that resetting Face ID destroys the key and a
  pointer to "Also encrypt to" as the backup. Same reasoning as Q2: `.biometryAny` would let a
  passcode holder in.
- **Q4.** Android biometric-only lock: 5.1.0 or later?
- **Q5.** Raise the iOS minimum to 26 at some point so the custom ML-KEM and X-Wing can be
  retired? Not for 5.1.0.

## Credit

A user evaluating AgePony for professional use (email, Oct 25 and 26 2026). No personal names in
anything shipped or committed.
