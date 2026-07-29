# AgePony iOS parity plan — 2.0 → 3.1.0

Working document for bringing the iOS app to parity with Android 3.1.0.
Companion to `AgePony_3.1.0_Plan.md` and `PQC_Phase_Notes.md` in `~/Apps/AgePonyAndroid`.
Last updated: 2026-07-29.

## 1. Where the two apps actually stand

| | iOS | Android |
| --- | --- | --- |
| Version | 2.0 (`MARKETING_VERSION`) | 3.1.0 (`versionCode = 8`) |
| Parity baseline | Android 2.0.0 / versionCode 4 — the P1–P8 signing track | same |
| Gap | one PQC release (3.0.x) and one streaming release (3.1.0) | — |

The 2.0 baseline is genuinely shared: age encryption, SSHSIG signing with software,
Secure Enclave / Keystore, and FIDO security keys over NFC, plus multi-file tar. The
gap is everything after that.

Note that the Android 3.1.0 plan deferred "iOS post-quantum parity" to 3.2.0. This
document supersedes that: iOS picks up both releases at once and lands on 3.1.0.

## 2. What iOS already has (do not rebuild)

Surveying the iOS tree first turned up more than expected. **The payload streaming
work is already done on iOS** — it predates the Android 3.1.0 effort:

- `Age.encryptStream(plaintext:to:into:)` / `Age.decryptStream(ciphertext:identities:into:)`
- `AgePayload.encryptStream` / `decryptStream`, chunked, with `sealChunk` / `openChunk`
- `AgePayload.readHeader(from:)` — reads the header off an `InputStream`
- `AgeStreamingTests.swift` already pins this

Also already present and needing no port: `AgeFileInspector.swift` (a partial header
inspector), `ReviewPrompter.swift` and `WalkthroughView.swift` (the Android 2e/2f
work), and `TarArchive.swift` in its buffered form.

So the iOS streaming task is **not** "add streaming" — it is the four pieces the
payload work did not cover. That is a materially smaller job than the Android
changelog implies.

## 3. The actual gap

### 3a. Post-quantum (Android 3.0.x) — all missing

| Android file | iOS counterpart | Notes |
| --- | --- | --- |
| `crypto/Sha3.kt` | `Crypto/SHA3.swift` **(new)** | Android wraps Bouncy Castle. **CryptoKit has no SHA-3 or SHAKE**, so iOS hand-rolls Keccak-f[1600] with incremental squeezing. |
| `crypto/MLKEM768.kt` | `Crypto/MLKEM768.swift` **(new)** | Android is a 96-line Bouncy Castle wrapper. **iOS has no equivalent on iOS 18**, so this is a full FIPS 203 implementation: NTT, poly arithmetic, compression, byte encoding, K-PKE, and the KEM wrapper. The single largest item in this port. |
| `crypto/HpkeMlkem768X25519.kt` | `Crypto/HpkeMlkem768X25519.swift` **(new)** | X-Wing hybrid KEM + RFC 9180 single-shot HPKE base mode. X25519 comes from CryptoKit; HKDF-SHA256 is hand-split into extract/expand as HPKE requires. |
| `recipients/Hybrid.kt` | `Stanzas/HybridStanza.swift` **(new)** | `age1pq` / `AGE-SECRET-KEY-PQ-`, the `mlkem768x25519` stanza. |
| `recipients/AgeRecipient.kt` (labels) | `Age.swift` | Add `LabeledAgeRecipient` and enforce the label rule in `Age.encrypt`. |
| `bech32/Bech32.kt` (length cap) | `Bech32.swift` | **iOS still enforces the BIP-0173 90-character cap.** An `age1pq1…` recipient is ~1960 characters, so it cannot even be decoded today. Raise to a generous sanity cap. |

App-side PQC surface, also all missing: post-quantum identity generation, the
quantum-safe badge (`PostQuantumBadge.kt`), and `MigrateFlow.kt` (re-encrypt to a
PQ recipient).

### 3b. Streaming and UX (Android 3.1.0)

| Item | iOS status |
| --- | --- |
| Payload streaming | **already present** |
| Armor `EncodingSink` / `DecodingSource` | missing — `AgeArmor.swift` is buffered only |
| Tar streaming (`source`, `forEachEntry`, `writeEntry`) | missing — `TarArchive.swift` is buffered only |
| `SignedBundle` | **absent from the iOS core entirely** |
| `SSHSig.hashStream` | missing |
| Header-only probe (`parseHeaderStream`, `canDecryptStream`) | partly there via `readHeader`; needs the public probe API |
| Diceware generator + wordlist | missing |
| One-archive-or-one-file-each chooser | missing |
| Adjustable scrypt work factor (2^16–2^20) | missing |
| Honest OOM diagnosis + scrypt precheck | missing |
| Byte progress | missing |
| Rename recipient / save pasted key with a name | missing |
| Header inspector UI | partial — `AgeFileInspector.swift` exists, needs the 3.1.0 surface |
| Vault returns to its tab on re-lock (3.0.3) | missing |

## 4. Verification strategy

`swift test` and `xcodebuild` only run on the Mac; AgePonyCore is CryptoKit- and
Security-bound so it does not compile in the cloud sandbox, and no Swift toolchain
is reachable from there either. That makes the crypto the risky part: it is the one
place where "looks right" is not good enough and the feedback loop is slowest.

So the ML-KEM work was de-risked before any Swift was written:

1. A Python reference was written as a **literal structural mirror** of the intended
   Swift — same function names, same shapes — so transliteration is mechanical
   rather than interpretive.
2. The golden vectors were lifted from `HybridRecipientTests.kt` and checksum-verified
   against the Android tree (`sha256` matched on both sides) to rule out transcription
   error.
3. The reference was run against them. **All pass**, byte-for-byte:
   - `publicKeyDerivedFromSeedMatchesReference` (1216 bytes)
   - `deterministicWrap: enc` (1120 bytes) and `body` (32 bytes)
   - `identityUnwrapsReferenceStanza`, round-trip, and implicit-rejection on a
     corrupted ciphertext
4. Keccak was then validated separately against `hashlib` — SHA3-256, SHA3-512,
   SHAKE128, SHAKE256, across block-boundary lengths, plus incremental squeezing
   matching one-shot output.
5. The whole stack was re-run using the hand-rolled Keccak instead of `hashlib`, and
   still matches the reference vectors.

The construction is therefore pinned end to end before a line of Swift exists. What
remains for the Mac to catch is transliteration slips and Swift type errors, not
design error.

Per-phase gate, run on the Mac:

    cd ~/Apps/AgePony && swift test          # AgePonyCore
    xcodebuild -project AgePony.xcodeproj -scheme AgePony -destination 'generic/platform=iOS' build

Cross-implementation checks that must pass before 3.1.0 ships:

- The `HybridRecipientTests` vectors, ported to `Tests/AgePonyCoreTests/HybridTests.swift`.
- Round-trip against the `age` CLI v1.3.0+ in both directions, including a PQ recipient.
- The golden archive checksum that Android 3.1.0 used to guarantee tar parity with iOS —
  iOS must still produce that exact checksum after the tar streaming work.
- Decrypt of files produced by iOS 2.0 must still work.

## 5. Order of work

Core first, because it is testable with `swift test` alone and everything else sits
on it.

1. **SHA3 + ML-KEM-768** — the long pole. Lands with its own KATs.
2. **Hybrid KEM + HPKE + `age1pq` recipient + Bech32 cap + labels.** After this,
   `swift test` proves iOS interoperates with age v1.3.0+ post-quantum files.
3. **Streaming armor, tar, signed bundle, SSHSIG hash, header probe.**
4. **App: bounded-memory flows with byte progress** (thin, since the payload
   streaming already exists).
5. **App: multi-file chooser.**
6. **App: passphrase memory story** — honest errors, scrypt precheck, work factor, diceware.
7. **App: header inspector.**
8. **App: rename recipients, save a pasted key with a name.**
9. **App: PQ identity generation, badge, migration flow.**
10. **Vault tab restore.**
11. **Version bump to 3.1.0, README, release notes.**

## 6. Open questions

1. **Mirror rule.** Android's source of truth is `~/Apps/AgePonyAndroid`, mirrored to
   `~/Documents/GitHub/AgePonyAndroid`. Does iOS have the same arrangement? Only
   `~/Apps/AgePony` is connected to this session, and `~/Documents/GitHub` is not
   reachable — connect it if the mirror should be kept in step automatically.
2. **iOS deployment target.** `Package.swift` says iOS 18 / macOS 14, but the README
   says iOS 16+. Worth settling, since it decides whether any CryptoKit PQC path is
   even a future option.
3. **Diceware wordlist.** Same question the Android plan raised: EFF long list
   (7776 words, CC BY 3.0 US) needs a line in `NOTICE`. iOS should ship whatever
   Android shipped — check `Wordlist.kt` and match it exactly so generated
   passphrases are cross-platform reproducible.
4. **Armor default for large files.** Android left this open too.
5. **PQ identity storage.** The iOS vault is Keychain-backed rather than a prefs
   blob; the 32-byte PQ seed needs a `StoredIdentity` kind of its own.
