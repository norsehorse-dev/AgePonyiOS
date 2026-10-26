# AgePony iOS 5.0.1 plan (Rev 3)

Parity release: iOS 4.0.1 (live) up to Android 5.0.1 (versionCode 17) in one release. Ships as
iOS 5.0.1 so both stores carry the same number (decided Oct 1; this file was drafted as 5.0.0).
Android 5.0.0 added share, hardware keys, YubiKey decrypt, key transfer and paper backup.
Android 5.0.1 fixed every Android finding from the Sep 23 audit and changed two wire formats
(signature v2, transfer code). iOS has its own audit findings in
`AgePony_Security_Audit_2026-09-23.md`; they ship here too.

References (Android repo): `AgePony_5.0.0_Plan.md`, `AgePony_5.0.0_iOS_Parity.md`,
`AgePony_5.0.1_Plan.md` section 6, `docs/SIGNATURE_FORMATS_v2.md`, and the Kotlin sources named
below. Those are the reference implementation. Where this plan and the Kotlin disagree, the Kotlin
wins and this plan gets fixed.

Last updated: 2026-10-07 (Phase 6). Q1 to Q11 decided.

---

## Status

| Phase | State |
| --- | --- |
| 0. Baseline | Done Oct 1: `.gitignore`, 4.0.1 tree committed and tagged `4.0.1`, dead SwiftData templates and stale root privacy manifest removed. |
| 1. Core formats | Done Oct 1 (5 commits). Signature stanza v1/v2 + bundle v2 + SignedEncryption; tag recipients (classic + hybrid) with pluggable P-256 key agreement; YubiKey PIV (stub, piv-p256 + p256tag, transport-free APDU layer, RecordedKeyAgreement for async NFC); key transfer, both codes, LAN wire format (socket-free encoder + incremental parser), paper backup; strict parsing and audit L-1 to L-14 core fixes. 608 core tests green on Linux in a CryptoKit/OpenSSL test harness (not in the repo), including spec vectors, Android's pinned vectors, both age-plugin-tagtest recipients, every StrictFormatTests vector checked against Go age 1.1.1, and tag stanzas opened both ways by independent Python HPKE / ML-KEM code. Needs `swift test` on the Mac to confirm under real CryptoKit, and an app build to confirm nothing in the app broke against the changed core. |
| 2. Vault and lock | Done Oct 1; `swift test` and the Xcode build green on the Mac Oct 2. Device pass still to do. Core: `PasswordKeyBlob` v2 (device-bound KEK, 2^16, v1 still opens and is re-wrapped, duress outcome carries the decoy's scrypt output), `UnlockAttempts`, `MonotonicClock`, ephemeral GitHub session; 621 core tests green in the harness. App: H-1, H-2, M-1, M-2, M-3, M-4, M-5, M-8, L-15, L-16, L-17, L-21 and the L-25 items except the SE signing ACL (below). Release-build scrypt in the harness: 0.34 s at 2^15, 0.70 s at 2^16 per derivation on a slow VM, so a password unlock is about two of those on a phone; check on the oldest supported iPhone. |
| 3. Hardware keys | Done Oct 2; `swift test` and the Xcode build green on the Mac. Device pass with a real Secure Enclave and YubiKey still to do, plus a re-check of FIDO signing since the NFC transport changed. Secure Enclave `age1tag1` and `age1tagpq1` identities (P-256 in the Enclave, ML-KEM seed in the vault, optional Face ID per use), YubiKey identities from an age-plugin-yubikey stub (key read from the `# Recipient:` line or one NFC tap), YubiKey decrypt over NFC for `piv-p256` and `p256tag` with the PIN asked only when the key wants it, `age1tag` / `age1tagpq` saved recipients, PIV AID in Info.plist, the FIDO transport switching applets when CoreNFC picked the other one, and new SE signing keys with `.userPresence` (L-25) sharing the flow's Face ID prompt. 626 core tests green in the harness, including the one-tap PIV session against the simulated card. Not done: the "also encrypt to a backup recipient" default (moved to Phase 4 with the encrypt flow work) and the `SecItemCopyMatching` sweep test, which needs a device (CryptoKit Enclave keys never create Keychain items, so dropping the blob is the whole wipe). |
| 4. Share and passphrase mode | Code done Oct 2; Xcode build green on the Mac Oct 7 (after adding `import StoreKit` to HomeView). Device pass still to do. Share extension stages files file to file (`loadFileRepresentation`, no whole-file reads), picks decrypt or encrypt from the content, writes with complete protection, keeps the share folder out of backups, and opens the app through `openURL:options:completionHandler:` with the old selector as a fallback. The app checks the token is a UUID, claims the payload at once into its own temp folder (the App Group copy is gone before any flow runs), holds it across the lock screen, picks up a staged payload from the last ten minutes if the extension couldn't open the app, and sweeps on launch, lock and duress. Decrypted files share out behind a warning and are deleted when the flow goes away. Lock screen gets "Continue without unlocking" (passphrase text encrypt and decrypt, passphrase file decrypt, signed-bundle check without signer names), which can also finish a waiting share. "Also encrypt to" backup recipient default in Settings. L-23: no autocorrect learning in note and text editors, no text selection on sensitive key blocks, third-party keyboards blocked. Still to verify on iOS 26: that the extension really opens the app (the pick-up path covers it if not). |
| 5. Transfer and paper backup | Code done Oct 7; Xcode build green on the Mac Oct 7. Still to do: `xcodebuild test` (KeyPortabilityTests) and a device pass. App side of 1.4 and 1.5 (the core was Phase 1). `KeyPortability` writes and reads `agepony.json` in Android's record shapes (Q6) and converts the four places the vaults differ (ssh-ed25519 raw key and 32-byte seed vs wire blob and seed||pub; ssh-rsa `ssh-rsa` line vs wire blob; `postQuantum` = `mlkem768x25519`; `yubikey` = `yubikeyPiv` / `yubikeyP256`; the `contacts` source goes out as pasteAge/pasteSSH, which Android knows). Records decode one by one, unknown types and hardware keys are skipped, and every identity is checked against its public key (AS-2; ssh-rsa by a test signature). `LanLink`: NWListener bound to the Wi-Fi or hotspot address with a fallback to all interfaces, 4 slots with oldest unauthenticated evicted, 10 s handshake and 120 s transfer deadlines, the transfer opened before the ACK; sender never over cellular. Send keys and Receive keys screens (preview, transfer code, signers unticked, nothing made active, file and paste route, Local Network string), Paper backup on identity detail (PDF via UIGraphicsPDFRenderer, protected by default at scrypt 2^18, diceware, weak-passphrase gate, AirPrint warning), Restore from a paper backup in Settings (memory guard on the page's work factor). Owner check before keys leave: app password when it's the only unlock, else Face ID / passcode. Key files live in `tmp/AgePonyKeys-*`, removed on leaving the screen and on lock. `addIdentity(activate:)` as on Android. App tests: `AgePonyTests/KeyPortabilityTests.swift`. |
| 6. Help, release prep, gaps | Code done Oct 7, waiting on an Xcode build, `swift test`, `xcodebuild test` and the device pass. 2.8 no-passcode setup (Q11: plain message plus an AgePony password or PIN; `bootstrap(lockMode: .none)` then the password, half-made vault removed on failure; `KeychainError` in words with the OSStatus; Lock settings refuses Biometric without a passcode). Gaps found while doing Phase 6 and closed: the app side of 1.1 was never wired (sign-and-encrypt to keys now writes sig stanza v2 via `SignedEncryption`, passphrase files bundle v2; decrypt reads the stanza three ways and verifies it against the written file; bundles verify under their version's namespace, which made Android v2 bundles fail before; v1 notes; a header-signed file isn't unwrapped as a bundle; Re-encrypt refuses a header-signed file; packages flattened before signing), M-9 (recipients never trusted as signers), L-7 app side (trusted signer checked with `AllowedSigner.accepts`), L-2 app side (largest work factor). 2.7: Help and Security pages, software keys before Secure Enclave keys on decrypt. Release: MARKETING_VERSION 5.0.1 on app and extension, extension build aligned, `AgePony_iOS_5.0.1_ReleaseNotes.md`, App Store release notes, description (iOS 17.0, under 4,000 characters), review notes for local network and NFC. |

Notes from phase 1 that land in later phases:

- ssh-ed25519 public keys are now validated as curve points (Android does the same). One old test fixture was not a real point and was replaced. A stored recipient with a bad key will now fail to encrypt instead of producing a file nobody can open.
- Malformed armor, CRLF headers and non-canonical base64 that 4.0.1 accepted are now refused, matching Go age and Android 5.0.1. Pasted armor with other line widths (76 columns) no longer decodes.
- App-side items found while porting: the scrypt memory guard must take the largest work factor across stanzas (L-2), FileVerifier should call `AllowedSigner.accepts` and stop trusting recipients (M-9), add `A000000308` to the NFC select identifiers, add `35F9.1` to the privacy manifest for the monotonic clock.
- The C2SP CCTV testkit wasn't added: GitHub isn't reachable from the session's sandbox. Still worth adding on the Mac.

Notes from phase 5:

- QR spike: the invite is about 2,040 characters. CoreImage encodes byte mode only, which is version 33 at level L and
  38 at M (Android's ZXing picks alphanumeric: 27 at L). The receive screen uses L, like Android. Confirm on a device that
  Android scans the iPhone's code and the iPhone scans Android's.
- Hotspot spike, decided without a device: the sender uses `prohibitedInterfaceTypes = [.cellular]` rather than
  `requiredInterfaceType = .wifi`, so the hotspot case (`bridge100`) isn't excluded. Device pass: iPhone as hotspot,
  Android as hotspot, both on Wi-Fi, and Wi-Fi plus a VPN.
- Local Network permission: iOS reports `.waiting(.dns(-65570))` while its first-use alert is up. The sender waits up to
  60 s for an answer; only `.failed` with that code is final. Check on a device where the alert appears (sender's first
  connect, or the receiver's listener) and what a denied receiver looks like to the sender.
- Signers that carry allowed_signers options (namespaces=, valid-before=, ...) are not imported on iOS: the iOS vault has no
  options field (L-6 is core only here), so they'd lose their restrictions. Android imports the ones it can enforce. Adding
  `options` to the iOS `StoredSigner` would close the gap; not in this phase.
- ssh-rsa keys under 2048 bits drop out of the iOS preview without a line (the parser refuses them); Android lists them with
  a warning, unticked.
- The transfer tar also carries Ed25519 OpenSSH PEMs under `ssh/` (Android puts only RSA there). Both readers use
  `agepony.json` when it's present, so this only helps `age -d | tar x`.
- Plan 2.6 said YubiKey stubs print as a reference. Android's paper backup is X25519 and post-quantum only, and so is this;
  the stub is on the identity screen already.

## 0. Where iOS stands today (from reading the tree)

| Area | State on iOS | What it means for this release |
| --- | --- | --- |
| Repo | One commit ("Initial Commit"). Almost everything (Features, Services, Vault, Sources, Tests, the extension) is untracked. No `.gitignore`. | Commit a 4.0.1 baseline before touching anything (section 7). |
| Version | App `MARKETING_VERSION 4.0.1`, share extension still `3.1.0`. Project-level and test targets at iOS 26.5, app and extension at 17.0. | Bump app and extension together. |
| Secure Enclave | `secureEnclaveP256` is a **signing** key only (`SecureEnclave.P256.Signing`, `ecdsa-sha2-nistp256`). There is no SE decryption key. | No migration needed. The `age1tag1` SE key is a new identity type next to it, not a replacement. Closes Android plan decision 6. |
| piv-p256 | Encrypt only (`P256Stanza.swift`). No identity side. | YubiKey decrypt is new on iOS. |
| HPKE P-256 / tag | Absent. Hybrid `mlkem768x25519` HPKE is there (hand-rolled ML-KEM, SHA-3). | Tag recipients reuse the ML-KEM and SHA-3 code. |
| Signing | `SignedBundle` v1 only. No sig stanza. | iOS needs stanza v1 read, stanza v2 read/write, bundle v2 read/write. |
| NFC | Info.plist lists only the FIDO AID `A0000006472F0001`. Entitlement has `TAG`. | Add PIV AID `A000000308`. |
| Share | Extension stages the payload in the App Group and opens the app with `agepony://share?token=`. | Base exists. Model is question Q1. Audit M-7 and L-24 apply. |
| scrypt | `ScryptMemory` caps the work factor at 20 with a memory check. | #12 is effectively covered. Still missing: "scrypt must be the only stanza" on decrypt (L-2). |
| RSA | 2048-bit minimum already enforced for recipients. | Android L-4 already done on iOS. Signer side still to check. |
| Header | 1 MiB cap already. MAC is computed over re-serialized stanzas, not raw bytes. | L-1: MAC the raw header bytes. |
| Copy/QR lag (tester report) | Working tree already flips Copy instantly and writes the pasteboard off the main thread; QR renders in `Task.detached`. | Probably fixed post-4.0.1. Verify on device with a Secure Enclave key. |
| Passphrase-only mode (#13) | Absent. | New. |

Interop today: an Android 5.x file signed with the stanza opens on iOS 4.0.1 (unknown stanzas are
skipped) but shows as unsigned. A 5.0.1-signed bundle (passphrase files) is v2 and iOS 4.0.1
reads it as v1 and fails verification. Key transfer and paper backups don't exist on iOS. Confirm
the first two with real files during phase 1, they're good release-note material.

## 1. Wire formats (must match Android byte for byte)

Everything here lives in `AgePonyCore` and gets `swift test` coverage with the Android test
vectors before any UI is built.

### 1.1 Signatures

Reference: `signing/SignatureStanza.kt`, `archive/SignedBundle.kt`, `docs/SIGNATURE_FORMATS_v2.md`.

- [ ] Sig stanza **v1 read**: `agepony.com/sig v1`, key = HKDF-SHA256(fileKey, salt empty,
      info `agepony.com/sig-v1`), body = nonce(12) || ChaCha20-Poly1305(armored SSHSIG). SSHSIG
      over the plaintext, namespace `agepony`. Show the "doesn't cover recipients" note.
- [ ] Sig stanza **v2 read and write**: info `agepony.com/sig-v2`, namespace `agepony-sig-v2`,
      M_sig over SHA-512(plaintext) and SHA-512(R), R built from the raw stanza bodies in header
      order, skipping `agepony.com/sig`. Stanza goes after the recipient stanzas, before the MAC.
- [ ] Signed bundle **v2 read and write** (passphrase files only): manifest
      `agepony-signed/2\nname=...\n`, M_bundle, namespace `agepony-bundle-v2`. Manifest cap 4096,
      sig entry cap 8192.
- [ ] Bundle v1 read stays (every iOS-signed file to date is a v1 bundle).
- [ ] Three-way result: absent / unreadable / opened(version). Unreadable shows as a failed
      signature, never unsigned. Verify before writing when the data is in memory (L-9).
- [ ] Detached `.sig` unchanged (`agepony` namespace).
- [ ] `allowed_signers`: `namespaces="agepony"` also allows the two v2 namespaces unless negated.
- [ ] Test vectors from the spec: SHA-256(M_sig) = `8c7f5062...ed65524f`,
      SHA-256(M_bundle) = `f1e944ee...3386d0b7`.

Note for the streaming path: v2 needs SHA-512 of the plaintext before the header is written,
so a streaming sign-and-encrypt of a large file needs two passes over the input (hash, then
encrypt). Check how Android handles it in `SignedEncryption.kt` and do the same.

### 1.2 Tag recipients `age1tag1` / `age1tagpq1`

Reference: `crypto/HpkeP256.kt`, `recipients/Tag.kt`, `recipients/HardwareIdentity.kt`.

- [ ] Hand-roll the RFC 9180 key schedule for DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 +
      ChaCha20Poly1305 rather than using CryptoKit's `HPKE`. Reasons: the hybrid
      MLKEM768-P256 combiner isn't in CryptoKit on iOS 17, the Secure Enclave key only gives us
      ECDH, and one code path is easier to pin to the tagtest vectors.
- [ ] Classic: recipient = 33-byte compressed point, HRP `age1tag`, enc = 65-byte uncompressed
      point, info `age-encryption.org/p256tag`.
- [ ] Hybrid: KEM 0x0050, shared secret = SHA3-256(ss_PQ || ss_T || ct_T || ek_T ||
      "MLKEM768-P256"), enc = ct_PQ(1088) || ct_T(65), recipient = ek_PQ(1184) || P-256(65),
      HRP `age1tagpq`, label `postquantum`.
- [ ] Tag = HKDF-Extract(salt = label, ikm = enc || SHA-256(P-256 part)[:4])[:4]. Classic
      hashes the compressed point, hybrid the uncompressed P-256 part. Constant-time compare.
- [ ] Only SEC1 02/03 (33) and 04 (65) accepted.
- [ ] KATs: DeriveKeyPair with ikm `age-plugin-tagtest` gives the recipients in
      `TagRecipientTest.kt`.
- [ ] No mixing hybrid and classic recipients in one file (same rule as `age1pq1`).
- [ ] Recipient picker and Add Recipient accept `age1tag1` / `age1tagpq1`, and a one-time
      `age1yubikey1` (Android 5.0.0 fixed that one going to the X25519 parser; check iOS).

### 1.3 YubiKey PIV identity

Reference: `recipients/YubiKey.kt`, `piv/Piv.kt`.

- [ ] Stub `AGE-PLUGIN-YUBIKEY-1...`: HRP `age-plugin-yubikey-`, serial (u32 LE) || slot
      (0x82 to 0x95) || tag (SHA-256(compressed key)[:4]).
- [ ] `piv-p256` unwrap: wrap key = HKDF-SHA256(ECDH x, salt = epk || compressed recipient,
      info `piv-p256`), ChaCha20-Poly1305, zero nonce. One identity answers `piv-p256` and
      `p256tag`.
- [ ] APDUs: SELECT PIV, VERIFY PIN, GENERAL AUTHENTICATE (ECDH) on the stub's slot. Bounded
      `61xx` chaining and lengths (L-11). Core takes a transport protocol so tests run against a
      simulated card, as Android does.

### 1.4 Key transfer `agepony.com/transfer v1`

Reference: `portability/KeyTransfer.kt`, `TransferCode.kt`, `LanTransfer.kt`, app
`vault/KeyPortability.kt`.

- [ ] Age file to a one-time `age1pq1` key, holding a tar: `FORMAT`, `identities.txt`,
      `ssh/<name>`, `agepony.json`. Max 512 entries, regular files only.
- [ ] Confirmation code (receiver key): SHA-256 of the lowercased trimmed recipient, first 60
      bits, Crockford base32, `XXXX-XXXX-XXXX`.
- [ ] Transfer code (5.0.1, M-6): SHA-256("agepony.com/transfer-code v1" || 0x00 || sealed),
      armored input de-armored first. Vector: the 36 bytes `age-encryption.org/v1\n-> X25519 abc\n`
      give `QNED-DFQW-8WY0`.
- [ ] Invite string: `AGEPONY:XFER1/<RECIPIENT>/<TOKEN HEX>/<PORT>/<IP>+<IP>`, upper-cased for
      QR alphanumeric mode, lowercased before parsing.
- [ ] LAN framing (RelayPony wire v1): `type(1) | len(4 BE) | payload`. Sender: HELLO(v1, scheme
      age, device name, handle = token hex), FILE_BEGIN(u64), FILE_CHUNK*, FILE_END(sha256),
      DONE. Receiver: ACK(1/0). 16 MiB cap, 64 KiB chunks, 10 s handshake deadline, 4 slots.
- [ ] `agepony.json`: Android's `StoredIdentity` / `StoredRecipient` / `StoredSigner` shapes
      (question Q6). Decode records one by one and skip unknown types. Consistency-check every
      imported identity against its public key (SSH, RSA, PIV, sk), as Android's AS-2 does.

### 1.5 Paper backup

Reference: `portability/PaperBackup.kt`.

- [ ] Protected page = armored age, scrypt work factor 18, over an identity file with
      `# name:` and `# created:` and no `# public key:` line.
- [ ] Restore takes a protected page or a bare `AGE-SECRET-KEY-...` string. X25519 and PQ only.

### 1.6 Stricter parsing (audit Low items that touch the iOS core)

- [ ] L-1: strict canonical base64, Go-exact stanza grammar, MAC over raw header bytes.
- [ ] L-2: refuse a header with scrypt plus anything else before any KDF work; memory guard
      takes the largest work factor across stanzas.
- [ ] L-5: 32-byte wrapped-key bodies, 16-byte file keys.
- [ ] L-6 / L-7: `allowed_signers` options parsed, enforced, kept on export; `sk-*` needs the
      user-presence flag unless `no-touch-required`.
- [ ] L-10: bcrypt_pbkdf rounds cap (Android used 10,000) plus salt and key-length caps.
- [ ] L-11: CBOR length and depth bounds, no `Int()` traps, no `reserveCapacity` from input;
      RSA mpint p <= 1 doesn't hit a precondition.
- [ ] L-12: ML-KEM encapsulation-key modulus check (FIPS 203).
- [ ] L-13: `Field25519` subtraction fix, reject y >= p.
- [ ] L-14: unit test that a low-order X25519 point is "not for me", not a crash.
- [ ] Empty final STREAM chunk refused. Armor lines capped at 4 KiB while reading. Tar: regular
      files only, no truncation.
- [ ] Suggestion: add the C2SP CCTV age testkit vectors to `Tests/`. The audit notes they'd have
      caught L-1, L-2, L-5 and the empty chunk. Worth adding to Android at the same time.

## 2. Features

### 2.1 Secure Enclave decryption keys (`age1tag1` / `age1tagpq1`)

- New `StoredIdentityType` cases (working names `secureEnclaveTag`, `secureEnclaveTagPQ`).
  Vault schema bump: a vault holding one can't be opened by 4.x, same as Android.
- `SecureEnclave.P256.KeyAgreement.PrivateKey` with access control
  `.privateKeyUsage` (plus `.userPresence` when per-use unlock is on, off by default). Store the
  `dataRepresentation` blob in the vault, like the signing key.
- Don't use `.biometryCurrentSet`: Android chose "not invalidated by biometric re-enrollment".
- Unlike Android, an iOS SE key isn't deleted when the passcode is removed (unless created
  with a passcode-set accessibility). Say so on the iOS create screen instead of copying
  Android's warning word for word.
- Hybrid: Secure Enclave holds the P-256 half, the ML-KEM-768 half lives in the vault,
  exactly as Android (Q2). Works on iOS 17+. The iOS 26 Secure Enclave ML-KEM is a later spike.
- Decrypt order: software identities on every stanza first, hardware last; surface a hardware
  error only if nothing else opened the file (Android `Age.unwrapFileKey`).
- Simulator has no SE: hide creation there, and put the SE behind a protocol so `swift test`
  runs the same path with a software P-256 key.
- Wipe, duress and purge from Recently deleted: dropping the blob is enough (no persistent SE
  keychain item is created). Confirm with a `SecItemCopyMatching` sweep in a test.
- Loss warning on create, plus "also encrypt to a backup recipient" as a saved default.

### 2.2 YubiKey decrypt

- Import the stub, one NFC tap reads the slot's public key, then `piv-p256` and `p256tag`
  decrypt over NFC with a tap, PIN when the slot wants it. Only prompt when the file is
  addressed to that key (tag match first).
- CoreNFC `NFCISO7816Tag`; add `A000000308` to
  `com.apple.developer.nfc.readersession.iso7816.select-identifiers`. The FIDO NFC session code
  in `Services/FIDO/SecurityKeyTransport.swift` is the model.
- NFC only, matching Android (Q3). USB-C / Lightning comes later on both platforms together.

### 2.3 Share extension

- Match Android behavior: armored or binary age in means decrypt, anything else means encrypt.
  Ciphertext shares out freely; plaintext shares out behind the warning.
- Signed files arriving by share get the same verdict as the Files tab.
- Hard memory ceiling in the extension (~100 MB on recent iOS): route files by URL, never
  `Data(contentsOf:)` on the whole file; refuse a scrypt work factor that doesn't fit before
  allocating.
- Audit fixes: M-7 (delete the payload as soon as the app reads it, hold the token in its own
  state, `.completeFileProtection`, exclude from backup, sweep on launch, lock and duress),
  L-24 (`UUID(uuidString:)` for the token, sanitized intent filenames), L-25 (no whole-file reads).
- Model stays hand-off to the app (Q1). The extension never touches the vault or the Keychain.
  Verify early that the responder-chain `openURL` still launches the app on iOS 26; if it does
  not, the fallback is a "Open AgePony to continue" screen in the extension plus pickup of the
  staged payload on next launch.
- No equivalent of Android's PROCESS_TEXT "replace selection". iOS action extensions can hand
  text back, but almost no host app accepts it. Deliberate limit, listed in release notes.

### 2.4 Passphrase work without unlocking (#13)

- Lock screen gets "Continue without unlocking": passphrase text encrypt/decrypt and passphrase
  file decrypt. Vault stays locked, no keys touched. A share arriving while locked offers it too.

### 2.5 Send / Receive keys

- Settings > Send keys / Receive keys, same screens and wording as Android.
- Receiver: one-time `age1pq1` key in memory only, `NWListener` on TCP bound to the Wi-Fi (or
  hotspot `bridge100`) address, QR invite, 15-minute expiry, listens only while the screen is
  open. Shows the transfer code after receiving; Import stays disabled until confirmed. Preview
  lists every key with its fingerprint, warns on name clashes, signers start unticked, nothing
  becomes the active identity.
- Sender: pick keys, re-authenticate, scan the invite, compare the confirmation code, seal,
  `NWConnection` with `requiredInterfaceType = .wifi`, show Sent only after ACK, show the
  transfer code.
- File route fallback: share sheet / AirDrop / Files, plus paste. Same transfer code on every
  route.
- Needs `NSLocalNetworkUsageDescription`. No Bonjour, so no `NSBonjourServices`. Handle the
  Local Network permission being denied: say where to turn it on and offer the file route.
- Hardware keys never move; YubiKey stubs do (reference only).
- Spike first: confirm `CIQRCodeGenerator` produces a scannable code for the ~2,050-character
  invite. If CoreImage encodes it in byte mode at correction level M it may not fit; fall back to
  level L or a small alphanumeric-mode encoder.
- Spike: when the iPhone is the hotspot, check that `.wifi` interface matching still works on
  `bridge100`, or the hotspot case needs `.other`.

### 2.6 Paper backup

- Identity detail > Paper backup: PDF via `UIGraphicsPDFRenderer`, QR plus chunked text,
  label, public key, created date, restore steps. Protected by default (diceware offered, weak
  passphrase warning), plain mode behind a strong warning. Save to Files or share; AirPrint
  shows a warning that print services can spool or forward the page.
- Settings > Restore from a paper backup: scan or type, passphrase, import, never made active.
- Hardware identities show "can't be backed up"; YubiKey stubs print as a reference.
- Screen is always covered in the app switcher regardless of settings.

### 2.7 Smaller parity items

- Software keys before hardware keys on decrypt (2.1).
- Transferred and paper-restored keys aren't made active; picker only preselects the identity
  the user made active.
- In-app Help and Security pages: hardware keys, YubiKey, transfer, paper, passphrase mode,
  duress means PIN-only.

### 2.8 Setup on a phone with no passcode

Found from an App Store review on 4.0.1 (Oct 7): "I keep getting a keychain error", still there
after reinstalling and resetting the Keychain. A fresh 4.0.1 install sets up fine on a phone with
a passcode. Likely cause: `Vault.bootstrap()` always calls `KeychainStore.storeMasterKey` with the
biometric ACL (`[.biometryCurrentSet, .or, .devicePasscode]`, `WhenUnlockedThisDeviceOnly`).
With no device passcode set, `SecItemAdd` fails, and onboarding shows
`error.localizedDescription`, which for `KeychainError.unhandled` is the useless
"The operation couldn't be completed. (AgePony.KeychainError error 0.)". Reinstalling can't help,
and iCloud Keychain resets don't touch a `ThisDeviceOnly` item. HEAD still has the same path
(`bootstrap()` sets `lockMode = .biometric` unconditionally).

- Before bootstrap, check `LAContext().canEvaluatePolicy(.deviceOwnerAuthentication)`. On
  `LAError.passcodeNotSet`, don't try the biometric ACL.
- No-passcode path (Q11): say plainly that iOS needs a passcode for the Face ID / passcode lock,
  with a button to Settings, and offer setting up with an app password instead (`.none` lock
  mode plus password; after M-3 that is password wrap only, and the Q7 binding secret is
  `WhenUnlockedThisDeviceOnly`, which works without a passcode).
- `KeychainError` conforms to `LocalizedError`; `unhandled` shows the OSStatus and
  `SecCopyErrorMessageString`, so a report carries a real code.
- Related case to verify on device: passcode removed after setup invalidates the biometric-ACL
  item. Load returns not found while `vault.dat` exists; L-25 should route that to
  "Can't open vault" with Reset, never to onboarding over the old vault.
- Tests: device pass on a phone with the passcode turned off (fresh setup, and an existing
  vault after turning the passcode off).

## 3. Security parity with Android 5.0.1 (and the iOS-only audit findings)

| Audit | Android 5.0.1 fix | iOS 5.0.1 fix |
| --- | --- | --- |
| H-1 | Duress makes the vault PIN-only | Setting duress asks for the current PIN, deletes the biometric-ACL Keychain master key and any plain key, hides Face ID on the lock screen, disables lock-mode rows. A 4.0.1 vault with duress plus Face ID goes PIN-only at once; leftover wraps deleted after the first PIN unlock. |
| H-2 (iOS) | n/a | `isExcludedFromBackup` on `Application Support/AgePony`. Password blob v2 device-bound (next row). |
| M-2 analog | KEK = HMAC(Keystore key, scrypt(secret, 2^16)) | KEK = HMAC(32-byte `WhenUnlockedThisDeviceOnly` Keychain secret, scrypt(secret, 2^16)). Blob byte 0 = 2. v1 still unlocks and is re-wrapped; the new blob is opened once before the old one is deleted. Measure unlock time at 2^16 on the oldest supported phone. Binding choice is Q7. |
| M-3 (iOS) | n/a (H-4 is the Android twin) | `.none` plus a password: delete the plain Keychain item, password wrap only. 4.0.1 vaults in that state migrate on first password unlock. |
| H-3 / M-4 | Process-wide auto-lock, bounded picker exemption | Grace measured on a monotonic clock that keeps counting while asleep (`CLOCK_MONOTONIC_RAW`), negative or restarted means lock. "Immediately" locks on entering the background; a grace period also locks from a background task when it runs out. Lock on `protectedDataWillBecomeUnavailable` (screen lock). No picker exemption needed: the iOS document picker and share sheet don't send the scene to the background. Privacy manifest gains System boot time, reason 35F9.1. |
| M-1 | 6-digit PIN / 8-char password minimum, backoff, optional erase after 10 | Same rules. Counter persisted as `unlock.attempts` in the vault directory, like Android (lives and dies with the blobs, excluded from backup, cleared by reset and wipe); counted before the check; reboot-aware via the monotonic clock and boot time. Real and duress unlocks reset it. Re-auth checks share it. |
| M-5 | FLAG_SECURE by default, "Allow screenshots" toggle | Privacy cover in its own `UIWindow` above `.alert` so sheets are covered. Screenshot blocking is Q4. |
| M-6 | Transfer code, fingerprints, signers unticked, never active | Built that way from the start (2.5). |
| M-7 (iOS) | n/a | Share and tmp residue sweep (2.3). Clean decrypt temp files in `onDisappear`, not only on Done/Cancel. |
| M-8 | Duress keeps onboarding flag, resets prefs, sweeps cache | Wipe tmp, App Group payloads, `AgePonySigners-*`, proxy settings, review counters, `URLCache` and cookies, `Documents/Inbox`. Keep the onboarding flag. Pad the wrong-PIN path with a dummy scrypt; reuse the computed scrypt for the decoy vault so timing matches. |
| M-9 (iOS) | n/a | Saved recipients stop counting as trusted signers. At most "valid, not trusted" with the recipient name as a hint. |
| L-1 to L-14 | Core hardening | Section 1.6. |
| L-15 | Re-auth before weakening the lock | Same list: No lock, remove or change password, remove duress, longer grace, allow screenshots (if Q4 adds it), erase-after-10 off. |
| L-16 / L-17 | Remove-password guard, real PIN can't equal duress | Same. Today iOS silently disables duress when they match (L-25). |
| L-18 / L-19 | Failed decrypt leaves nothing, staging copies deleted | iOS already deletes on failure; fix the swipe-dismiss and crash paths (M-7). |
| L-21 | Settings out of backups | Proxy credentials move from UserDefaults to the Keychain. |
| L-23 | Secrets out of saved state, masked fields, copies via ClipboardGuard | Autocorrect and learning off in note and text editors. `.textSelection` off on sensitive key blocks. Block third-party keyboards in the app. |
| L-25 (iOS) | n/a | Keychain update adds under a staging account before it deletes, and loads fall back to it. Onboarding only when no piece of a vault exists; a vault file with no key shows "Can't open vault" with Reset. Lock mode pinned once for pre-4.0.0 vaults, so "In-app biometric prompts" can't flip it. Notes text now says 2^16, which is what notes use. Direct GitHub fetch uses an ephemeral session. **Deferred to Phase 3:** SE signing key `.userPresence`, since it changes the key's access control and needs the same new-key path as the SE tag keys. |
| R8, key rotation (C-1), overlays (L-22), file:// shares (L-20) | Android only | Nothing to port. App Store signing was never exposed. |

## 4. Deliberately not in this release

- Tor / SOCKS: no longer deferred by default; see Q9 (spike first).
- Replace-selection (Android PROCESS_TEXT): no reliable iOS equivalent.
- README rewrite: deferred to the end, same as Android did.
- Dropping to iOS 16: no. The tag code is fine on 16, but CryptoKit `HPKE` and other iOS 17
  APIs are already in the tree; minimum stays 17.0.

## 5. Order of work

1. **Phase 0, baseline.** `.gitignore`, commit the 4.0.1 tree, tag `4.0.1`, delete the dead
   SwiftData templates (`Item.swift`, `ContentView.swift`, which also carry a personal-name
   header), drop the stale root `PrivacyInfo.xcprivacy`, align the extension version.
2. **Phase 1, core formats** (`swift test` only): signatures (1.1), tag recipients (1.2),
   PIV (1.3), transfer and codes (1.4), paper (1.5), hardening and CCTV (1.6). Generate
   cross-platform fixtures on Android and check them in on both sides.
3. **Phase 2, vault and lock** (section 3): new identity types and schema bump, blob v2,
   PIN-only duress, attempts, monotonic auto-lock, residue sweeps, re-auth. Done before the
   features because transfer, paper and SE keys all write to the vault.
4. **Phase 3, hardware keys**: SE tag keys, then YubiKey NFC.
5. **Phase 4, share and passphrase mode**.
6. **Phase 5, transfer and paper backup** (including the two QR / hotspot spikes up front).
7. **Phase 6**: Help and Security pages, release notes, device pass, version bump, TestFlight.

## 6. Tests

Unit (`swift test`):
- Every vector in section 1, plus the tagtest KATs and CCTV.
- Negative tests: CBOR, tar, SSH keys, `allowed_signers` options, sk UP flag, mixed scrypt
  headers, non-canonical base64.

Cross-platform (real devices, both directions unless noted):
- Signed files: iOS to Android, Android to iOS, each to `age -d` returning the bare bytes;
  v2 stanza and v2 bundle; 4.x/5.0.0 v1 files show the v1 note.
- `age1tag1` / `age1tagpq1`: age 1.3 CLI to the SE key; iOS to the tagtest plugin.
- YubiKey: a file from `age-plugin-yubikey` (old `piv-p256` and new `p256tag`) opens on iOS;
  wrong PIN; PIN retry counter.
- Key transfer: iOS to Android and Android to iOS over Wi-Fi, over each phone's hotspot, with
  a VPN on; file and paste routes; codes match on every route; Local Network permission denied.
- Paper backup made on one platform restores on the other, and with `age -d`.
- Share: locked vault, huge scrypt work factor, 1 GB file into the extension.

Lock and vault (device):
- Duress on a Face ID vault, 4.0.1 vault upgrade with duress plus Face ID, timing of real vs
  duress vs wrong PIN, backoff across kill and reboot, erase after 10, clock set backwards with
  the vault open, screen lock, iCloud/Finder backup contains no vault files, app switcher with
  a sheet open.

## 7. Release mechanics

- `MARKETING_VERSION 5.0.1` on the app and the extension (extension is at 3.1.0 today).
- App Store description still says "Requires iOS 18.6"; fix with this submission.
- New Info.plist strings: `NSLocalNetworkUsageDescription`. NFC string already present.
- Privacy manifest: the shipped `AgePony/PrivacyInfo.xcprivacy` declares only CA92.1 and C617.1.
  The monotonic auto-lock clock (boot time / uptime) needs `35F9.1` added.
- App Privacy answers don't change (no data collected; LAN traffic is device to device).
- Review notes: explain the local network use and that key transfer needs two devices.
- TestFlight "What to Test": English and Simplified Chinese, under ~3,900 bytes.
- Same version number as Android (Q5), so "both phones need 5.0.1" holds across platforms.
  Release notes still note that iOS skips 5.0.0 and gets both Android releases at once.

## 8. Credit

Issues #11 to #14 and the Sep 2026 audit. Copy/QR lag from a tester report. Identity transfer
from a user request (Jul 2026). No personal names in anything shipped or committed.

## 9. Decisions and open questions

Decided (Oct 1 2026):

- **Q1. Share model:** hand-off to the app, hardened (M-7, L-24, L-25). The extension never sees
  the vault.
- **Q2. Hybrid SE key:** ML-KEM half in the vault, Secure Enclave holds P-256, same as Android.
  iOS 26 Secure Enclave ML-KEM is a later spike.
- **Q3. YubiKey:** NFC only. USB-C on both platforms later.
- **Q5. Version:** iOS ships as 5.0.1.

Decided later on Oct 1 2026:

- **Q4. Screenshots:** fix the app-switcher cover (own window, covers sheets) and blank the window
  while screen recording is detected. No screenshot-blocking trick, no "Allow screenshots" toggle.
- **Q6. `agepony.json`:** Android 5.0.1's JSON is the schema. Document it as
  `docs/TRANSFER_FORMAT_v1.md` in the Android repo; iOS reads and writes exactly that.
- **Q7. Password key binding:** HMAC with a random 32-byte `ThisDeviceOnly` Keychain secret.
- **Q8. LAN code:** vendor the Swift transport from RelayPony iOS (folder connected to the session).
- **Q9. Tor:** look at it for 5.0.1. Spike first: an embedded Tor library (or a SOCKS path for
  the GitHub key fetch) against the current HTTP-only proxy. Scope decision after the spike.
- **Q10. Distribution:** straight to App Review, no TestFlight round. The device pass in
  section 6 carries more weight because of that.

Decided Oct 7 2026:

- **Q11. No passcode at setup (2.8):** plain message plus an AgePony password or PIN
  (password-only vault). Done in Phase 6.
