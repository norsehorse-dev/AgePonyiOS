# AgePony iOS 5.1.0 RC3: E8 CryptoKit on iOS 26 and Enclave ML-KEM keys

Status: code done Oct 26 2026, not built yet. Needs `swift test`, `xcodebuild test` and the device
list below. Follows the spike write-up (`AgePony_5.1.0_RC3_Spike.md`, results and S4 design) except
where the RC3 brief differs: no new `StoredIdentityType` case (downgrade safety, below).

## Design as built

### A. CryptoKit path for the post-quantum KEMs (iOS 26 / macOS 26)

One switch, `HybridKEMBackend` (new, `Sources/AgePonyCore/Crypto/HybridKEMBackend.swift`), behind the
same public types, so the app doesn't change:

| Operation | iOS 26 / macOS 26 | iOS 17 to 25 |
| --- | --- | --- |
| `HybridIdentity` (age1pq1) key from the 32-byte seed | `XWingMLKEM768X25519.PrivateKey(seedRepresentation:publicKey: nil)` | own `HpkeMlkem768X25519.PrivateKey` |
| `mlkem768x25519` open | `HPKE.Recipient` with `Ciphersuite(kem: .XWingMLKEM768X25519, kdf: .HKDF_SHA256, aead: .chaChaPoly)` | own |
| `mlkem768x25519` seal (`HybridRecipient.wrap`) | `HPKE.Sender`, same suite | own |
| ML-KEM half of `TagIdentity.hybrid(mlkemSeed:)` | `CryptoKit.MLKEM768.PrivateKey(seedRepresentation:publicKey: nil)` | own `MLKEM768.KeyPair` |
| ML-KEM encapsulation for `age1tagpq1` recipients | `CryptoKit.MLKEM768.PublicKey.encapsulate()` | own |
| MLKEM768-P256 combiner, HPKE key schedule, P-256 | own (CryptoKit has no MLKEM768-P256) | own |

Validation stays AgePony's and runs before CryptoKit sees any bytes:

- Decrypt (`HybridIdentity.unwrap`): stanza type (exact case), one argument, canonical base64
  (`Stanza.base64Decode`), enc 1120 bytes, body 32 bytes, all as before; then the low-order /
  all-zero X25519 check on `ct_T` with the same `HpkeMlkem768X25519.x25519Exchange` call the own code
  makes (the CryptoKit key keeps the X25519 scalar, derived as SHAKE256(seed)[64..<96]); then
  CryptoKit opens; then a 16-byte file key check (also `Age.checkFileKey` later). Any failure is nil,
  as before. Tag stanzas: `TagIdentity.parse` (type, two args, body, base64, tag, enc length) is
  unchanged and runs before any decapsulation.
- Encrypt: public key length (`HybridKEMError.invalidPublicKeyLength`), FIPS 203 modulus check
  (`MLKEMError.malformedEncapsulationKey`), then the X25519 low-order refusal via the same
  `x25519Exchange` (same error as the own code), in the own code's order. For tag recipients:
  length and modulus check before `CryptoKit.MLKEM768` encapsulates.
- No fallback: on iOS/macOS 26 CryptoKit is the only ML-KEM / X-Wing code that runs for
  decapsulation, encapsulation and HPKE seal/open, including for stanzas not addressed to the user.
  A CryptoKit throw after AgePony's checks is never retried through the own code; it maps to the
  error the own code gives for that failure, so UserMessage and CCTV categories are unchanged:
  - X-Wing open fails (authentication or anything else): nil, "not for me", as before.
  - Software ML-KEM decapsulation for a tag key fails: `MLKEMDecapsulationRefused`, which
    `TagIdentity.unwrap` turns into nil (the own code reaches "not for me" there through implicit
    rejection). Enclave ML-KEM errors (a cancelled prompt) still propagate as `SecureEnclaveKeyError`.
  - X-Wing seal fails: `HpkeMlkem768X25519.mapSealError` keeps `HybridKEMError`, `MLKEMError` and
    `CryptoKitError` as they are and maps anything else to `HybridKEMError.invalidPublicKeyLength`
    ("That quantum-safe key is damaged."); an enc of the wrong size is `invalidEncapsulationLength`.
  - Tag ML-KEM encapsulation fails: `MLKEMError.malformedEncapsulationKey`
    (`HybridKEMBackend.mapEncapsulationError`).
  - CryptoKit refuses a seed when building a key: `HybridKEMError.invalidSeedLength` (age1pq1) or
    `MLKEMError.invalidSeedLength` (tag ML-KEM half), the own "damaged key" errors.
  - The one remaining own-code ML-KEM keygen on 26 (making a seed-layout tag key in tests) now goes
    through `HybridKEMBackend.mlkemKey` too, as does `HpkeP256.hybridFromSeed`.
- Known-answer tests pass `testRandom`, which CryptoKit can't take: any call with `testRandom` runs
  the own code. The CCTV vectors and the cross-backend tests cover the CryptoKit branch.

Test hook: `HybridKEMBackend.forceOwnCode` (internal, lock-protected with `OSAllocatedUnfairLock` for
Swift 6) and `HybridKEMBackend.withOwnCode { }`. The backend is chosen when a key is built, so a test
builds its identities inside `withOwnCode`. iOS 17 to 25 behavior: the `#available` branches are
false, every path is the 5.0.1 code.

### B. Quantum-safe hardware keys with both halves in the Secure Enclave (iOS 26+)

- Generation (`SecureEnclaveTagPQ.generate(protection:)`, core): P-256 Enclave key as before, plus
  on iOS 26 a `SecureEnclave.MLKEM768` key made with the same `SecureEnclaveKeyProtection` flags
  (`noPrompt`, `userPresence`, E6 `biometryCurrentSet`). No seed is stored. Below iOS 26 (or without
  the Xcode 26 SDK) the 5.0.1 path: random 64-byte seed in the vault.
- Storage, decided: same `StoredIdentityType.secureEnclaveTagPQ`, new layout inside
  `privateKeyMaterial` (`SecureEnclaveTagPQMaterial`, core):
  `"AGPNSE2\0"` (8 bytes) || UInt32 big-endian ML-KEM blob length || ML-KEM Enclave blob || P-256
  Enclave blob. Old layout: 64-byte seed || P-256 blob, unchanged. The new layout is recognised only
  when the magic matches and the length field fits (1 to 65536, with a non-empty P-256 blob after it,
  also at most 65536); anything else decodes as the old layout, which is exactly 5.0.1's rule (more
  than 64 bytes). The public key is stored as today (1249 bytes), so lists, pickers, Bech32, probes
  and encrypt-to are unchanged in both versions.
- Hydration (`StoredIdentity.toAgeIdentity` -> `SecureEnclaveTagPQ.identity`): new layout builds a
  `TagIdentity` whose ML-KEM half is `SecureEnclaveMLKEM` (new, `MLKEMDecapsulation`), with the
  encapsulation key taken from the stored public key (no Enclave call at hydration). Both Enclave
  halves get one `LAContext`: the flow's recent context, or one new context for the pair when there
  is none, so a presence key should prompt once. Below iOS 26 a new-layout key (a restored vault)
  hydrates to an identity whose ML-KEM half throws `SecureEnclaveKeyError.requiresIOS26` and which
  doesn't claim stanzas (see Review fixes, 1).
- Pluggable ML-KEM half (spike S4 design, steps 1 to 3): `public protocol MLKEMDecapsulation`
  (`encapsulationKey`, `decapsulate(ciphertext:)`), `MLKEM768.KeyPair` conforms;
  `HpkeP256.HybridPrivateKey.mlkem` and `TagIdentity.mlkem` take `any MLKEMDecapsulation`; new
  `TagIdentity.hybrid(mlkem:p256PublicKey:p256:)`; `hybrid(mlkemSeed:...)` keeps its signature.
- `TagIdentity.unwrap` fix: a hybrid identity with no ML-KEM half returns nil instead of reaching the
  classic DHKEM and throwing on the enc length. New `TagIdentity.probe(recipient:)` (public data only);
  `StoredIdentity.hardwareProbe()` uses it for both layouts.
- Transfer and paper backup: unchanged. The type is the same, so the existing `KeyPortability`
  exclusions (`isTransferable`, `isPaperBackable`, the private-key checks) cover the new layout.
- Text: generate screen footer says which layout a new key gets; identity page says where the ML-KEM
  half is; Help has "Where does a quantum-safe hardware key live?"; Security has a "Hardware keys"
  section; Licenses' dependency text mentions CryptoKit's ML-KEM and X-Wing on iOS 26. All through
  `String(localized:)` / `LocalizedStringKey`, so Xcode adds them to the String Catalog on build.
  The catalog has no other languages yet, so nothing else to fill in.

## 5.0.1 downgrade finding

5.0.1 = commit `3662737` ("README up to 5.0.1", the last commit before the 5.1.0 work in `0d0f1fc`).
Read with `git show 3662737:AgePony/Vault/...`:

- `Vault.decryptVault` decodes one `VaultSnapshot` (`identities: [StoredIdentity]`, ...) with
  `JSONDecoder`. `StoredIdentity` uses synthesized `Codable`, and `StoredIdentityType` is a plain
  `String` enum, so an unknown raw value throws and the whole vault fails to open. This confirms the
  decision not to add a case. `privateKeyMaterial` is `Data`, so the new layout decodes fine.
- `toAgeIdentity` for `.secureEnclaveTagPQ` (5.0.1): the guard (`count > 64`, public key 1249 bytes)
  passes; it builds `SecureEnclaveKeyAgreement(dataRepresentation: bytes 64...)` (no Enclave call yet)
  and `TagIdentity.hybrid(mlkemSeed: first 64 bytes)`, which accepts any 64 bytes. So hydration
  succeeds (and 5.0.1's `DecryptIdentities` wraps it in `try?` anyway).
- Decrypting with it: the tag only depends on the P-256 point, so the stanza matches; the own ML-KEM
  decapsulation with the wrong key gives an implicit-rejection secret (no throw); then
  `SecureEnclave.P256...PrivateKey(dataRepresentation:)` refuses the blob and throws
  `SecureEnclaveKeyError.invalidKeyData`. `Age.unwrapFileKey` collects hardware errors per identity,
  tries every software key first, and only shows that error ("The stored Secure Enclave key is
  damaged.") when nothing else opens the file.
- `hardwareProbe` (5.0.1) also accepts it, so the file inspector still names the key. Lists, pickers,
  QR, encrypt-to and transfer exclusions read only the public key or the type.
- Known limitation, can't be fixed in 5.0.1: because the new-layout key still "matches" by its
  P-256 tag, 5.0.1's `YubiKeyDecrypt.need` (which skips the tap when `Age.anyOpens` finds a matching
  hardware identity) skips the YubiKey tap. A file encrypted to both that key and a YubiKey then
  fails on 5.0.1 with "The stored Secure Enclave key is damaged." instead of asking for the YubiKey.
  5.1.0 itself doesn't have this problem (see Review fixes, 1).
- Net: a 5.0.1 build opens the vault, shows and encrypts to the new key, and fails per key (with an
  error, no crash) when decrypting with it. The bytes are left as they are, so going back to 5.1.0
  makes the key work again. `EnclaveTagPQTests.test_newLayout_readBy501Hydration_failsForThatKeyOnly`
  replays 5.0.1's hydration on a real Enclave-layout key.

## Per-file changes

Core (`Sources/AgePonyCore`):

- `Crypto/HybridKEMBackend.swift` (new): backend switch and test hook; `XWingDecryptionKey`
  (internal) with the own `HpkeMlkem768X25519.PrivateKey` conforming; `MLKEMDecapsulation` (public)
  with `MLKEM768.KeyPair` conforming; `mlkemKey(seed:)`, `mlkemEncapsulate(encapsulationKey:message:)`.
- `Crypto/CryptoKitPQ.swift` (new, `#if (os(iOS) || os(macOS)) && compiler(>=6.2)`, all
  `@available(iOS 26, macOS 26, *)`): `CryptoKitXWing` (suite, seal), `CryptoKitXWingKey`,
  `CryptoKitMLKEM`, `CryptoKitMLKEMKey`. Writes `AgePonyCore.MLKEM768` / `CryptoKit.MLKEM768`.
- `Crypto/HpkeMlkem768X25519.swift`: seal without `testRandom` goes to `cryptoKitSeal` on 26 (checks,
  then CryptoKit only, errors through `mapSealError`); `publicKeyParts` now internal.
- `Crypto/HpkeP256.swift`: `HybridPrivateKey.mlkem: any MLKEMDecapsulation`; `hybridEncap` uses
  `HybridKEMBackend.mlkemEncapsulate`; `hybridDecap` calls `mlkem.decapsulate(ciphertext:)`.
- `Stanzas/HybridStanza.swift`: `HybridIdentity` holds `any XWingDecryptionKey` from
  `HybridKEMBackend.xwingKey(seed:)`; `unwrap` checks unchanged, plus a 16-byte check after open;
  internal `usesCryptoKit` for tests.
- `Stanzas/TagStanza.swift`: pluggable ML-KEM half, `hybrid(mlkem:...)`, `probe(recipient:)`, unwrap
  returns nil for a hybrid identity without its ML-KEM half.
- `Hardware/SecureEnclaveMLKEM.swift` (new, same compile gate): `SecureEnclaveMLKEM` (generate with
  `SecureEnclaveKeyProtection`, decapsulate with an optional `LAContext`, errors mapped to
  `SecureEnclaveKeyError`, FIPS 203 check on the new key).
- `Hardware/SecureEnclaveTagPQ.swift` (new): `SecureEnclaveTagPQMaterial` (layout codec, every
  platform) and `SecureEnclaveTagPQ` (`mlkemInEnclaveAvailable`, `generate`, `identity`).
- `Hardware/SecureEnclaveKeyAgreement.swift`: `SecureEnclaveKeyError.requiresIOS26`.

App (`AgePony`):

- `Vault/VaultModels.swift`: hydration via `SecureEnclaveTagPQ.identity` (layout errors map to
  `VaultModelError.malformedPrivateMaterial`); `mlkemInSecureEnclave`; `hardwareProbe` from the
  public key; comments on the layouts and the downgrade reasoning.
- `Features/Onboarding/GenerateIdentityView.swift`: quantum-safe kind generates through
  `SecureEnclaveTagPQ.generate(protection:)` (same `seTagProtection`, so the E6 "Require Face ID (no
  passcode)" toggle covers both halves); stores the material as returned; footer text per layout.
- `Features/Identities/IdentityDetailView.swift`: hardware key note says where the ML-KEM half is.
- `Features/Settings/InfoPages.swift`: Help entry, Security "Hardware keys" section, Licenses text.
- `Services/UserMessage.swift`: `requiresIOS26` message.
- No change needed: `StoredRecipient+Hydration.swift`, `KeyPortability.swift`, `DecryptIdentities.swift`,
  `BiometricGate.swift` (the context handling is inside `SecureEnclaveTagPQ.identity`).

## Tests

- `CCTVTestkitTests`, `HybridTests`, `TagRecipientTests`: `final` removed so the new subclasses
  `CCTVTestkitOwnCodeTests`, `HybridOwnCodeTests`, `TagRecipientOwnCodeTests`
  (`CryptoKitBackendTests.swift`) run every test again inside `withOwnCode` (`invokeTest` override).
  On macOS 26 the original classes are the CryptoKit run (all 147 vectors, KATs decrypt through
  CryptoKit, the age-plugin-tagtest recipient pins CryptoKit's ML-KEM derivation). CCTV prints
  `CCTV: post-quantum backend CryptoKit|own code (<class>)`. `TagRecipientTests` now writes
  `AgePonyCore.MLKEM768`.
- `CryptoKitBackendTests` (new): the switch and hook really switch (types checked); age1pq1 and
  age1tagpq1 wrap/unwrap in all four backend pairings from the same seed; stanza checks before
  either backend (extra argument, uppercase type, 25-byte file key, low-order share, short enc);
  bad-modulus and low-order recipients refused with the same error on both backends; CryptoKit
  ML-KEM from a vault seed equals the own code, implicit rejection included; a refused software
  ML-KEM decapsulation gives nil while a hardware error still propagates; the CryptoKit error
  mapping.
- `EnclaveTagPQTests` (new): layout round trips (both), byte layout pinned, the old layout never
  read as new (200 random records, plus magic with a too-long, zero, oversized or all-consuming
  length), malformed inputs; pluggable ML-KEM half round trip and no decapsulation for a foreign
  stanza; probe matches and returns nil. Enclave (skips with the reason printed, `RC3-SE:` lines,
  when Enclave ML-KEM isn't available or key creation fails in the process): spike S4d through the
  real types with no context and with a shared `LAContext`, encrypting with both backends;
  old-layout key with a real Enclave P-256 still decrypts on both backends; the 5.0.1 replay above.
- `AgePonyTests/EnclaveTagPQVaultTests.swift` (new, Swift Testing): `StoredIdentityType` raw values
  pinned (no new case); both layouts probe, stay hardware-only (no transfer, no paper backup), show
  the same recipient; the new layout survives the vault's JSON; too-short material is "damaged".

## Compile-uncertain spots

1. `OSAllocatedUnfairLock.withLock` in `HybridKEMBackend` (Swift 6 package mode, `@Sendable`
   closure). Fallback if it complains: `nonisolated(unsafe) private static var` plus `NSLock`.
2. Condition lists mixing `#available` with other conditions and `let x = try? ...`
   (`HybridKEMBackend`, `SecureEnclaveTagPQ.generate`). I put `#available` first everywhere.
3. Inherited XCTest methods in the `...OwnCodeTests` subclasses and `super.invokeTest()` inside the
   `withOwnCode` closure. If the subclasses show 0 tests, say so and I'll switch to explicit test
   methods.
4. Name lookup of `MLKEM768` in core files that import CryptoKit (`HpkeMlkem768X25519.swift`,
   `HpkeP256.swift`, `TagStanza.swift`) relies on the module's own type winning, as it did in the
   spike build. New files qualify every use.
5. `SecureEnclave.MLKEM768.PrivateKey(accessControl:)` and
   `(dataRepresentation:authenticationContext:)` with an optional context: same calls as the spike.
6. `try XCTUnwrap(try Age.parseHeader(...))` and the `[(String, LAContext?)]` loop in
   `EnclaveTagPQTests`.

Runtime points to watch: whether one unevaluated `LAContext` shared by the two Enclave keys gives
one prompt or two for a `userPresence` key (device list item 3); and whether the downgrade test's
garbage P-256 blob throws (expected `invalidKeyData`).

## Device test list (RC3)

iPhone on iOS 26:

1. Generate identity > Hardware key, quantum-safe. Footer says both halves live in the Secure
   Enclave. Save. Identity page says both halves are in the Secure Enclave. Copy the age1tagpq1
   string.
2. On a Mac: `age -r age1tagpq1... -o test.age file.txt` with age CLI 1.3. Open test.age in AgePony:
   decrypts.
3. Repeat 1 and 2 with "Ask for Face ID each time": decrypt prompts once (not twice) and opens.
   Cancel the prompt once: error shown, nothing else breaks.
4. Vault on Face ID only (E6), with "Require Face ID (no passcode)" on: generate, encrypt with age,
   decrypt with Face ID; the passcode is never offered.
5. Optional, destructive, on a spare key: with a Face ID only key, add an appearance in Settings.
   The key no longer decrypts (both halves gone), as E6 describes.
6. An existing quantum-safe hardware key made with 5.0.1 or RC2 (seed layout): still decrypts a file
   from age 1.3; its page says the ML-KEM half is in the encrypted vault.
7. A file encrypted to an age1pq1 identity (from age 1.3 and from AgePony) decrypts on iOS 26
   (CryptoKit) and on an iOS 17 simulator (own code). Encrypt to an age1pq1 recipient on both; `age
   -d` on the Mac opens both.
8. Send keys to another device and Paper backup: the new hardware key is not offered.
9. Help and Security pages show the new text; Licenses mentions CryptoKit on iOS 26.
10. Optional: install the 5.0.1 TestFlight build over RC3 with a new-layout key in the vault. Vault
    opens, key is listed, decrypting with it says the Secure Enclave key is damaged, other keys
    work. Reinstall RC3: the key decrypts again.

iOS 17 simulator: generating a quantum-safe hardware key isn't possible (no Enclave), but the age1pq1
and tag software paths run the own code; `xcodebuild test` on an iOS 17 simulator, if one is
installed, runs every suite with the own code.

## How to run

```
swift test 2>&1 | grep -E "CCTV: post|RC3|S[1-5]:|Executed|error:|skipped"
xcodebuild test -project AgePony.xcodeproj -scheme AgePony -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Review fixes

From the independent RC3 review (no high-severity crypto issue). Not built yet either.

1. **New-layout key where Enclave ML-KEM can't be used** (below iOS 26, e.g. a restored vault).
   Before, hydration threw, `DecryptIdentities.prepare` dropped it with `try?`, and the user saw "no
   matching key". Now `SecureEnclaveTagPQ.identity` returns `unavailableIdentity(...)`: a
   `TagIdentity` with the stored P-256 blob and an `UnavailableMLKEM(encapsulationKey:)` half (new,
   internal, not availability-gated) whose `decapsulate` throws `SecureEnclaveKeyError.requiresIOS26`.
   `TagIdentity.matches` returns false for such an identity, so `YubiKeyDecrypt.need` still asks for
   a YubiKey addressed by the same file (the 5.0.1 problem in the downgrade section doesn't recur);
   decrypt still tries it and shows the error when nothing else opens the file. `hardwareProbe` is
   unaffected, so the file inspector still names the key. UserMessage now reads "This hardware key
   was made on another device or needs iOS 26 or later, so it can't decrypt here."
2. **`SecureEnclaveMLKEM.decapsulate`** checks, after loading the Enclave key, that its public key
   equals the stored encapsulation key (`invalidKeyData` otherwise). Reading it needs no prompt.
3. **Generation on iOS 26 when the Enclave refuses the ML-KEM key**: `SecureEnclaveTagPQ.generate`
   now falls back to the vault-seed layout with the P-256 Enclave key already made (an internal
   `makeEnclaveMLKEM` hook lets the test force the refusal). This is about where a new key's ML-KEM
   half lives, not about which code runs: the seed-layout key's ML-KEM half still runs in CryptoKit
   on 26. The identity page already reads the stored layout (`mlkemInSecureEnclave`); the generate
   screen footer now reads the material actually made, with its own text for this case ("The Secure
   Enclave couldn't make the ML-KEM-768 half of this key, so ... is kept in the encrypted vault.").
4. **Downgrade note** added above: on 5.0.1 a file to both a new-layout key and a YubiKey fails
   without the YubiKey tap.
5. **Backend asserted per run**: `CCTVTestkitTests`, `HybridTests` and `TagRecipientTests` assert
   in `invokeTest` that `HybridKEMBackend.usesCryptoKit` equals `class var expectsCryptoKit` (true
   on macOS/iOS 26). The OwnCode subclasses override it to false and also assert
   `XCTAssertFalse(HybridKEMBackend.usesCryptoKit)` inside `withOwnCode` before `super.invokeTest()`.
6. **Low-order check order**: `CryptoKitXWingKey.open` turns any failure of AgePony's X25519 check
   into `HybridKEMError.lowOrderPoint` (decrypt still returns nil, so nothing user-visible changes).
   `test_hybrid_lowOrderShare_refusedByAgePonyBeforeCryptoKit` (macOS 26) asserts that error for an
   all-zero and a u = 1 `ct_T`; CryptoKit's own refusal would be a different error, so this proves
   AgePony's check runs first. The misnamed "long file key" case is now the 41-byte body case it is.
7. `test_newLayout_readBy501Hydration_failsForThatKeyOnly` asserts `SecureEnclaveKeyError.invalidKeyData`.
8. `test_enclaveKey_endToEnd` asserts both halves hold the same non-nil `LAContext` (`===`), the
   passed one when given, a shared new one when nil is passed.
9. `test_unavailableEnclaveMLKEM_throwsRequiresIOS26_andDoesNotClaimStanzas` (any OS): the
   `UnavailableMLKEM` identity and the `unavailableIdentity` helper throw `requiresIOS26` from
   unwrap and from `Age.decrypt`, don't claim the stanza, and the public probe still matches.
   `test_generate_enclaveMLKEMRefused_fallsBackToVaultSeedLayout` covers fix 3.
10. `forceOwnCode` is documented as process-global, for XCTest's one-at-a-time runs only, and not
    safe under parallel Swift Testing.

Files touched by these fixes: `Sources/AgePonyCore/Hardware/SecureEnclaveTagPQ.swift`,
`Hardware/SecureEnclaveMLKEM.swift`, `Hardware/SecureEnclaveKeyAgreement.swift` (comment),
`Stanzas/TagStanza.swift`, `Crypto/CryptoKitPQ.swift`, `Crypto/HybridKEMBackend.swift` (comment),
`AgePony/Services/UserMessage.swift`, `AgePony/Features/Onboarding/GenerateIdentityView.swift`, and the
tests `CCTVTestkitTests`, `HybridTests`, `TagRecipientTests`, `CryptoKitBackendTests`, `EnclaveTagPQTests`.

Compile-uncertain additions: `class var` overrides plus `invokeTest` overrides at two levels
(base asserts, subclass wraps); the `EnclaveMLKEMMaker` closure default built inside `#available`;
`identity.mlkem as? SecureEnclaveMLKEM` inside `#if compiler(>=6.2)` / `#available` in the test.
