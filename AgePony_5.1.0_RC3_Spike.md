# AgePony 5.1.0 RC3: E8 CryptoKit spike

Status: tests written Oct 26 2026, not compiled or run yet. Test-only: one new file,
`Tests/AgePonyCoreTests/CryptoKitSpikeTests.swift`. Nothing in `Sources/` or the app changes.
Spike questions S1 to S5 and the scope decision are in `AgePony_5.1.0_Evaluation_Requests.md`, E8.

## How to run

On the Apple-silicon Mac, from the repo root:

```
swift test --filter CryptoKitSpikeTests 2>&1 | grep -E "S[1-5]|Executed|error:|skipped"
```

Needs **macOS 26 (Tahoe) and Xcode 26** (Swift 6.2, macOS 26 SDK). Every test prints one line
starting with its id (`S1a:`, `S2:`, `S4c:` ...), plus `S1a-diff:` lines for the CCTV vectors that
aren't expected to succeed. Paste the grep output back and it becomes the results section below.

What happens elsewhere:

- macOS 14 or 15 with Xcode 26: everything compiles, each CryptoKit test prints
  `Sx: SKIPPED, needs macOS 26 ...` and throws `XCTSkip`. S5 still runs.
- Xcode 16 or older (no macOS 26 SDK): the post-quantum types don't exist at compile time, so the
  file compiles to a single `testS0_NeedsXcode26` that skips with that reason. The gate is
  `#if compiler(>=6.2)`, a proxy for "Xcode 26". The rest of the test target is unaffected.
- `swift test` with no filter runs the spike next to the normal suite. It should stay green
  everywhere; the only assertions are the byte-compatibility ones listed under each test.

## API names used, and how sure they are

Checked against Apple's documentation pages (developer.apple.com, CryptoKit) and, for
`HPKE.Sender`, against swift-crypto's `HPKE.swift`, which mirrors CryptoKit's API.

| API | Signature as documented | Confidence |
| --- | --- | --- |
| `HPKE.Ciphersuite(kem:kdf:aead:)` | `init(kem: HPKE.KEM, kdf: HPKE.KDF, aead: HPKE.AEAD)` (iOS 17+) | Confirmed |
| `HPKE.KEM.XWingMLKEM768X25519` | enum case, 26+ | Confirmed |
| `HPKE.KDF.HKDF_SHA256`, `HPKE.AEAD.chaChaPoly` | enum cases | Confirmed |
| `HPKE.Recipient(privateKey:ciphersuite:info:encapsulatedKey:)` | `init<SK: HPKEKEMPrivateKey>` overload, 26+; `mutating func open(_:authenticating:)` | Confirmed (docs + swift-crypto) |
| `HPKE.Sender(recipientKey:ciphersuite:info:)` | `init<PK: HPKEKEMPublicKey>` overload; `encapsulatedKey`; `mutating func seal(_:authenticating:)` | From swift-crypto; Apple's Sender page didn't render its member list |
| `XWingMLKEM768X25519.PrivateKey(seedRepresentation:publicKey:)` | `init<D: DataProtocol>(seedRepresentation: D, publicKey: XWingMLKEM768X25519.PublicKey?) throws` | Confirmed. `publicKey:` has no default, so the tests pass `nil` |
| `XWingMLKEM768X25519.PrivateKey.generate()`, `.publicKey`, `.decapsulate(_:)` | from `KEMPrivateKey` (`static func generate() throws -> Self`, `var publicKey`, `func decapsulate(Data) throws -> SymmetricKey`) | Protocol requirements; X-Wing's own page leaves those sections empty |
| `XWingMLKEM768X25519.PrivateKey.seedRepresentation` | `var seedRepresentation: Data` | Confirmed. Size assumed 32 (X-Wing draft); S2 asserts it |
| `XWingMLKEM768X25519.PublicKey(rawRepresentation:)`, `.rawRepresentation` | `init<D>(rawRepresentation: D) throws` | Confirmed |
| `MLKEM768.PrivateKey(seedRepresentation:publicKey:)` | `init<D: DataProtocol>(seedRepresentation: D, publicKey: MLKEM768.PublicKey?) throws`; seed is `d \|\| z` (FIPS 203 Alg. 16); throws if `publicKey` doesn't match | Confirmed |
| `MLKEM768.PrivateKey.decapsulate(_:)`, `.seedRepresentation`, `.publicKey` | `func decapsulate<D>(D) throws -> SymmetricKey` | Confirmed |
| `MLKEM768.PublicKey(rawRepresentation:)`, `.encapsulate()` | `encapsulate() throws -> KEM.EncapsulationResult` (`sharedSecret: SymmetricKey`, `encapsulated: Data`) | Confirmed |
| `SecureEnclave.MLKEM768.PrivateKey` | `generate()`, `init(accessControl:)`, `init(accessControl:authenticationContext:)`, `init(dataRepresentation:)`, `init(dataRepresentation:authenticationContext:)`, `dataRepresentation`, `publicKey: MLKEM768.PublicKey`, `decapsulate(_:)` | Confirmed |

Name clash: AgePonyCore's own `enum MLKEM768` and CryptoKit 26's `MLKEM768` have the same name.
Inside AgePonyCore the module's own type wins, so `Sources/` is unaffected. `TagRecipientTests`
already uses `MLKEM768` unqualified next to `import CryptoKit`; Swift's shadowing rule (a module
that imports CryptoKit shadows it) should keep that resolving to AgePony's on the 26 SDK, but if
it doesn't, that file needs `AgePonyCore.` added. The spike writes `AgePonyCore.MLKEM768` and
`CryptoKit.MLKEM768` every time. Any 5.1.0 code
in `Sources/` that touches CryptoKit's type has to write `CryptoKit.MLKEM768` (and
`SecureEnclave.MLKEM768`, which is unambiguous).

## What each test checks

### S1. X-Wing HPKE (`mlkem768x25519`)

The suite is built by hand, because CryptoKit's built-in post-quantum suite
(`XWingMLKEM768X25519_SHA256_AES_GCM_256`) uses AES-GCM and age uses ChaCha20Poly1305:
`HPKE.Ciphersuite(kem: .XWingMLKEM768X25519, kdf: .HKDF_SHA256, aead: .chaChaPoly)`, info
`age-encryption.org/mlkem768x25519`, empty AAD, one `seal`/`open` per context (sequence 0, so
the nonce is base_nonce, as in age). Helper: `CKXWing` at the bottom of the file.

- **S1a, CCTV vectors.** Every Testkit vector with `hybrid` in its name (18 `hybrid*` plus
  `armor_hybrid`, 19 in all). Inflates zlib and strips armor with the existing helpers
  (`CCTVTestkitTests.inflateZlib`, `AgeArmor.decode`), reads the header stanzas leniently, builds
  the CryptoKit key from the identity's seed (S2) and opens every `mlkem768x25519` stanza.
  - Success vectors (`hybrid`, `hybrid_and_x25519`, `hybrid_grease`, `hybrid_multiple_recipients`,
    `armor_hybrid`): asserts every stanza CryptoKit opens gives exactly the vector's `file key`.
    Line: `S1a: 5/5 success vectors open to the CCTV file key ...`.
  - The other 14: recorded only, as `S1a-diff: <name> [expect ...] CryptoKit: ... | AgePony: ...`.
    The AgePony side shows `HybridIdentity.unwrap` on the same lenient stanza, then the whole file
    through `CCTVTestkitTests.run` (the real decrypt path).
- **S1b, CryptoKit seals, AgePony opens.** 8 rounds: a fresh `HybridIdentity`, its public key
  into `XWingMLKEM768X25519.PublicKey`, `HPKE.Sender` seals a random 16-byte file key. Asserts
  enc is 1120 bytes and the body 32, then that `HybridIdentity.unwrap` returns the file key and that
  a full age file (`AgeHeader.serialize` with CryptoKit's stanza, `AgePayload.encrypt`) opens with
  `Age.decrypt`.
- **S1c, AgePony seals, CryptoKit opens.** 8 rounds: `XWingMLKEM768X25519.PrivateKey.generate()`,
  public key to an `age1pq1` string and back through `HybridRecipient(ageRecipient:)`, then (a)
  `HybridRecipient.wrap` with a known file key, CryptoKit opens the stanza; (b) `Age.encrypt`,
  CryptoKit unwraps the file key from the parsed header, AgePony checks the header MAC with it and
  decrypts the payload.
- **S1d, KEM level.** AgePony's `HpkeMlkem768X25519.encap` against CryptoKit's X-Wing
  `decapsulate`: same 32-byte shared secret. Narrows any S1 failure to the KEM or to the HPKE layer.
- **S1e, encrypt-side input checks (recorded only).** AgePony refuses to encrypt to an ML-KEM key
  that fails the FIPS 203 modulus check (audit L-12) and to an `age1pq1` key whose X25519 half is
  low order. The test hands both to CryptoKit (`MLKEM768.PublicKey(rawRepresentation:)` +
  `encapsulate()`, and X-Wing `PublicKey` + `HPKE.Sender`) and prints whether CryptoKit refuses
  them, next to AgePony's own refusal.

### S2. X-Wing seeds

`XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)` for the two distinct
`AGE-SECRET-KEY-PQ-1` seeds in the CCTV vectors, the fixed `00..1f` seed HybridTests pins, and 8
fresh `HybridIdentity` seeds. Asserts the CryptoKit public key equals AgePony's 1216-byte
`age1pq1` key, `seedRepresentation` returns the same 32 bytes, and the `publicKey:` consistency
form accepts AgePony's key. Reverse: 8 CryptoKit-generated keys, `seedRepresentation` into
`HybridIdentity(seed:)`, same public key, and the `AGE-SECRET-KEY-PQ-1` string round-trips. Also
prints whether a mismatched `publicKey:` is refused.

### S3. ML-KEM-768 from the 64-byte vault seed

Seeds: 6 random 64-byte seeds (how `GenerateIdentityView` makes them for `secureEnclaveTagPQ`),
the age-plugin-tagtest key's ML-KEM seed and 2 more via `HpkeP256.hybridExpandSeed` (how
`TagIdentity.softwareHybrid` makes them). For each: CryptoKit's encapsulation key equals
`AgePonyCore.MLKEM768.keyPairFromSeed`'s, `seedRepresentation` round-trips, AgePony encapsulates
and CryptoKit decapsulates, CryptoKit encapsulates and AgePony decapsulates, and a corrupted
ciphertext gives the same implicit-rejection secret (`J(z || c)`) on both sides.

**S3b, the tag combiner.** Answers "can the combiner take an externally computed ML-KEM secret":
yes, as the code stands. `HpkeP256.hybridCombine(ssPQ:ssT:ctT:ekT:)` is a plain function of
bytes; only `TagIdentity` and `HpkeP256.HybridPrivateKey` tie the ML-KEM half to a software
`MLKEM768.KeyPair`. The test wraps with the stock `TagRecipient`, then unwraps with
`SpikeKit.unwrapTagPQ`, which does what `TagIdentity.unwrap` does (tag check first, then both
halves, combine, `HpkeP256.open`) with the ML-KEM decapsulation passed in as a closure; here
CryptoKit's `MLKEM768.PrivateKey.decapsulate`. Asserts it and the stock `TagIdentity.unwrap` both
return the file key.

### S4. Secure Enclave ML-KEM-768

Skips with the reason printed if `SecureEnclave.isAvailable` is false, or if
`SecureEnclave.MLKEM768.PrivateKey.generate()` throws in the `swift test` process (the error is
printed).

- **S4a** default access control (`generate()`), **S4b** `[.privateKeyUsage]` only, exactly the
  `SecAccessControl` `SecureEnclaveKeyAgreement` builds for `.noPrompt`, created and reloaded
  with an `LAContext`. No biometry, since `swift test` can't answer a prompt. Each one: the
  public key is 1184 bytes and passes AgePony's FIPS 203 check; AgePony's `MLKEM768.encapsulate`
  and CryptoKit's `encapsulate()` both give the secret the Enclave decapsulates;
  `dataRepresentation` reloads into a new key object with the same public key, and it
  decapsulates the first ciphertext to the same secret. Prints the blob size.
- **S4c** creates (does not use) an Enclave ML-KEM key with each `SecureEnclaveKeyProtection`
  case's flags (`noPrompt`, `userPresence`, `biometryCurrentSet`) and prints which ones the Enclave
  accepts. Recorded only. On a Mac with no Touch ID enrolled, `biometryCurrentSet` may be refused at
  creation; that says nothing about an iPhone with Face ID.
- **S4d** end to end, no Sources change: an `age1tagpq1` recipient made of the S4b Enclave ML-KEM
  key and a new P-256 Enclave key (`SecureEnclaveKeyAgreement.generate(protection: .noPrompt)`),
  round-tripped through its Bech32 string (which runs the modulus check), `Age.encrypt` to it, then
  `Age.decrypt` with `EnclaveTagPQIdentitySketch`, a test-local `AgeIdentity` holding the two
  Enclave blobs and no seed. Asserts the plaintext comes back.

### S5. AgePony's own path

`CCTVTestkitTests.testCCTVVectors` already runs all 147 vectors, the hybrid ones included,
through AgePony's own code, and it is the authoritative check. `testS5_AgePonyOwnPathOnSameVectors`
runs the same 19 vectors through `CCTVTestkitTests.run` and prints one comparable line (category
only, `no match` accepted for `header failure` as in the runner). It needs no macOS 26 and runs
everywhere.

## Predicted outcomes

| Test | Prediction | Main uncertainty |
| --- | --- | --- |
| S1a success vectors | 5/5 match | CryptoKit accepting a custom suite with X-Wing and ChaChaPoly (the init is generic, so it should) |
| S1b, S1c, S1d | 8/8 each | None beyond S1a; X-Wing (KEM 0x647A) is the same construction as age's MLKEM768-X25519 |
| S1e | Unknown, recorded | Whether CryptoKit runs the FIPS 203 modulus check on import and rejects a low-order X25519 half |
| S2 | All match, seeds 32 bytes | `seedRepresentation` size and format (X-Wing draft: 32-byte seed, SHAKE256 expanded) |
| S3, S3b | All match | None; `d \|\| z` is documented and FIPS 203 is deterministic |
| S4 | Likely passes on Apple silicon | Whether the Mac's Enclave supports ML-KEM, and whether key creation works in an unsigned CLI test process. A skip here is not a fail: the iPhone device pass decides |

Expected `S1a-diff` behaviour, which is the useful part of S1a:

| Vector | CryptoKit (predicted) | AgePony | What it means |
| --- | --- | --- | --- |
| `hybrid_bad_tag`, `hybrid_currupted_enc_*`, `hybrid_no_match` | throws (AEAD auth failure) | unwrap nil, file `no match` | Same |
| `hybrid_long_share`, `hybrid_short_share` | throws (enc not 1120 bytes) | unwrap nil | Same |
| `hybrid_extra_argument` | opens (it only sees enc) | unwrap nil, file header failure | Argument count stays AgePony's check |
| `hybrid_uppercase` | opens (stanza type isn't its business) | unwrap nil, `no match` | Type match stays AgePony's |
| `hybrid_long_file_key` | opens to 25 bytes | unwrap nil (body not 32), header failure | Body size and 16-byte file key stay AgePony's |
| `hybrid_not_canonical_body`, `hybrid_not_canonical_enc` | opens (bytes are fine) | strict parser refuses, header failure | Canonical base64 stays in the stanza parser (it already is) |
| `hybrid_low_order`, `hybrid_identity` | **unknown**: throws, or opens to the file key | unwrap nil, header failure via alias | If CryptoKit opens these, the CryptoKit path needs its own low-order check first (below) |
| `hybrid_x25519_arg` | n/a, no `mlkem768x25519` stanza | header failure | Nothing to compare |

The general result expected: CryptoKit can replace the KEM and HPKE core inside
`HybridIdentity.unwrap` and `HybridRecipient.wrap`, and every stanza-level check AgePony has
today stays where it is.

## S4 design: an Enclave-only `age1tagpq1` key (write-up, not implemented)

**Can it use the current combiner?** Yes. `HpkeP256.hybridCombine` takes four byte strings and
doesn't care where `ssPQ` came from (S3b and S4d show it with no Sources change). What stops the
stock `TagIdentity` from using an Enclave ML-KEM key is the type of its ML-KEM half:
`TagIdentity.mlkem: MLKEM768.KeyPair?` and `HpkeP256.HybridPrivateKey.mlkem: MLKEM768.KeyPair`,
whose `decapsulationKey` is the raw 2400-byte key an Enclave never hands out. Also, in
`TagIdentity.unwrap` a hybrid recipient with `mlkem == nil` falls through to the classic
`dhkemDecap` and throws on the enc length, rather than returning nil.

**Minimal Sources change** (mirrors how `P256KeyAgreement` already makes the P-256 half
pluggable):

1. `Crypto/HpkeP256.swift`: add
   `public protocol MLKEMDecapsulation { var encapsulationKey: Data { get }; func decapsulate(ciphertext: Data) throws -> Data }`
   and make `MLKEM768.KeyPair` conform (its `decapsulate` calls
   `MLKEM768.decapsulate(decapsulationKey:ciphertext:)`).
2. `HpkeP256.HybridPrivateKey.mlkem` becomes `any MLKEMDecapsulation`. Same init labels, so
   every caller that passes a `KeyPair` compiles unchanged. `hybridDecap` calls
   `privateKey.mlkem.decapsulate(ciphertext: ctPQ)`.
3. `TagIdentity.mlkem` becomes `(any MLKEMDecapsulation)?`. New
   `public static func hybrid(mlkem: any MLKEMDecapsulation, p256PublicKey: Data, p256: P256KeyAgreement)`;
   the existing `hybrid(mlkemSeed:...)` builds the `KeyPair` and calls it. In `unwrap`, a hybrid
   recipient with no ML-KEM half returns nil instead of reaching `dhkemDecap`. Add a public-only
   constructor for `hardwareProbe()` (it only needs `matches`, which reads the recipient).
4. New `Hardware/SecureEnclaveMLKEM.swift`, `@available(iOS 26, macOS 26, *)`:
   `public struct SecureEnclaveMLKEM: MLKEMDecapsulation` holding `dataRepresentation` and an
   optional `LAContext`, with `generate(protection: SecureEnclaveKeyProtection)` returning
   `(dataRepresentation, encapsulationKey)`. `decapsulate` rebuilds
   `SecureEnclave.MLKEM768.PrivateKey(dataRepresentation:authenticationContext:)` and maps errors
   to `SecureEnclaveKeyError`, like `SecureEnclaveKeyAgreement`.

The software CryptoKit path (S1 to S3) only needs a second conformer, a CryptoKit
`MLKEM768.PrivateKey` built from the 64-byte seed, which falls out of the same protocol.

**App and vault** (from `VaultModels.swift` and `GenerateIdentityView.swift`):

- New `StoredIdentityType` case next to `secureEnclaveTagPQ` (name to pick; declaration order is
  display order). `publicKeyMaterial`: the same 1249-byte hybrid key (ML-KEM ek || 65-byte P-256
  point), so the recipient string, `hardwareProbe` and tag matching don't change.
- `privateKeyMaterial`: two Enclave handles and no seed. The ML-KEM blob size isn't documented
  (S4 prints it), so store a 2-byte big-endian length of the ML-KEM `dataRepresentation`, the
  ML-KEM blob, then the P-256 blob. Not secret in the way the old seed was: both blobs are useless
  outside this device's Enclave.
- `toAgeIdentity(authenticationContext:)` builds both `SecureEnclaveMLKEM` and
  `SecureEnclaveKeyAgreement` with the **same** `LAContext`, so a key that wants presence prompts
  once for the pair. Below iOS 26 it throws a clear error (such a key can only be made on 26, but
  the vault could be restored onto an older device).
- Generation: `SecureEnclaveKeyAgreement.generate(protection:)` and
  `SecureEnclaveMLKEM.generate(protection:)` with the same `SecureEnclaveKeyProtection`, so both
  halves get the same flags: `noPrompt` `[.privateKeyUsage]`, `userPresence`
  `[.privateKeyUsage, .userPresence]`, or E6's Face ID only `[.privateKeyUsage, .biometryCurrentSet]`.
  E6's Q3 answer then covers both halves: with `biometryCurrentSet`, a Face ID reset destroys
  both, the same recovery story as today (today the seed survives but is useless without the P-256
  half). S4c shows whether the Enclave accepts each flag set for ML-KEM keys; the device pass
  confirms prompting.
- Transfer and paper backup: add the case to the `KeyPortability` switches that already exclude
  `secureEnclaveTagPQ`. Identities badge, Help and Security text as in E8's implementation list.
  The generate option shows only on iOS 26 and later.
- Check before shipping: `StoredIdentityType` is a plain `Codable` enum, so a build that doesn't
  know the new case may fail to decode the whole vault. The App Store doesn't downgrade, but a
  TestFlight build going back to 5.0.1 or a restore onto an older app version could. Confirm how
  the vault decodes an unknown type (and how `secureEnclaveTagPQ` was introduced in 5.0.1) before
  adding the case.

## Decision table

| Result | 5.1.0 action |
| --- | --- |
| S1 to S3 pass (S1a 5/5, S1b to S1d 8/8, S2 and S3 all equal) | The CryptoKit path ships in 5.1.0 on iOS 26 / macOS 26 for `mlkem768x25519` and for the ML-KEM half of `mlkem768p256tag`. Shape below. |
| S1e or `S1a-diff` show CryptoKit opens `hybrid_low_order` / `hybrid_identity`, or accepts bad-modulus or low-order keys on encrypt | Still ships, with AgePony's checks kept in front of CryptoKit (below). Written down here. |
| Any S1 to S3 byte mismatch | That primitive moves to 5.2.0 with the mismatch recorded in E8. Nothing ships with a vector that differs. |
| S4 passes on the Mac (S4a, S4b, S4d) | Enclave ML-KEM `age1tagpq1` keys ship in 5.1.0 per the design above, subject to the iPhone device pass. |
| S4 skips on the Mac (no Enclave ML-KEM, or key creation fails in a CLI process) | Not a fail. Decide on the iPhone: a small debug-build check in the app, or the RC device pass. |
| S4 fails on the iPhone, or S4c shows the Enclave refuses the P-256 key's flags for ML-KEM | Enclave ML-KEM keys move to 5.2.0 with the reason recorded. The CryptoKit software path can still ship. |

**Implementation shape if S1 to S3 pass** (its own RC, one at a time):

- `HpkeMlkem768X25519.seal` / `open`: an `if #available(iOS 26, macOS 26, *)` branch using the
  hand-built CryptoKit suite, behind the same types, so the app doesn't change. Everything around
  it stays AgePony's: stanza type, one argument, canonical base64, enc 1120 bytes, body 32 bytes,
  16-byte file key, the `postquantum` label rule. On encrypt, AgePony's FIPS 203 modulus check and
  low-order refusal run before CryptoKit unless S1e shows CryptoKit refuses both itself. On
  decrypt, if S1a shows CryptoKit opens the low-order vectors, the identity first runs its X25519
  scalar against `ct_T` with `Curve25519.KeyAgreement` and returns nil on an all-zero result.
  (Corrected in 5.1.1: `Curve25519.KeyAgreement` does not throw on a low-order point; it returns
  an all-zero secret, so the check has to be explicit. See the 5.1.1 plan, item 2.)
- ML-KEM half of `mlkem768p256tag`: through the `MLKEMDecapsulation` protocol above, a CryptoKit
  `MLKEM768.PrivateKey` from the vault seed on 26, `MLKEM768.KeyPair` on 17 to 25. Encrypting to
  `age1tagpq1` recipients can use `CryptoKit.MLKEM768.PublicKey.encapsulate()` after AgePony's
  modulus check. The MLKEM768-P256 combiner and HPKE key schedule stay AgePony's, since CryptoKit
  has no MLKEM768-P256 KEM.
- Known-answer tests: CryptoKit can't take fixed encapsulation randomness, so `HybridTests` and
  `TagRecipientTests` KATs keep pinning the own code; the CryptoKit branch is covered by the CCTV
  vectors and by this spike's interop tests, which become permanent tests.
- Both branches on one Mac: on macOS 26, `swift test` would otherwise only reach the CryptoKit
  branch. An internal test hook that forces the own-code branch (internal like the `testRandom`
  hooks, and concurrency-safe under Swift 6) lets `CCTVTestkitTests` run all 147 vectors twice.
  The device pass covers the iOS 17 simulator.
- Android: no change in 5.1.0, as E8 says.

## Results

Not run yet. Paste the grep output here, then fill the decision table's outcome into E8.

## Results (run Oct 26 2026, macOS 26.6.2 build 25G83, Apple silicon)

All 10 spike tests passed.

- S1a: 5/5 success vectors open to the CCTV file key with CryptoKit X-Wing HPKE (HKDF-SHA256,
  ChaChaPoly). Of the 14 non-success vectors, CryptoKit opens 5 that age requires rejecting
  (hybrid_extra_argument, hybrid_long_file_key, hybrid_not_canonical_body,
  hybrid_not_canonical_enc, hybrid_uppercase): stanza grammar, argument count, canonical
  base64 and the 16-byte file key must stay checked by AgePony before CryptoKit opens.
  CryptoKit refuses hybrid_identity, hybrid_low_order, hybrid_long_share and
  hybrid_short_share itself (underlyingCoreCryptoError -7).
- S1b: 8/8 CryptoKit-sealed stanzas open in AgePony. S1c: 8/8 stanzas and 8/8 files from
  AgePony open in CryptoKit. S1d: 8/8 X-Wing shared secrets equal.
- S1e: CryptoKit accepts bad-modulus and low-order public keys at construction and refuses
  them at encapsulation (-7); AgePony refuses them earlier. Keep AgePony's checks.
- S2: 11/11 AGE-SECRET-KEY-PQ-1 seeds give the same age1pq1 key in CryptoKit; 8/8 CryptoKit
  seeds round-trip into HybridIdentity; a mismatched publicKey is refused.
- S3: 9/9 64-byte seeds give the same ML-KEM-768 key; shared secrets equal both ways;
  implicit rejection equal. S3b: 6/6 mlkem768p256tag stanzas open with the ML-KEM half from
  CryptoKit fed to HpkeP256.hybridCombine, no Sources change.
- S4: ML-KEM-768 in the Mac's Secure Enclave works with default access control and with
  [.privateKeyUsage]; dataRepresentation reloads; creation works with the noPrompt,
  userPresence and biometryCurrentSet flag sets; an age1tagpq1 file with both halves in the
  Enclave opens. Blob sizes: ML-KEM 1489 bytes, P-256 324 bytes.

Decision (per the Oct 26 scope: spike, then implement both in 5.1.0): both parts ship in 5.1.0.
The iPhone device pass confirms S4 on iOS 26 hardware.
