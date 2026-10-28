# AgePony iOS 5.1.0 RC2b: items 1 and 3

Item 1 (YubiKey: ask for the PIN before the tap) and item 3 (picker rows show key material), from
`AgePony_iOS_5.1.0_Plan.md` and the shared design in the Android repo's `AgePony_5.1.0_Plan.md`.
Decisions applied (Oct 26): an unknown policy asks for the PIN first, with "This key has no PIN" in
the prompt; GET METADATA runs on the import tap.

Nothing was compiled here. Every changed or new Swift file parses clean with tree-sitter-swift.
The first build is the real check:

    swift test
    xcodebuild test -project AgePony.xcodeproj -scheme AgePony -destination 'platform=iOS Simulator,name=iPhone 17'

No git commands beyond status/diff, nothing committed. Not touched (Face ID only lock work in
parallel): `Vault/Vault.swift`, `Vault/KeychainStore.swift`, `Vault/LockMode.swift`,
`Settings/LockSettingsView.swift`, `Home/RootView.swift`, `Onboarding/GenerateIdentityView.swift`,
`Onboarding/OnboardingView.swift`, `Sources/AgePonyCore/Hardware/*`, `Services/BiometricGate.swift`.
`UserMessage.swift` needed no new cases (the existing PIV messages cover it).

## Item 1: YubiKey PIN before the tap

### How it behaves now

| Stored policy | First call | Tap |
| --- | --- | --- |
| `required` | PIN prompt, no tap | one tap: VERIFY, then the ECDHs |
| `unknown` (every 5.0.1 identity) | PIN prompt with "This key has no PIN" | one tap with the PIN; or, after "This key has no PIN", one tap without |
| `notRequired` | no prompt | one tap without the PIN |

- Learned results go back into the vault: a tap without the PIN that worked sets `notRequired`; a
  "PIN required" answer sets `required`, shows the prompt (note: "This YubiKey key needs its
  PIN.", no "no PIN" button) and taps again. That retry is the safety net for a key whose policy
  changed.
- iOS addition, not in the Android design: when the policy is `unknown` and the user gave a PIN,
  the same tap also sends GET METADATA and stores what it says. So a 5.0.1 identity asks with the
  "no PIN" option once, then on firmware 5.3+ knows its policy from then on. Drop the
  `readPINPolicy` argument (pass `false`) if you'd rather keep strict parity.
- Wrong PIN with tries left re-prompts with "Wrong PIN. N tries left before it locks."; blocked PIN
  is unchanged (fails with the PUK message). An empty or 9+ character PIN re-prompts without
  spending a tap.
- The PIN lives only in the flow's `@State` between the prompt and the next `prepare` call, and is
  now cleared as soon as `prepare` returns on every path (before, a cancelled or failed tap left it
  set for the next attempt).

### Files

- `Sources/AgePonyCore/PIV/YubiKeyPINPolicy.swift` (new): `public enum YubiKeyPINPolicy: String`
  (`unknown`, `required`, `notRequired`). `init(identityFileValue:)` (Never / Once / Always, first
  word only), `init(metadataByte:)` (1 never; 0 slot default, 2 once, 3 always, 4/5 Bio match =
  required; anything else unknown). Custom `init(from:)`: an unknown raw string decodes as
  `.unknown`, so a value from a future version can't fail the vault or a transfer record.
- `Sources/AgePonyCore/PIV/Piv.swift`: `Piv.pinPolicy(_:slot:)` sends GET METADATA
  (`00 F7 00 <slot> 00`); `Piv.pinPolicy(metadata:sw:)` parses tag 02 byte 0. Any SW other than
  9000 (6D00 on firmware before 5.3) or a missing/truncated tag gives `.unknown`. Only the
  transport throws.
- `Sources/AgePonyCore/PIV/PivSession.swift`: `readKeyAndPINPolicy(_:stub:)` (readKey plus GET
  METADATA in the same tap; a failed metadata read never fails the key read).
  `parseIdentityFile` now returns `(stub, publicKey, pinPolicy)`, reading `PIN policy:` in the same
  pass as `Recipient:`. The touch policy line is not mistaken for it.
- `AgePony/Vault/VaultModels.swift`: `StoredIdentity.pinPolicy: YubiKeyPINPolicy?` (new last init
  parameter, default nil) and `yubiKeyPINPolicy` (nil reads as `.unknown`). Synthesized Codable, so
  a missing key decodes as nil; `Vault` decodes with a plain `JSONDecoder`, which ignores unknown
  keys, so a 5.0.1 build reading a 5.1.0 vault drops the field. Checked: no custom `CodingKeys`
  or `init(from:)` on `StoredIdentity` or the vault snapshot.
- `AgePony/Vault/Vault+YubiKeyPolicy.swift` (new): `setYubiKeyPINPolicy(_:forIdentity:)`. Vault has
  no in-place update and the extension may only use public API, so it replaces the record:
  `deleteIdentity`, `addIdentity(updated, activate: false)`, `purgeIdentity`, then restores the
  active identity if it moved. Same id, nothing left in the bin. Side effect: the key moves to the
  end of `vault.identities`, so it shows last in pickers that walk the array (Settings, the
  recipient picker). The Identities list sorts each section by `createdAt` and doesn't change.
  Only runs when the policy actually changes, so at most once or twice per key. **Once the lock work has merged,
  please add to `Vault.swift`:**

      public func updateIdentity(_ identity: StoredIdentity) throws {
          guard let idx = identities.firstIndex(where: { $0.id == identity.id }) else { return }
          identities[idx] = identity
          try persist()
      }

  and make the extension body call it.
- `AgePony/Services/YubiKeyDecrypt.swift`: `identity(for:pin:readPINPolicy:)` returns `Tapped`
  (identity plus the policy the tap read). `readKey(stub:)` returns `(key, pinPolicy)`.
- `AgePony/Features/Files/DecryptIdentities.swift`: new `YubiKeyPINEntry` (`.pin(String)`,
  `.noPIN`). `prepare(vault:stanzas:yubiKeyPIN:)` takes it and decides before the tap (table above);
  `Outcome.needsPIN(note:offersNoPIN:)`. All the logic is here, once, for the three callers. The
  prompt modifier is now `yubiKeyPINPrompt(isPresented:note:offersNoPIN:onSubmit:)`, buttons
  Continue / This key has no PIN (only when offered) / Cancel. Message: "Enter the PIV PIN for
  this YubiKey, then hold the key to the top of your iPhone. AgePony keeps the PIN only until this
  decrypt is done." (with the note in front when there is one).
- `DecryptFlow.swift`, `TextDecryptView.swift`, `MigrateFlow.swift`: `yubiKeyPIN` is
  `YubiKeyPINEntry?`, new `yubiKeyOffersNoPIN` state, `prepare`'s result is taken into a `let` and
  the PIN cleared before the `switch`. The share-extension hand-off opens `DecryptFlow` (file) or
  `TextDecryptView` (text) through `HomeView`, so it gets the same behaviour.
- `AgePony/Features/Onboarding/ImportIdentityView.swift`: policy from the file's comment; when the
  import taps (no `Recipient:` line), GET METADATA in that tap wins if the key answers.
- `AgePony/Services/Portability/KeyPortability.swift`: `WireIdentity.pinPolicy: String?`
  (`"required"` / `"notRequired"`, left out when unknown, only for `yubikeyPiv`). Read back through
  `YubiKeyPINPolicy(rawValue:)`; an unknown value reads as unknown. `fresh()` carries the field.
  Older readers ignore it (iOS decodes each record with `JSONDecoder`). **Android needs to write
  the same key and values** when it does item 1 (plan step 6, `docs/TRANSFER_FORMAT_v1.md`).

### Tests

- `Tests/AgePonyCoreTests/YubiKeyPivTests.swift` (XCTest, existing style):
  - `test_identityFile_pinPolicyComment`: Never, Once, Always, no line (with the touch policy line
    present), a bare stub, an unknown value.
  - `test_metadata_pinPolicyBytes`: bytes 0, 1, 2, 3, an unknown byte, SW 6D00, no policy tag, a
    truncated tag.
  - `test_metadata_onTheImportTap`: `readKeyAndPINPolicy` on the existing `FakePivCard` (answers
    6D00, old firmware) and on a new `MetadataPivCard` for bytes 0 to 3; checks the APDU is
    `00 F7 00 82 00` and no PIN was sent.
  - The existing `test_identityFile_parse` still compiles against the three-element tuple
    (it uses the labels).
- `AgePonyTests/KeyPortabilityTests.swift` (Swift Testing): `yubiKeyPINPolicy_travelsInAgeponyJSON`
  (required and notRequired round trip, unknown left out, unknown string ignored, other types never
  carry it) and `yubiKeyPINPolicy_vaultRecordDecoding` (a record without the key decodes as
  unknown, a future value decodes as unknown). Adds `import CryptoKit` for a P-256 test key.

### Device pass (from the plan)

Default (Once) key: PIN dialog first and exactly one tap, also after killing the app. Never key
imported from its identity file: one tap, no dialog. 5.0.1 YubiKey identity: PIN first with "This
key has no PIN". Wrong PIN: tries left. All three callers (file, text, migrate) plus a share
hand-off.

**Decision (Oct 26): ships on the unit tests, no device pass.** No working YubiKey for this
release (the only one has a broken USB-C port, and PIV setup needs USB). The change is limited to
the order of PIN and tap plus the policy read; the decrypt path itself is unchanged. If a real key
misbehaves, the expected failure is an extra tap, not a failed decrypt. Do the device pass above
in 5.2.0 with a replacement key.

## Item 3: picker rows show key material

Rule: name, type in words (`sectionTitle`, the same words the Identities and Recipients list
sections use), and the existing short public string.

- `AgePony/DesignSystem/KeyPickerText.swift` (new): `menuLine(_:)` for identities and recipients,
  `"<name> · <type> · <key>"` through the String Catalog. Menu pickers get one line of text per
  option, so they can't truncate in the middle; the key part is `KeyPortability.keySummary`, the
  short form the transfer preview already uses (public string shortened in the middle, or the
  SHA256 fingerprint for SSH keys, whose public lines all start with the same `ssh-ed25519 AAAA`).
  No new truncation helper.
- Menu pickers now use `KeyPickerText.menuLine`:
  - `Settings/SettingsView.swift`: Active identity, and "Also encrypt to" (a recipient picker with
    the same problem).
  - `Files/EncryptFlow.swift`: "Sign with" (the only identity-name picker in EncryptFlow; the
    plan's "encrypt to self" row).
  - `Sign/SignFileView.swift`: Signing identity.
- List rows add the public string on its own line, `monoCaption`, secondary, one line, truncated
  in the middle, exactly as `IdentityListView` and `RecipientListView` show it:
  - `Files/RecipientPickerView.swift`: identity rows and saved-recipient rows (under the existing
    type line).
  - `Sign/SignersView.swift`, promote from a recipient: the bare `ssh-ed25519`/`ssh-rsa` mono line
    is now the type in words (subheadline) plus the public string line.
- `AgePonyTests/KeyPickerTextTests.swift` (new, Swift Testing): two same-named x25519 identities,
  two same-named SSH Ed25519 identities with the same comment, and two same-named recipients all
  produce different menu lines and public strings. This is a logic test of what the rows render,
  not a snapshot or UI test; a UI test needs a seeded vault in the simulator and is left for when
  the UI test target gets fixtures.

## Compile-uncertain spots

1. `DecryptIdentities.prepare` switches on `YubiKeyPINEntry?` with `.some(.pin(let entered))`,
   `.some(.noPIN)`, `.none`. Should be exhaustive; written out with `.some` to avoid relying on
   optional pattern promotion.
2. `YubiKeyDecrypt.identity`: the `runPiv` closure has an explicit signature
   `(card: PivCard) -> ([Data: Data], YubiKeyPINPolicy)` and runs on the NFC worker thread like the
   existing closure; it only adds a nonisolated core call.
3. `YubiKeyPINPolicy` declares `init(from:)` itself while taking `Encodable` from `RawRepresentable`.
   Standard, but it's the one Codable customization in the change.
4. `KeyPortability.storedIdentity`: `w.pinPolicy.flatMap(YubiKeyPINPolicy.init(rawValue:))` names
   the init by label because the enum now has three one-argument inits.
5. `KeyPortabilityTests`: `var object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])`.
6. `Vault+YubiKeyPolicy.swift` depends on `deleteIdentity`, `addIdentity(_:activate:)`,
   `purgeIdentity`, `activeIdentity()` and the `activeIdentityID` setter keeping their current
   signatures; the parallel lock work didn't change them as of this pass.

## Skipped or left open

- Strings: the String Catalog is empty (extraction at build), so there is nothing to translate
  yet. New strings: "This key has no PIN", the new PIN prompt message (two variants), and the
  picker line format.
- The NFC alert texts passed to `runPiv` (`alert: String`) are plain Swift strings as before, not
  catalog entries. Unchanged here.
- `updateIdentity` on `Vault` (see above), for after the lock work merges.
- Android `pinPolicy` in `agepony.json`: key name and values to match on that side.

## Coordinator change after the pass (Oct 26 2026)

`Vault+YubiKeyPolicy.swift` (delete, re-add, purge) is gone. Once the lock work was done,
`Vault.setYubiKeyPINPolicy(_:forIdentity:)` went into `Vault.swift` next to `renameIdentity`:
it updates the record in place and persists, so the key keeps its position, its id and the
active identity. `DecryptIdentities` calls it unchanged.

Kept: reading GET METADATA on a decrypt tap when the policy is unknown and a PIN was entered,
so a 5.0.1 identity learns its policy after one decrypt. Android item 1 should do the same.
