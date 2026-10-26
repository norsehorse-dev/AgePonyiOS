# AgePony iOS — planned features

Things that are going in, but are not in yet. Separate from
`AgePony_iOS_Parity_Plan.md`, which tracks one specific effort (catching iOS up to
Android 3.1.0) and ends when that effort does. This file outlives releases.

Each entry says where it came from, what is actually wrong, and what "done" means.
An item with no acceptance criteria is a wish, not a plan.

Last updated: 2026-08-06.

---

## 1. Identity and recipient rows must carry more than the name

**Source:** user report by email, 2026-08-01. Answered the same day promising it in a
future release.
**Applies to:** iOS, Android, and PGPony on both. See the cross-app note at the end.
**Status:** planned, not started.

### The complaint, restated

> When selecting or listing identities, show something more identifiable than the
> name. If two have the same name it is impossible to tell them apart.

This is a correctness complaint dressed as a UI one. Picking the wrong identity is
not a cosmetic mistake: on the encrypt side it means a file that the person you meant
cannot open, and on the signing side it means a signature that attests to the wrong
key. Both fail silently and neither is obvious afterwards.

### Where iOS already gets this right

`Features/Identities/IdentityListView.swift` is the model to copy. A row carries a
per-type SF Symbol, the name, a post-quantum badge, an ACTIVE capsule, and
`identity.publicDisplayString()` truncated in the middle, and the whole list is
sectioned by `StoredIdentityType`. Two identities called "Personal" are already
distinguishable there.

`Features/Identities/RecipientListView.swift` is the same shape, with `shortPublic`
and a source capsule, and `Features/Sign/SignersView.swift:255` prints
`keyType · fingerprint` outright.

So the helper already exists on both models. The gap is that the **selection**
surfaces do not use it. That is the wrong way round: the list is where you browse and
can afford to tap through, and the picker is where the irreversible choice is made.

### Where it is missing

| Surface | File | What a row shows today |
| --- | --- | --- |
| Active identity | `Features/Settings/SettingsView.swift:134` | `Text(id.name)` |
| Encrypt-to-self | `Features/Files/EncryptFlow.swift:325` | `Text(identity.name)` |
| Signing key | `Features/Sign/SignFileView.swift:201` | `Text(id.name)` |
| Recipient picker, identities | `Features/Files/RecipientPickerView.swift:259` | name + type label |
| Recipient picker, saved | `Features/Files/RecipientPickerView.swift:280` | name + type label |
| Promote to signer | `Features/Sign/SignersView.swift:170` | name + `ssh-ed25519` / `ssh-rsa` |

The three `Picker` rows are the worst of them. A `.menu` picker collapses each option
to a single line of text, so two identities with the same name render as two visually
identical rows with no way to tell which is which short of cancelling out, renaming
one, and coming back. The signing picker is the one to fix first.

The two `RecipientPickerView` rows are better but not sufficient: same name plus same
type still collides, and that is not a contrived case. Two `x25519` keys both called
"Work", one rotated, is the ordinary way this happens.

### What a row should show

Name, then type, then enough key material to disambiguate. Concretely:

- Reuse `publicDisplayString()` and `shortPublic` rather than inventing a third
  abbreviation. Three different truncations of the same key across one app is its own
  small confusion.
- In `Picker` rows, where there is only one line, compose it: `Work · x25519 ·
  age1q9f…7k3m`. A `Text` with mixed `.font` runs is fine inside a picker label.
- Keep the type as words, not only as an icon or a coloured badge. An icon is a
  reminder for someone who already knows the mapping and no help at all to someone who
  does not.
- Do not fall back to the creation date as the distinguishing field. It disambiguates
  only for the person who remembers which one they made first, which is exactly the
  person who did not need help.

### Acceptance

- Two identities with the same name and the same type are distinguishable in every
  surface in the table above, without leaving that surface.
- A snapshot or UI test that creates two same-named, same-type identities and asserts
  the rendered rows differ. Without that test this regresses the next time a picker is
  touched.
- No new truncation helper: the existing two are used everywhere.

---

## Cross-app note

The same request applies beyond iOS, and the four apps are in different places:

| App | State |
| --- | --- |
| **AgePony iOS** | Lists good, pickers bare. This document. |
| **AgePony Android** | Not yet surveyed. Check `RecipientPicker.kt` and the settings picker. |
| **AgePony Desktop** | Largely fine. `panels/identities.rs` shows kind, badges, created date and the full recipient. The gap is `panels/encrypt.rs:80`, where a book row is name + "Yours" + a bare `◆` + note, with no key material and no text on the post-quantum marker. |
| **PGPony** | Reported as having the same problem. Not yet surveyed. |

One thing worth carrying across before changing anything: on Desktop this cannot
currently produce a wrong-recipient encryption, because `Store::add` and
`Book::add` both reject duplicate names outright and `unique_among` suffixes
generated ones. That is what makes it safe for `EncryptState::picked` to key on names
rather than IDs. If duplicate names are ever allowed on Desktop to match the phones,
that keying has to change first, or a display fix will have quietly introduced a real
bug.

---

## 2. Decoy / duress password to wipe the vault

**Source:** feature suggestion from a user, Aug 2026 (`ageponyfeaturesuggestions.md`).
**Applies to:** iOS and Android directly. Desktop is a different shape of problem — see
`AgePonyDesktop/PLANNED_FEATURES.md`.
**Status:** planned, not started.

### The request, restated

> A secondary "decoy" password that, when entered, deletes the database instead of
> unlocking it — a duress-style wipe.

### Why this is a bigger change than "add a decoy password"

Today AgePony's vault has no app-owned password at all. `Vault.unlock(prompt:)`
(`Vault/Vault.swift:135`) goes straight to `BiometricGate.authenticate`, which evaluates
`.deviceOwnerAuthentication` — Face ID / Touch ID with the *device's* passcode as the
OS-level fallback (`Services/BiometricGate.swift:49`). AgePony itself never sees or
checks a password; the Keychain ACL is the actual gate. There is nowhere in the app
today for a user to type a decoy password, because there's nowhere for them to type the
real one either.

So this ships in two parts, not one: an app-owned password/PIN unlock path offered
alongside biometric (something for the decoy to sit next to), and then the decoy check
and wipe on top of it.

### What "wipe" means here

`Vault.swift` already has the primitives: `deleteIdentity`, `deleteRecipient`,
`deleteNote`, `deleteSigner` (lines 177–267) and `KeychainStore.deleteMasterKey()`. A
duress wipe is those, run for everything, triggered by the decoy password instead of by
hand.

### Duress-specific requirements, not just "delete the data"

- **No tell.** What the app shows after a decoy-password wipe must be indistinguishable
  from what it shows after a wrong real password, or from a fresh install. No "Vault
  wiped" toast, no confirmation dialog — a hostile observer watching over the victim's
  shoulder should learn nothing.
- **Constant-time comparison** between the entered password and both the real and decoy
  secrets, so response latency doesn't leak which branch ran.
- **Decide what "unlocked" looks like afterward**, before building it. Dropping into an
  empty, freshly-onboarded vault looks legitimate, but a second attempt with *any*
  password now trivially "succeeds" since nothing is left to check against. Showing a
  generic "wrong password" state and never opening is safer but can't be used to make
  someone look like they complied. Pick one on purpose.

### Acceptance

- A vault with identities, recipients and signers, given the decoy password, ends with
  zero of each and no master key in the Keychain.
- The screen shown after the decoy password is state-identical to the one shown after a
  wrong real password.
- Nothing except the exact decoy password triggers the wipe — not a prefix, not a
  mistyped real password.
- A timing test shows entering the decoy password and entering a wrong password take
  statistically the same time.

---

## 3. Clipboard auto-clear after copying — mostly already true here

**Source:** feature suggestion from a user, Aug 2026.
**Applies to:** iOS (audit item), Android (missing — see `AgePonyAndroid/PLANNED_FEATURES.md`),
Desktop (missing, lower stakes — see `AgePonyDesktop/PLANNED_FEATURES.md`).
**Status:** iOS — believed done already, needs an explicit audit and a regression test.

### The request, restated

> Automatically clear the clipboard after an encrypt operation copies to it.

### Where iOS already does this

`AgePonyKeyBlock.swift` copies via `UIPasteboard.general.setItems(...)` with a
60-second `pasteboardExpiry` (lines 88–91), and both text-mode copy paths —
`TextEncryptView.swift:253` and `TextDecryptView.swift:267` — use the same
expiring-item pattern rather than the plain `UIPasteboard.general.string =` setter.
Nothing in `AgePony/AgePony` uses that plain setter today.

### What's actually left

- This is a "prove it" item, not a "build it" item: add a test that copies via each of
  the three call sites and asserts the pasteboard is empty after the expiry window, so a
  future copy call written without the expiring form doesn't quietly regress the
  guarantee.
- Confirm 60 seconds is still the right window for a copied *ciphertext* result and not
  just the key-string case it was originally chosen for — the request didn't specify a
  duration.

### Acceptance

- A test (or CI grep) proves every clipboard write in the app uses the expiring form,
  and fails if a new plain `UIPasteboard.general.string =` assignment shows up.
- Confirmed expiry window matches what's documented here, or this doc is updated to
  match a deliberately different choice.
