# AgePony iOS 5.1.0 RC2: screens and errors (U4, U5)

Scope: U4 (screens) and U5 (errors and states) from `AgePony_5.1.0_UI_Plan.md`, built on the RC1
components (StatusText, AgePonyColors, AgePonyTypography, the button style wrappers, KeyBlock,
KeyAvatarView, PostQuantumBadge). Rule numbers refer to the human-grade-app-ui skill. Nothing was
compiled here; every edit was made by hand for iOS 17+ and the changed files were run through a
tree-sitter Swift parse (clean, apart from one ternary in `LanLink.swift` the parser also rejects in
the committed version). The first build is the real check:

    xcodebuild test -project AgePony.xcodeproj -scheme AgePony -destination 'platform=iOS Simulator,name=iPhone 17'

No git commands were run beyond `git status`/`git diff`, and nothing is committed. Not touched:
`Package.swift`, `Tests/`, `Sources/`, `Vault/Vault.swift`, `Vault/KeychainStore.swift`, the plan
and inventory files. Not in this pass: YubiKey PIN before the tap (item 1), picker rows showing key
material (item 3), Face ID only lock (E6), test vectors (E7).

## New and renamed files

- `AgePony/Services/UserMessage.swift` (new, U5, rules 23 and 24): one mapper from any `Error` to a
  plain localized sentence. API:
  - `UserMessage.text(for: error, fallback: String)`: the fallback names the operation
    ("Couldn't decrypt the file.") and is used for errors the app doesn't know, with
    `(domain code)` appended only when the error is a real `NSError`. Never the error's own text,
    `String(describing:)` or a type name.
  - `UserMessage.isCancellation(_:)`: CancellationError, LAError user/app/system cancel,
    BiometricGateError.userCancelled, CocoaError.userCancelled, URLError.cancelled,
    SecurityKeyError.cancelled, NFC user cancel. Screens show nothing for these.
  - `UserMessage.lockout(millis:)` and `waitDescription(millis:)`: localized replacements for
    AgePonyCore's English-only `UnlockAttempts.lockoutMessage`/`describeWait` (same rounding,
    `DateComponentsFormatter` so units localize).
  - `UserMessage.secretPolicyProblem(secret:isPIN:)`: localized replacement for
    `PasswordKeyBlob.policyError` (same rules, it calls the core check first).
  It keeps the module's default MainActor isolation, like every service that calls it.
- `AgePony/Features/Files/FileInfoSection.swift` (renamed from `FileInfoCard.swift` with `mv`; git
  shows a delete plus an untracked file): the single implementation of the file summary, now Form
  rows. See U4.

## U4 screens, per file

- `Features/Files/FilesView.swift` (rules 6, 9, 19): the button hub is a `List` with three
  sections, "Encryption" (Encrypt a file, Decrypt a file), "Signatures" (Sign, Verify) and "Other
  tools" (Inspect, Re-encrypt), each row a `Label` button that opens its flow as a sheet (so no
  chevron), footers that say what Signatures and the tools do. Hero `lock.doc` gone.
- `Features/Text/TextModeView.swift`: same pattern, one section with Encrypt text and Decrypt text,
  footer about armored text. Hero icon gone.
- `Features/Files/FileInfoSection.swift` (rules 6, 7, 2): two Form sections. "File" (or "Details"
  for pasted text): Name (mono, middle truncation), Size, Format as `LabeledContent`. "Recipients":
  one `Label` row per stanza with a secondary icon; scrypt cost as footnote text, or a warning
  `StatusText` when it may not fit; a matched identity as a success `StatusText`; SSH tag in mono.
  No fill, no radius, no stat trio.
- `Features/Text/TextDecryptView.swift`: its private duplicate `FileInfoSection` is deleted and it
  uses the shared one (`filename: nil`). The "Decrypt failed" alert became an inline `StatusText`
  section.
- `Features/Files/DecryptFlow.swift` (rules 6, 9, 23): pick stage is a Form with a "Choose a .age
  file…" row and a footer; ready stage (was a ScrollView with a custom passphrase block) is a Form:
  FileInfoSection, a Passphrase section with a plain `SecureField`, the Decrypt button as a
  standard primary button row, footer "AgePony asks for Face ID or your passcode before it uses
  your keys."; done stage is a Form: success `StatusText` "Decrypted" plus File row, footer saying
  the copy is deleted on close, a "Signature" section with the verdict row, then the share button.
  Toolbar Cancel becomes Done on the done stage. Errors show as a `StatusText` section under the
  action instead of an alert. Both hero icons gone.
- `Features/Files/InspectFlow.swift`: pick stage Form; done stage Form with FileInfoSection and a
  "Can you open it?" section (success `StatusText` when one of your identities matches, a plain
  `Label` otherwise, plus the quantum-safe line); "Inspect another file" is a row. Done moved to the
  confirmation slot. Alert to inline `StatusText`.
- `Features/Files/MigrateFlow.swift`: pick stage Form; configure uses FileInfoSection directly (it
  used to wrap the card in a row with a clear background); Re-encrypt is the standard primary
  button; done stage Form with "Re-encrypted" `StatusText`, File, Size before, Size now,
  Recipients, footer, share button; toolbar Done on the done stage. Alert to inline `StatusText`.
- `Features/Files/EncryptFlow.swift`: pick stage Form ("Choose files…"); the multi-file choice
  stage is a Form with Files and Total size rows and an "Output" section of two rows with a
  trailing accent checkmark (the tinted radio cards with r12 fills are gone, rule 7; selection is
  announced with `.isSelected`); done stage Form: `StatusText` verdict ("Encrypted", or the batch
  headline with success or warning), File row, signed note as the footer, a "Files" section with
  one row per batch result (green check or orange warning icon, file name in mono, error text
  under it), share buttons, then "Encrypt another file" as a plain row. The footnote-size Done is
  the toolbar Done (`finishAfterSuccess`, so the review prompt hook is unchanged). Alert to inline
  `StatusText`.
- `Features/Sign/SignFileView.swift`: the "No signing key" stage is a `ContentUnavailableView`
  with a "Create a signing key" action (copy now says SSH or Secure Enclave keys can sign); pick
  stage Form; done stage Form ("Signed" `StatusText`, Signature file, Signed by, footer, share
  button, "Sign another file" row); toolbar Done on the done stage. Alert to inline `StatusText`.
- `Features/Sign/VerifiedBadge.swift`: `VerifiedBadge` is now rows for a Form section: the verdict
  as a `Label` with the icon in the status colour and the title in headline, the explanation in
  subheadline secondary, then Key type and Fingerprint (mono) as `LabeledContent`. No 56pt hero,
  no centred stack. `CompactVerifiedBadge` is one left-aligned row (icon in status colour, words
  in the normal colour, detail in footnote). Same names, so callers didn't change.
- `Features/Sign/VerifyFileView.swift`: result stage is a Form ("Signature" section with
  `VerifiedBadge`, the two input file names, then "Add as trusted signer" and "Verify another
  file" rows); toolbar Done on the result stage; the alert became an inline `StatusText` on the
  input stage.
- `Features/Home/RootView.swift` (lock and resolving): `LockedView` is a `NavigationStack` with a
  Form titled "AgePony": one sentence ("Your identities, recipients and notes are encrypted on
  this iPhone. Unlock AgePony to use them."), the error as `StatusText`, the waiting-share line,
  then the actions as rows (password or PIN field, Unlock primary, Use Face ID, Continue without
  unlocking with a footer). Recovery shows its title and message, Reset and start over as a
  destructive primary button, and Try unlocking again. Hero shield, large wordmark and "Locked"
  status line are gone. `ResolvingView` is only a spinner on the system background (no wordmark).
  `performUnlock`, `submitPassword`, `performReset` and the recovery logic are unchanged.
- `Features/Onboarding/OnboardingView.swift`: `WelcomeStage` is a Form titled "AgePony" with one
  sentence ("AgePony encrypts files, text and notes with age, and your keys stay on this iPhone.")
  and Continue; the shield, wordmark, tagline and `BulletRow` list are deleted (`BulletRow` had no
  other users). `NoPasscodeStage` is a Form (headline, the same paragraphs, the password button,
  then the check-again row with its spinner); `ChoiceStage` is a Form too. The `keychainRefused`
  stage, `refusedDetail`, `setUpPasswordOnly`, `bootstrapAndContinue` and the stage machine are
  unchanged; only layout, copy and the error text (now via `UserMessage`, which returns
  `KeychainError.errorDescription` unchanged for C1's codes).
- `Features/Onboarding/WalkthroughView.swift`: the 68pt symbol on each page is gone; the title and
  text carry the page (the `symbol` field stays in the page model, unused).
- `Services/PrivacyShield.swift`: the app-switcher cover is the plain system background, no shield.
- `Features/Home/HomeView.swift`: the missing share payload is a `ContentUnavailableView`
  ("The shared file is missing"), replacing "Couldn't read the shared payload." and its 44pt icon.
- `Features/Home/PassphraseModeView.swift` (rule 10): the three-segment control is a `.menu`
  Picker labelled "Action". The "Couldn't finish" alert became an inline `StatusText`.
- `Features/Identities/IdentitiesView.swift`: the "My identities / Recipients" segmented control
  stays. Two short labels fit a segmented control in every likely locale (German "Meine
  Identitäten / Empfänger", French "Mes identités / Destinataires"), it switches the whole tab's
  content, and a toolbar menu would hide which list you're on. A third choice would move it to a
  menu. The lists now get an `onAdd` closure for their empty states.
- `Features/Onboarding/ImportIdentityView.swift`: the age / SSH / YubiKey segments are a `.menu`
  Picker labelled "Key type". The "Could not import" alert became an inline `StatusText`.
- `Features/Identities/IdentityDetailView.swift`, `RecipientDetailView.swift` (rule 27): the
  icon-only pencil inside the Name row is gone; Rename is a toolbar text button. Name, Type,
  Created/Added, Source, Origin are `LabeledContent`. The identity reveal error is a `StatusText`
  in the reveal section instead of an alert.
- `Features/Identities/AddIdentityView.swift`: the custom title-and-buttons screen is a Form with
  two rows (Generate a new identity, Import an existing identity) and a footer.
- `Features/Files/RecipientPickerView.swift` (rule 27, 31): the bare `minus.circle` on pasted
  recipients is a labelled "Remove" button with a 44pt-high target, plus a "Remove" swipe action.
- `Features/Sign/SignersView.swift` (rule 31): signers are removed through Edit mode (an
  `EditButton` beside Add signer while the list has entries; `.onDelete` asks for confirmation
  first), the row's context menu, or the swipe that `.onDelete` provides. The empty state is a
  `ContentUnavailableView` that says what a trusted signer is, with "Paste a public key" and
  "Import allowed_signers" actions; the "From a recipient" picker's empty case is one too. The
  import alert's title now says "Couldn't import" when it failed.
- `Features/Settings/RecentlyDeletedView.swift`: each row has visible Restore and Delete buttons,
  both 44pt high; the swipe stays. Empty title "Nothing recently deleted".
- `Features/Notes/NotesView.swift`, `Features/Identities/IdentityListView.swift`,
  `RecipientListView.swift`, `Features/Portability/SendKeysView.swift`: empty states are
  `ContentUnavailableView` with copy that says what a note, identity, recipient or movable identity
  is and how to add one, with an action button where there is one to take.
- `Features/Portability/SendKeysView.swift`, `PaperRestoreView.swift`: the scanner error keeps its
  `.thinMaterial` box because it sits over the live camera feed, where text needs a backing to stay
  legible (commented in both). The message inside is a `StatusText` now.
- Copy (rules 19, 21): the "›" glyph paths are written out ("under Privacy & Security, Local
  Network, in the Settings app"; "Send keys to another device in AgePony's Settings") in
  LockSettingsView, InfoPages, PaperBackupView (PDF text), ReceiveKeysView and LanLink. "Pick
  from Files…" is "Choose a .age file…", "Choose files…" or "Choose a file…". "Inspect another",
  "Sign another", "Verify another" name the object ("… file"). No em dashes or exclamation marks
  in any new string (checked by grep).

## U5 errors, per file

About 75 raw sites from inventory section 16 now go through `UserMessage`, or through a typed
error whose payload `UserMessage` built:

- Services that put raw text in error payloads now put a finished sentence there, so the public
  enum shapes are unchanged (tests use them):
  - `FileEncryptor.swift`: every `ageError`, `readFailed`, `writeFailed`, `bundleDamaged` payload
    (11 sites, including the package-flattening messages) is `UserMessage.text(for:fallback:)`.
    `bundleDamaged` carries the whole "The file decrypted, but the signed bundle inside it is
    damaged." sentence.
  - `FileSigner.swift`: `readFailed` always carries a sentence (it used to carry a bare file name
    from one site and an error text from another), `signError` (4 sites), `writeFailed` (2). A
    cancelled NFC sheet is rethrown as is, so the screen shows nothing.
  - `SecureEnclaveSigner.swift`, `RecipientImportService.swift`, `AgeFileInspector.swift`
    (`headerParseFailed`), `QRScanner.swift` (the payload is no longer shown), `BiometricGate.swift`
    (`failed` carries the mapped LAError sentence; a `BiometricGateError` thrown inside the `do`
    is no longer re-wrapped), `SharedContainer.swift` in both targets (new `failure(_:_:)` helper:
    sentence plus domain and code, or a full-storage sentence), `FileVerifier.swift` (all
    `.invalid(reason:)` strings localized; the core's English `unreadable(why)` detail is not
    shown), `LanLink.swift` (`unreachable` carries a code such as "POSIX 61" via the new
    nonisolated `LanLinkError.code(for:)`, never `localizedDescription`; a `LanTransferError` is
    rethrown for the mapper).
  - `ScryptMemory.blockingReason` is built from whole localized sentences.
  - `SecurityKeyTransport.swift`: the APDU and unknown CTAP messages are localized with the code in
    parentheses; the NFC sheet's error text comes from the mapper.
  - `YubiKeyDecrypt.message(for:)` is one line that calls the mapper (its PIV and YubiKey cases
    moved there).
  - `Intents/EncryptWithPassphraseIntent.swift`: both `operationFailed` payloads.
- Views: every `localizedDescription`, `String(describing:)`, `"(\(e))"` and `"…: \(m)"` site in
  SettingsView, LockSettingsView, RootView, NoteDetailView, CreateNoteView, InspectFlow,
  MigrateFlow, RecipientPickerView, EncryptFlow, DecryptFlow, SendKeysView, PaperBackupView,
  PaperRestoreView, PortabilityCommon, ReceiveKeysView, AddRecipientView, IdentityDetailView,
  TextEncryptView, TextDecryptView, AddSignerView, SignersView, SignFileView, VerifyFileView,
  ImportIdentityView, GenerateIdentityView, OnboardingView and ShareViewController. The string
  matching on `"wrongPassphrase"`/`"noMatchingIdentity"` (PassphraseModeView, NoteDetailView,
  DecryptFlow, TextDecryptView) is gone; NoteDetailView switches on `AgeError` cases.
- Generic messages replaced: LockSettingsView "Something went wrong. Try again." (the switch is
  exhaustive now; wrongPassword and the vault-file cases get their own words), RootView "Could
  not unlock the vault." (exhaustive, mapper fallback "Couldn't unlock the vault."),
  PaperRestoreView "Couldn't open the backup." (wrong passphrase, damaged, or the mapper with
  "Couldn't decrypt the backup page with that passphrase."), PassphraseModeView "Couldn't read
  the age header." (the header error's own sentence, fallback per task), HomeView "Couldn't read
  the shared payload." (see U4).
- `UnlockAttempts.lockoutMessage`/`describeWait` and `PasswordKeyBlob.policyError` are no longer
  called from the app (RootView, LockSettingsView, PortabilityCommon); `Vault.swift` still calls
  `policyError` internally (C1 file, untouched), and the mapper turns its `weakSecret` English
  text back into the localized rule.
- Errors shown with `StatusText` in place of alerts: DecryptFlow, EncryptFlow, InspectFlow,
  MigrateFlow, SignFileView, VerifyFileView, TextDecryptView, TextEncryptView, PassphraseModeView,
  NoteDetailView, CreateNoteView, AddSignerView, ImportIdentityView, IdentityDetailView (reveal),
  RootView lock screen. Alerts kept where there's no form to put the message in or the sheet that
  failed has gone: reset failure (RootView, SettingsView), onboarding setup failures (the
  password sheet closes first), GenerateIdentityView, AddRecipientView save, Signers import
  result, the owner check in PortabilityCommon, the vault-erased notice. Their messages all come
  from the mapper or are written out.

## Error type to message

"Fallback" means the caller's operation sentence. Codes in parentheses are appended as shown.

| Error | Message |
|---|---|
| KeychainError (all) | its C1 `errorDescription`, unchanged (OSStatus codes included) |
| VaultError.notUnlocked | The vault is locked. Unlock AgePony and try again. |
| .vaultFileMissing | The vault file is missing. This usually means AgePony was reinstalled. (RootView adds "Tap Reset and start over…") |
| .malformedVaultFile | The vault file is damaged and can't be read. |
| .decryptionFailed | The vault couldn't be decrypted. Its key in the Keychain may have been reset. |
| .wrongPassword | Wrong password or PIN. (RootView and LockSettings use the real noun and the erase warning) |
| .lockedOut(ms) | Too many wrong attempts. Try again in {localized wait}. |
| .noAppPassword | No app password is set for this vault. |
| .duressEqualsReal / .realEqualsDuress | The duress password must be different from your real one. / Your password must be different from the duress password. |
| .weakSecret | A PIN can only contain digits. / Use at least 6 digits. / Use at least 8 characters. |
| .kindLockedByDuress / .lockModeLockedByDuress | Remove the duress password first to switch between a password and a PIN. / … to change how the vault unlocks. |
| .passwordIsOnlyUnlock | The app password is the only way into the vault. Choose another way to unlock before removing it. |
| PasswordKeyBlob.BlobError.deviceKeyMissing | This iPhone's key for the app password is missing, so the password can't open the vault. |
| .duressMaterialUsed | The duress password has already been used on this vault. |
| .tooShort/.unknownVersion/.implausibleWorkFactor/.shortMAC | The stored app password data is damaged. |
| VaultModelError.malformedPublic/PrivateMaterial(t) | The stored {type} key is damaged. |
| .signingOnlyIdentity(t) | {type} identities can sign but can't decrypt. |
| .needsYubiKeyTap | This identity is on a YubiKey. Hold the key to your iPhone to use it. |
| StoredRecipientHydrationError | The stored recipient is damaged. |
| FileEncryptorError.noRecipients | Choose at least one recipient. |
| .scryptCannotMixWithRecipients | A passphrase can't be combined with recipients in the same file. |
| .cannotOpenInput(n) / .cannotOpenOutput(n) | Couldn't open {n}. / Couldn't create {n}. |
| .readFailed/.writeFailed/.ageError/.scryptWontFit/.bundleDamaged | the sentence in the payload (built by the mapper or ScryptMemory) |
| FileSignerError.identityCannotSign | This identity can't make signatures. |
| .requiresSecurityKey | This identity is on a security key. Hold the key to your iPhone to sign. |
| .keyTypeNotYetSupported(t) | AgePony can't sign with {type} keys yet. |
| .malformedIdentityMaterial | This identity's stored key is damaged. |
| .readFailed/.writeFailed/.signError | payload sentence |
| SignEncryptError | The identity you chose to sign with can't make signatures. / The signing identity is on a security key… (EncryptFlow overrides: sign it from Sign a file) / Couldn't open {n}. |
| MigrateError | its existing localized `errorDescription` |
| AgeFileInspectorError.notAnAgeFile / .malformedArmor | That isn't an age-encrypted file. / The armored text is damaged. (screens have file- or text-specific versions) |
| .headerParseFailed / .cannotOpenFile(n) | payload sentence / Couldn't open {n}. |
| SSHImportError | This SSH key needs its passphrase. / Wrong passphrase for this SSH key. / AgePony can import SSH Ed25519 and RSA keys. This is another type. / That isn't a readable OpenSSH private key. |
| RecipientImportError | That isn't a recipient AgePony recognizes… / That GitHub account has no keys AgePony can use. / payload / That isn't a valid GitHub username. |
| SecureEnclaveSignerError | The Secure Enclave isn't available on this device. / payload / The stored Secure Enclave key is damaged. |
| SharedContainerError | The folder AgePony shares with its share extension isn't available. / payload / The shared item is damaged. Share it again. / The shared item has expired. Share it again. |
| BiometricGateError | Face ID, Touch ID and the passcode aren't available on this device. / Authentication was cancelled. / payload |
| QRScannerError | This device has no camera AgePony can use. / AgePony isn't allowed to use the camera. Turn it on for AgePony in the Settings app. / The camera couldn't start. Close the scanner and try again. |
| LanLinkError, AgePonyIntentError, SecurityKeyError | their localized `errorDescription` (LanLink's unreachable detail is a code; APDU status and CTAP code in parentheses) |
| AgeError.noRecipients / .scryptMustBeSoleRecipient | Choose at least one recipient. / A passphrase can't be combined with recipients in the same file. |
| .scryptNotAlone | This file mixes a passphrase with other recipients, which age doesn't allow. |
| .mismatchedRecipientLabels | Some of these recipients can't share a file with the others, such as quantum-safe and classic keys. |
| .noMatchingIdentity | None of your identities can open this file. |
| .wrongPassphrase | Wrong passphrase. |
| .truncatedFile | The file is incomplete. It may have been cut off while copying. |
| .headerError / .payloadError / .invalidFileKeyLength | the header or payload row / The file's age header is damaged. |
| AgeHeaderError.missingVersionLine | That isn't an age-encrypted file. |
| .unsupportedVersion | This file uses an age format version AgePony doesn't read. |
| .invalidMAC | The file's header failed its integrity check. It was changed or damaged. |
| .tooLarge | The file's age header is too large to read. |
| other header cases, StanzaError | The file's age header is damaged. |
| AgePayloadError.decryptFailed | The encrypted contents failed their integrity check. The file was changed or damaged. |
| .streamReadFailed / .streamWriteFailed | Couldn't read the file. / Couldn't write the output file. |
| other payload cases | The encrypted contents are damaged or incomplete. |
| AgeArmorError | The armored text is missing its BEGIN or END line. / There's extra text outside the armored block. / The armored text is damaged. |
| Bech32Error.invalidChecksum / .mixedCase / .unexpectedHRP | That key has a typo: its checksum doesn't match. / That key mixes upper and lower case letters. / That's a different kind of key than this field takes. (ImportIdentityView keeps its more detailed version) |
| other Bech32 cases | That isn't a valid age key. |
| Scrypt.ScryptError | The passphrase settings are out of range. |
| ScryptStanzaError.decryptFailed / .invalidWorkFactor / others | Wrong passphrase. / The file's passphrase work factor is out of range. / header damaged |
| X25519Error | That X25519 key is damaged. / None of your identities can open this file. / header damaged |
| HybridKEMError.lowOrderPoint | This file wasn't made for any of your keys, or it was tampered with. |
| other HybridKEMError, MLKEMError, HybridStanzaError | That quantum-safe key is damaged. |
| P256RecipientError, P256CurveError, HpkeP256Error | That P-256 key is damaged. |
| TagRecipientError | That hardware key recipient is damaged. / That's a different kind of key than this field takes. |
| SecureEnclaveKeyError | not available / iOS couldn't set up the protection for the Secure Enclave key. / The stored Secure Enclave key is damaged. / The Secure Enclave couldn't open this file. |
| Ed25519ConversionError, SSHEd25519Error.conversionFailed | That Ed25519 key can't be converted for encryption. |
| OAEPError / AESCBCError / AESCTRError / RSAKeyError | The RSA key couldn't open this file. / That RSA key is too small to use. / A step in the RSA key handling failed. The key may be damaged. |
| SSHKeyError, SSHRSAKeyParserError, OpenSSHEncryptedKeyError | That isn't an SSH public key line. / AgePony doesn't use {type} keys. / This SSH key is protected with {cipher}, which AgePony can't open. / Wrong passphrase for this SSH key. / That RSA key is {n} bits. AgePony needs at least 2048. / This SSH key needs its passphrase. / The SSH key is damaged or isn't in a format AgePony reads. |
| SSHEd25519PassphraseError, SSHWireFormatError, OpenSSHEd25519ExportError | The SSH key is damaged or isn't in a format AgePony reads. |
| BcryptPBKDF.BcryptError | This SSH key's passphrase settings can't be used. |
| SSHRSAStanzaError | That RSA key is too small to use. / Couldn't encrypt to that SSH RSA key. / The SSH RSA key couldn't open this file. |
| SSHKeySourceError | That isn't a valid GitHub username. / GitHub didn't return the keys (HTTP {n}). / That GitHub account has no keys AgePony can use. / The proxy settings are incomplete. Check Network in Settings. |
| SSHSigError | The signature doesn't match this file. / This signature was made for something else (namespace {ns}). / The signature was made without touching the security key, so it doesn't count. / This signature uses {alg}, which AgePony can't check. / … format version AgePony can't check. / Couldn't make the signature. / The signature is damaged or isn't an SSH signature. (FileVerifier keeps its own wording for the common cases) |
| SignedEncryptionError | A file encrypted with a passphrase can't carry a signature. / The signature doesn't cover this message. / The decrypted contents don't match what was signed. |
| SignedBundleError | The signed bundle is damaged. / … has no file in it. / … has no signature in it. / The signed bundle's file list can't be read. |
| TarArchiveError | The name {n} is too long to put in a bundle. / {n} is too large to put in a bundle. / The bundle is damaged or incomplete. |
| PivError | This YubiKey key needs its PIN. / The PIV PIN is blocked. Unblock it with the PUK in YubiKey Manager. / Wrong PIN. {n tries} left before it locks. / A YubiKey PIN is 6 to 8 characters. / That key has no PIV applet (status {SW}). / That YubiKey has no key in the slot this identity uses (status {SW}). / The key in that slot isn't a P-256 key. / The YubiKey refused the request (status {SW}). / The YubiKey's answer didn't make sense. Tap it again. |
| YubiKeyError | That's YubiKey {serial}. This identity is on YubiKey {serial}. / The key in that slot isn't the one this identity points at. / That isn't an age-plugin-yubikey identity (AGE-PLUGIN-YUBIKEY-1…). / That identity points at a slot age-plugin-yubikey doesn't use. |
| RecordedKeyAgreement.Missing | The YubiKey didn't answer for every key this file needs. Tap it again. |
| CTAP2Error, CBORError, COSEKeyError, AuthenticatorDataError | The security key's answer didn't make sense. Tap it again. |
| Diceware.DicewareError | The word list for passphrases couldn't be loaded. |
| KeyTransferError | That isn't an AgePony key transfer. / … made by a newer version of AgePony. Update AgePony on this phone. / … more keys than AgePony takes at once. / … sealed for a different receive session. Start Receive keys again and rescan. / That isn't a receive key from another phone. (ReceiveKeysView keeps its own nonisolated wording) |
| LanTransferError | That QR code isn't from Receive keys on another phone. / That receive QR code is damaged. Scan it again. / The other phone sent something unexpected. Start the transfer again. / The other phone's code didn't match. Start Receive keys again and rescan. / Transfer is too large to send directly. / The other phone refused the transfer. Start Receive keys again and rescan. |
| PaperBackupError | Enter the backup passphrase. / That isn't an AgePony paper backup. / The backup is damaged or didn't scan completely. / Wrong backup passphrase. |
| LAError | Face ID or Touch ID didn't recognize you. / Authentication was cancelled. / Set a device passcode in the Settings app to use this lock. / Face ID or Touch ID isn't available. Check that AgePony may use it in the Settings app. / … isn't set up on this iPhone. / … is locked after too many tries… / other: Authentication didn't succeed (LAError {code}). |
| NFCReaderError | Cancelled. / The NFC scan timed out… / NFC is busy… / The key moved away before the exchange finished… / This iPhone can't read security keys over NFC. / other: The NFC exchange failed (NFC error {code}). |
| URLError | There's no internet connection. / The server took too long to answer. / Couldn't reach the server (URLError {code}). / The secure connection to the server failed (URLError {code}). / Cancelled. / The request failed (URLError {code}). |
| CocoaError | The file isn't there any more. / AgePony isn't allowed to use that file. Pick it again. / There isn't enough free storage on this iPhone. / That location is read-only. / The file is damaged. / The file is too large to read. / A file with that name already exists. / Cancelled. / A file operation failed (Cocoa error {code}). |
| POSIXError | storage, permission, missing file, read-only as above / A system call failed (POSIX {code}). |
| NWError | The other phone isn't accepting connections. Open Receive keys on it again. / Couldn't reach the other phone. Put both on the same Wi-Fi. / The connection failed (POSIX/DNS/OSStatus {code}). |
| CryptoKitError.authenticationFailure / other | The data failed its integrity check. It was changed or damaged, or the key is wrong. / A CryptoKit operation failed. The key may be damaged. |
| DecodingError | The saved data is damaged and couldn't be read. |
| CancellationError | Cancelled. |
| anything else | fallback, plus "(domain code)" for a real NSError |

## Spots to check first if the build fails

1. `UserMessage.swift` switches over AgePonyCore enums exhaustively. Another agent is editing
   `Sources/`: if a core error enum gains a case, the build stops at that switch (that's the
   point; add a row). HybridKEMError's new `lowOrderPoint` is already covered.
2. `UserMessage` keeps the default MainActor isolation. Services call it from synchronous
   MainActor-isolated code that runs on GCD queues, the same pattern FileEncryptor already uses.
   `LanLink.swift` (nonisolated) doesn't call it; it uses the new nonisolated
   `LanLinkError.code(for:)`.
3. `switch e.code` over `CocoaError.Code` and `URLError.Code` (struct codes matched with
   `.member` patterns), `POSIXErrorCode`, `NWError` with `default`, `LAError.Code` with `default`,
   and `NFCReaderError` under `#if canImport(CoreNFC)`.
4. `type(of: error) is NSError.Type` to tell a real NSError from a bridged Swift error (in
   UserMessage, LanLink, both SharedContainer copies, ShareViewController).
5. Toolbars with `if stage == .done { ToolbarItem … } else { ToolbarItem … }` and
   `if let identity { ToolbarItem … }` (ToolbarContentBuilder, iOS 16+).
6. `VerifiedBadge` and `FileInfoSection` return several rows/sections from `body`; they must sit
   inside a Form/Section (they do at every call site).
7. `SignersView`: `.alert(Text, isPresented:actions:message:)` with a ternary of two `Text`s, and
   `EditButton` inside `ToolbarItemGroup` with an `if`.
8. `IdentityListView`/`RecipientListView` gained `var onAdd: () -> Void = {}` beside a
   `@State private var`; the memberwise init should still be internal.
9. `FileInfoCard.swift` was renamed to `FileInfoSection.swift` in the synchronized folder; if
   Xcode still lists the old path, remove the stale reference.

## Runtime checks for the device pass

- Lock screen and Welcome as Forms: large title "AgePony", first section sentence, buttons.
- Files and Text tab rows tint: they use `.foregroundStyle(.primary)` so they read as rows, not
  links.
- EncryptFlow "Output" rows: checkmark moves, VoiceOver says selected.
- Signers: Edit, swipe and context-menu remove all ask before removing.
- RecentlyDeleted rows with Restore and Delete side by side on a small phone with a long name.
- Lockout wording ("Try again in 30 seconds") from `DateComponentsFormatter`.

## Skipped, and why

- `AddRecipientView`'s Paste / Scan / GitHub segments stay: three short labels, and the task named
  only the three segmented controls above.
- Notes rows still delete by swipe only on the list; Delete note is a visible button on the note's
  own screen, so the list keeps the platform swipe.
- `LockSetupStage` in onboarding keeps its VStack layout (no hero icon or card in it).
- `WalkthroughPage.symbol` is left in the model unused rather than editing every page.
- `Vault.swift` still calls the English `PasswordKeyBlob.policyError` (C1 file); the mapper covers
  its output.
- Strings in `Sources/AgePonyCore` remain English; the app no longer shows them except through the
  mapper.

## Independent review and fixes (Oct 26 2026)

A separate agent reviewed U4 and U5: every switch in UserMessage checked case by case against
the current enums, all system error-code cases real, SwiftUI APIs fine on iOS 17, no stale
references, no behavior change in unlock, setup (C1), duress, share hand-off or M-7 cleanup. No
likely compile errors. Fixed after the review:

- DecryptFlow (security, pre-existing): a decrypt that finished after the flow was dismissed
  (Cancel or swipe mid-decrypt) left its plaintext temp file behind, because `onDisappear` had
  already run. A `FlowLifetime` object now outlives the view; the completion deletes the file if
  the flow is gone.
- Verdicts ("Decrypted", "Encrypted", "Re-encrypted", "Signed", the batch headline) colour the
  word as well as the icon (`StatusText(..., verdict: true)`, semibold); sentences keep the colour
  on the icon only.
- `let description: String?` made explicit in MigrateFlow and SignFileView.
- AddSignerView clears its error when the pasted key changes.
- SignersView leaves Edit mode when the last signer is deleted.
- `LAError.userFallback` counts as a cancellation (no error shown).
- SendKeysView: the empty-identities note is a plain row, not a ContentUnavailableView inside a
  Form row.
- PaperRestoreView fallback no longer suggests a wrong passphrase ("Couldn't open the backup
  page."); RecipientImportService's proxy message matches UserMessage.
- SecurityKeyTransport's NFC sheet messages are localized.

Kept on purpose: the two-segment control in IdentitiesView (short labels, shows which list you're
on), Paste/Scan/GitHub in AddRecipientView and Password/PIN in LockSettingsView (short).
Errors that can sit below the fold on long Forms (EncryptFlow configure, TextDecryptView,
TextEncryptView) are a device-pass item: if they're hard to notice, move the error section under
the action.
