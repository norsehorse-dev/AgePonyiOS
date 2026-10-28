# AgePony iOS 5.1.0 RC1: UI restyle changes (U1, U2, U3, U6)

Scope: U1 (strings, English only), U2 (theme and components), U3 (navigation chrome) and U6 (bugs)
from `AgePony_5.1.0_UI_Plan.md`. Rule numbers refer to the human-grade-app-ui skill. Nothing was
built here; every edit was made by hand for iOS 17+, so the first `xcodebuild` run is the real check:

    xcodebuild test -project AgePony.xcodeproj -scheme AgePony -destination 'platform=iOS Simulator,name=iPhone 17'

No git commands were run and nothing is committed. Not touched: `Sources/`, `Tests/`, the plan and
inventory files, `Vault/KeychainStore.swift`, `Vault/Vault.swift`, and the C1 logic in
`OnboardingView.swift` (keychainRefused stage, NoPasscodeStage refusedDetail; only fonts and colors
changed there).

## New files

- `AgePony/Localizable.xcstrings`: empty String Catalog (`{"sourceLanguage" : "en", "strings" : {}, "version" : "1.0"}`).
  The folder is a synchronized group, so the build should pick it up and fill it.
- `AgePony/Assets.xcassets/AccentColor.colorset`: was empty. Light #0E7D7A, dark #38CFE8.
- `AgePony/Assets.xcassets/AccentForeground.colorset`: text on an accent fill. Light #FFFFFF, dark #00282C.

## Design system (U2)

- `DesignSystem/AgePonyColors.swift` (rules 12, 13, 14): rewritten as a thin namespace. Members now:
  `accent` (= `Color.accentColor`, the asset), `onAccent` (`Color("AccentForeground")`),
  `destructive` (system red), `success` (system green), `warning` (system orange). Removed:
  `cyanLight`, `tealCore`, `tealDeep`, `tealInk`, `primary`, the magenta `destructive`, `brandGradient`.
  Every call site was reviewed: selection and checkboxes use `accent`; decorative teal on icons,
  headings and hero icons became `.secondary`; teal text became `.primary`/`.secondary`; success
  headings and done icons became `success`; magenta, `.red` and `.indigo` errors became one red.
- `DesignSystem/AgePonyButton.swift` (rules 7, 12, U6 contrast): the three custom styles are gone.
  `agePonyPrimary` and `agePonySecondary` are now `PrimitiveButtonStyle` wrappers that render a
  system `Button` with `.borderedProminent` (accent tint, `onAccent` text) or `.bordered`, both
  `.controlSize(.large)` and full width. A button with `role: .destructive` gets the red tint. The
  unused `agePonyDestructive` style was deleted (no call sites). No r14 shapes, no bodyEmph, no
  stacked tint plus border.
- `DesignSystem/AgePonyTypography.swift` (rules 1, 3, 26): all system text styles. Added
  `subheadline`; removed `bodyEmph` (all 23 call sites moved to `body`, rows are regular now).
  `title` is title2 semibold, `largeTitle` bold, `headline`/`body`/`footnote`/`caption` are the plain
  system styles. Mono tokens unchanged and used only for keys, fingerprints, file names and codes.
- `DesignSystem/AgePonyKeyBlock.swift` (rules 6, 7, U6 multi-fire): no tinted bordered card; it is
  plain content for a Form row. Mono value in `.primary`, label in subheadline secondary, buttons
  in an `HStack` with `.buttonStyle(.borderless)` so one tap fires one button. `label` is now
  `LocalizedStringKey?`. "QR" button reads "QR code". Reveal still blurs the value (functional
  hiding, not decoration).
- `DesignSystem/PostQuantumBadge.swift` (rule 15): `Label("Quantum-safe", systemImage: "atom")` in
  `.secondary`, no capsule. `compact` now only picks footnote over subheadline.
- `DesignSystem/KeyAvatarView.swift` (rule 14, Q4): flat circle with the same per-key hue, initials
  in subheadline semibold, size scaled with `@ScaledMetric(relativeTo: .body)`. Same init signature.
- `DesignSystem/QRCodeView.swift`: "Add recipient screen" (sentence case), spacing 16.
- `DesignSystem/PlaintextShareButton.swift`: `title` is `LocalizedStringKey`.
- `DesignSystem/AppTheme.swift`: `displayName` returns `LocalizedStringResource`.

## Gradient screens (rule 14)

All now a plain system background with default text colors; content otherwise unchanged.

- `Features/Home/RootView.swift`: ResolvingView and LockedView use `Color(.systemBackground)`.
  White text became default/secondary; the share-waiting callout lost its white capsule; the
  custom white SecureField became `.textFieldStyle(.roundedBorder)` (and an if/else on PIN or
  password); the footnote text buttons became `.borderless`. "Try unlock again" reads "Try
  unlocking again"; the vault-missing message says "Tap Reset and start over" to match the button.
- `Features/Onboarding/OnboardingView.swift` WelcomeStage: system background, default colors.
- `Features/Onboarding/WalkthroughView.swift`: see U3.
- `Services/PrivacyShield.swift`: cover is a system background with a secondary shield.
- `AgePonyShareExtension/ShareViewController.swift`: `CAGradientLayer` and the duplicated hex are
  gone; `view.backgroundColor = .systemBackground`, default spinner color.

## Navigation chrome (U3, rule 9, rule 30)

- `Features/Home/HomeView.swift`: every tab has a nav bar title (Files, Notes, Text, Identities,
  Settings). Removed `.toolbar(.hidden, for: .navigationBar)` on three tabs and `navigationTitle("")`
  plus inline mode on two. Tab tint is `AgePonyColors.accent`.
- `Features/Files/FilesView.swift`, `Features/Text/TextModeView.swift`: in-content largeTitle removed
  (the nav bar carries it). Hero icon kept for RC2, now `.secondary`.
- `Features/Onboarding/WalkthroughView.swift`: wrapped in a `NavigationStack`; Skip is a toolbar
  button; custom dots removed in favour of `.tabViewStyle(.page(indexDisplayMode: .always))` with
  `.indexViewStyle(.page(backgroundDisplayMode: .always))` so the system dots show on a light
  background. Last page button reads "Continue".
- `Features/Identities/AddRecipientView.swift`: `QRScannerHostView` is a `NavigationStack` with
  title "Scan a QR code", a toolbar Cancel and the hint in a bottom safe-area inset. The capsule
  Cancel and material box are gone.
- Toolbar "+" and lock buttons in Notes, Identities and Signers are now `Label`s ("New note", "Add
  identity"/"Add recipient", "Add signer", "Lock note") so VoiceOver reads them.

## Bugs (U6)

- tealInk text in dark mode: tealInk is gone (KeyBlock, FileInfoCard).
- Primary button contrast: light accent #0E7D7A with white (about 5:1), dark #38CFE8 with #00282C.
- KeyBlock multi-fire: `.borderless` on the button row.
- "Recipients tab" copy (`RecipientPickerView`): now "under Recipients on the Identities tab".
- `Features/Home/PlaceholderView.swift`: nothing references it, but deleting failed with
  "Operation not permitted" in this folder, so it is still there. It still compiles (it uses
  `AgePonyTypography.title`/`footnote`, both kept). Delete it on the Mac.
- Share extension label: `UIFont.preferredFont(forTextStyle: .body)` with
  `adjustsFontForContentSizeCategory = true`, `.label` color.

## Strings (U1)

Approach: literals in `Text`, `Label`, `Button`, `Section`, `navigationTitle`, `alert` and similar
already extract. What did not extract was fixed:

- Computed `String`s shown in `Text` (footers, summaries, error messages, prompts, notices) wrap
  their literals in `String(localized:)`. Biometric prompt reasons are localized too.
- Enum rawValues used as labels got a `label: LocalizedStringResource`: `IdentitiesView.Segment`
  ("My identities", "Recipients"), `PassphraseModeView.Job`. `ImportIdentityView.Mode` rawValues
  were not shown (the picker uses literal Texts), so left alone.
- `sectionTitle` in `Vault/VaultModels.swift` (identity and recipient types), `displayNoun` in
  `Vault/LockMode.swift`, `displayLabel` in `Services/AgeFileInspector.swift`, `typeLabel`,
  `unverifiableNote`, `refusalReason` and `nameClash` in `Services/Portability/KeyPortability.swift`.
- Custom views whose title was a `String` fed by literals now take `LocalizedStringKey`:
  `AgePonyKeyBlock.label`, `SecretEntrySheet.title`, `FileInfoCard.metaLabel`, `TextDecryptView.meta`,
  `EncryptFlow.modeOption`, `MigrateFlow.spinner`, `VerifyFileView.inputRow`, `InfoPages.faq` and
  `attribution` detail, `OnboardingView.BulletRow`, `SettingsView.appLink`. `CheckLine` has a
  `LocalizedStringKey` init plus a `@_disfavoredOverload` `StringProtocol` init for key names.
  `InspectFlow.calloutRow` takes a `Text`. `OwnerCheck` titles are localized at the call site.
- Ternaries of literals became if/else so each string is extracted on its own.
- Concatenations became one interpolated localized string: Notes "Edited \(relative)", NoteDetail,
  Settings scrypt footnote, PaperBackup footer, ReceiveKeys import summary, RecentlyDeleted,
  MigrateFlow sizes ("Was X, now Y"), EncryptFlow totals, YubiKey PIN note, LanLink detail.
- Plurals use automatic grammar agreement: `Text("Found ^[\(n) recipient](inflect: true)")` in views,
  `String(AttributedString(localized: "^[\(n) …](inflect: true)").characters)` where a `String` is
  needed (RootView wrong tries, EncryptFlow and TextEncryptView recipient count and batch headline,
  MigrateFlow, Signers import, RecentlyDeleted, ReceiveKeys summary, PaperRestore, YubiKey PIN).
- Interpolations that `String.LocalizationValue` can't take (an error enum, a `Character`, `UInt32`)
  are converted with `String(describing:)`/`String(_:)`.
- Share extension and Services error strings use `String(localized:)`; the PDF page text too.
- `Text(verbatim:)` for key type plus fingerprint lines and SSH type names, `Text(_, format: .number)`
  for the signer count, so they don't land in the catalog as junk keys.

Copy fixes:

- All 21 em dashes reworded (colon, comma, or two sentences); one more found in
  `SecurityKeyTransport` (CTAP 0x2E). The two "→" are gone ("N files in bundle.tar.age", "Was X,
  now Y"); "Settings → AgePony" in the camera error became "in the Settings app".
- Slogans: welcome tagline "Modern file encryption." is now "File and text encryption with age.";
  "Zero accounts. Zero cloud. Zero telemetry." is now "There's no account, and nothing is sent to a
  server."; the walkthrough page "Private by design" is now "Your keys stay here" with the same
  facts in plain sentences; the source-code row says "AgePony is open source under the Apache-2.0
  license." (no "Inspect all of it.").
- "Get started" is "Continue" (welcome and walkthrough).
- Sentence case: "My identities", "Help and support", "Notes and text", "Identities and
  recipients", "Save and continue", "Security key (Ed25519/P-256)", App Intents "Encrypt file with
  passphrase", "ASCII armor", shortcut "Encrypt with passphrase", Face ID fallback "Use passcode".
- "Danger zone" header is "Reset". ALL CAPS "ACTIVE" is "Active"; source pills are "Pasted",
  "QR code", "GitHub", "Contacts", "Your identity". PDF "UNPROTECTED:" is "Not protected:".
- Placeholder "alice@example.com" in AddSignerView replaced with "such as their name or email address".
- Backticks removed from error strings shown verbatim (they printed literally).

## Per file

Fonts below means: bodyEmph to body, caption/footnote paragraphs to subheadline or footnote,
`.system(size:)` on text removed, spacing moved onto the 4pt grid (14 to 12, 18 to 16, 10 to 8,
6 to 8, 2 or 3 to 4, 22 to 24, 20 to 16), radii limited to 12 (and the 16 QR plate).

- `Features/Files/EncryptFlow.swift`: hero and row icons secondary; mode options use accent for
  selection, 12pt radius; "Change" is `.borderless` (it used to make the whole row tappable);
  progress is `Text(fraction, format: .percent)` in sans with monospaced digits (rule 2); done
  icon green; batch result icons green/orange; Format footer and signed note reworded; strings.
- `Features/Files/DecryptFlow.swift`: colors, fonts, custom passphrase field to `.roundedBorder`,
  progress text sans, strings.
- `Features/Files/InspectFlow.swift`: colors, fonts, em dash, callouts take `Text`, strings.
- `Features/Files/MigrateFlow.swift`: colors, fonts, em dash, arrow, plural, progress, strings.
- `Features/Files/FileInfoCard.swift`: tint plus border replaced by one neutral
  `secondarySystemBackground` fill at radius 12 (rows are RC2); tealInk gone; "Tag" label in sans
  with the tag in mono; match line is a green icon plus words; scrypt warning orange.
- `Features/Files/RecipientPickerView.swift`: "Recipients tab" copy, selection in accent, paste
  field mono only once it has text, em dash, strings.
- `Features/Files/DecryptIdentities.swift`: YubiKey PIN note no longer concatenated.
- `Features/Text/TextEncryptView.swift`, `TextDecryptView.swift`: fonts, copy label if/else,
  plural, "BEGIN and END markers", match line green, strings.
- `Features/Home/HomeView.swift`, `RootView.swift`, `PassphraseModeView.swift`: see above.
- `Features/Identities/*`: list rows (Active word, source word, PQ label, avatar 36), detail
  screens (rename pencil is a `.borderless` icon-only Label, colors), AddRecipient (scanner,
  plural, em dash, mono placeholder, buttons), SecurityKeyPinPrompt (em dash, red).
- `Features/Notes/*`: titles, toolbar labels, colors, "Unsaved changes" no longer magenta, sparkle
  "wand.and.stars" replaced with "dice" (rule 17), strings.
- `Features/Onboarding/*`: Welcome (gradient, slogans, Continue), Walkthrough, Generate (key kind
  rows regular body with accent selection, `publicLabel` is `LocalizedStringKey`, warning orange,
  "Save and continue"), Import (strings, em dash).
- `Features/Portability/*`: red paragraphs became an icon plus text (warning or destructive icon,
  default text color, rule 12); "Imported"/"Sent"/"PDF ready" have a green icon; teal on buttons
  removed; mono placeholders and the mono sentence fixed; `BigCode` scales with Dynamic Type;
  `PreviewRow` detail in sans; PDF text localized.
- `Features/Settings/*`: rainbow and indigo app icons are secondary (rule 13, 17); "Help and
  support", "Reset" header, slogan, scrypt footnote; LockSettings sheet titles and messages;
  InfoPages answers in body text; RecentlyDeleted rows and plural.
- `Features/Sign/*`: colors (trusted is green, unknown orange, invalid red), fonts, toolbar label,
  plural, placeholder, em dash, strings.
- `Intents/*`: sentence-case titles, localized error descriptions.
- `Services/*`: user-facing messages localized (YubiKey, FIDO transport and service NFC prompts,
  LanLink, KeyPortability, FileVerifier reasons and notes, MigrateService, AgeFileInspector,
  RecipientImportService, BiometricGate fallback title).

## Spots to check first if the build fails

1. `AgePonyButton.swift`: `PrimitiveButtonStyle` wrappers that build `Button(role:action:label:)`
   from the configuration and apply `.buttonStyle(.borderedProminent)`. Also check that
   `.foregroundStyle(onAccent)` on the button actually colors the `.borderedProminent` label (if
   it doesn't, dark-mode buttons show white on #38CFE8; move the foreground onto
   `configuration.label`).
2. `PortabilityCommon.swift` `CheckLine`: two inits, the `StringProtocol` one marked
   `@_disfavoredOverload`. Literal labels must pick the `LocalizedStringKey` init.
3. `Text(progressFraction, format: .percent.precision(.fractionLength(0)))` in Encrypt, Decrypt
   and Migrate.
4. `String(AttributedString(localized: "^[…](inflect: true)").characters)`: compiles on iOS 15+;
   worth checking the English output for "identity", "try" and "day" on device.
5. `AddRecipientView.QRScannerHostView`: `.safeAreaInset(edge: .bottom)` on the camera
   representable inside a `NavigationStack` in a `fullScreenCover`.
6. `KeyAvatarView` and `BigCode`: `@ScaledMetric` set from a custom init via `_size = ScaledMetric(...)`.
7. `confirmationDialog` titles built with `String(localized:)` inside `.map { }` (Notes, Identity
   list, Signers, RecentlyDeleted).

## Left as is, and why

- `PlaceholderView.swift` could not be deleted from this side (see U6).
- Strings produced in `Sources/AgePonyCore` (`UnlockAttempts.lockoutMessage`, `describeWait`,
  `PasswordKeyBlob.policyError`) are still English-only; Sources was out of scope. They need an
  app-side mapping in U5.
- `Vault/Vault.swift` default `unlock(prompt:)` literal and `Vault/KeychainStore.swift` messages
  are untouched (C1 files). RootView already passes a localized prompt.
- The share extension has no catalog of its own; its `String(localized:)` calls only get
  translations once the extension target is given a catalog (or the app's catalog is added to it).
- Grouped Form section headers may still render uppercase on iOS (the List applies a text case to
  headers). Check on device; if they do, rule 4 needs `.textCase(nil)` on the headers in RC2.
- `PrivacyCoverView` lives in its own window, so it follows the device appearance, not the
  in-app Theme override.
- Raw error text (`localizedDescription`, `String(describing:)`, `\(m)`) is unchanged: that is U5.

## Left for RC2 (from the inventory)

- U4: the 24 hero icons (kept, now secondary or green), Files and Text hubs as Lists, pick and done
  stages as Forms, DecryptFlow and InspectFlow ScrollView stages, FileInfoCard and its duplicate in
  TextDecryptView as rows, EncryptFlow radio cards, the wordmark over status on the lock screen,
  segmented controls in PassphraseModeView, IdentitiesView, ImportIdentityView and AddRecipientView,
  remaining small footnote-style actions, swipe-only remove signer and delete trashed item, the
  thinMaterial error boxes in the SendKeys and PaperRestore scanners, glyph paths written with "›".
- U5: raw error mapping (about 75 sites), generic error copy, one empty-state pattern
  (ContentUnavailableView) with specific copy for identities, recipients, signers and SendKeys.
- U7/U8: a script that checks no user-visible literal is left, then the independent review.

## Independent review and fixes (Oct 26 2026)

A separate agent that did none of the work reviewed the source against the skill's checklist and
read it for compile errors (tree-sitter parse of all 70 changed files: clean). No likely compile
errors. In-scope findings, all fixed:

- Primary button label colour: `.foregroundStyle` moved onto the label inside the button
  (`DesignSystem/AgePonyButton.swift`), so the dark-mode label is near-black on the cyan accent
  instead of white (about 1.5:1).
- Status paragraphs in red or orange: new `DesignSystem/StatusText.swift` (status symbol in the
  status colour, words in the normal colour) used at 18 sites: ImportIdentityView,
  RecipientPickerView (2), AddRecipientView (3), NoteDetailView, CreateNoteView,
  PortabilityCommon, LockSettingsView (2), SecurityKeyPinPrompt, SendKeysView, PaperRestoreView,
  PaperBackupView (2), ReceiveKeysView, FileInfoCard (warning). The remaining warning labels
  already coloured only their icon.
- Uppercase Form section headers: `.textCase(nil)` on all 37 Forms and Lists. Check on device.
- Strings that never reached the catalog: `YubiKeyDecrypt` status message,
  "(invalid hardware key)" (VaultModels, StoredRecipient+Hydration), "(non-UTF8 PEM)" (now
  "(not a readable PEM file)"), the PaperBackupView word-count plural; app names in Settings'
  More from NorseHorse are `Text(verbatim:)` so they aren't offered for translation.
- Avatar initials: brightness 0.62 to 0.5, so white initials stay above 4:1 on every hue.
- Stale VerifiedBadge comment (teal and magenta) updated.

Runtime checks for the device pass: inflected plurals ("^[n more wrong try]" in RootView, "try"
in YubiKeyDecrypt, "day" in RecentlyDeletedView), "Quantum-safe" inside a Label for the
SnapshotTests match, section headers in sentence case.

Not RC1 (left for RC2 per plan): hero shield and wordmark on Welcome and Lock, FileInfoCard fill,
EncryptFlow mode cards, `.thinMaterial` over the camera, segmented controls, raw error text, the
rename pencil, swipe-only actions.
