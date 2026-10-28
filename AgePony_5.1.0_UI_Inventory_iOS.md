# AgePony iOS UI inventory (5.1.0, Oct 26 2026)

Step 1 of the human-grade-app-ui process: every tell found before anything changes. Read-only
pass over `AgePony/` and `AgePonyShareExtension/`. Paths are relative to `AgePony/` unless they
start with `AgePonyShareExtension/`. The plan that works from this is `AgePony_5.1.0_UI_Plan.md`.

## Design system

- `DesignSystem/AgePonyColors.swift`: fixed RGB, no light/dark variants, no asset colors.
  cyanLight #38CFE8 (gradient top, :18), tealCore #14B8B0 (primary, :22; white text on it is
  about 2.4:1), tealDeep #0E7D7A (:25), tealInk #0A4F4D (headlines, :28; used as text at
  `AgePonyKeyBlock:50`, `FileInfoCard:62,76`, near-invisible in dark mode), destructive #C046DC
  magenta (:39), `brandGradient` cyan to deep (:48-52). `AccentColor.colorset` is empty; tint is
  set at `HomeView:84`.
- `DesignSystem/AgePonyTypography.swift`: system font only. largeTitle/title/headline semibold,
  body, bodyEmph (body medium), footnote, caption, monoBody/monoSmall/monoCaption. Usage:
  footnote 93, caption 46, monoCaption 31, bodyEmph 23, headline 21, title 20, body 11,
  monoSmall 10, largeTitle 5. Footnote is the default paragraph size; bodyEmph on every row title.
- `DesignSystem/AgePonyButton.swift`: three styles, r14, minHeight 50, full width, bodyEmph.
  Primary white on tealCore; Secondary teal text on teal tint plus teal stroke (tint and border
  stacked); Destructive magenta on magenta tint. Used inside Forms via
  `.listRowBackground(Color.clear)` 25 times in 18 files.
- `AgePonyKeyBlock.swift`: teal 0.06 fill plus 0.18 stroke r12 card, mono text in tealInk, blur
  reveal, Copy/Reveal/QR footnote buttons with no `.borderless` inside Form rows (one tap may
  fire all three).
- `PostQuantumBadge.swift` capsule pill; `KeyAvatarView.swift` initials on a gradient circle;
  `QRCodeView.swift` white r16 plate (functional); `PlaintextShareButton.swift`, `AppTheme.swift`.
- `Home/PlaceholderView.swift` is dead code.

## 1. Mono on non-data
Progress percentages `EncryptFlow:372`, `DecryptFlow:211`, `MigrateFlow:194`. A sentence
`PaperBackupView:106-107`. Prose placeholders in mono fields: `SendKeysView:116-117`,
`PaperRestoreView:67-69`, `ReceiveKeysView:171-173`, `RecipientPickerView:179-180`,
`AddRecipientView:120-121`. Prose type label `PortabilityCommon:202` (fed from
`ReceiveKeysView:210,229`). "tag:" prefix `FileInfoCard:91-92`. Bold fixed 26pt mono code
`PortabilityCommon:226`.

## 2. Sizes
37 `.system(size:)` plus UIKit 17pt `AgePonyShareExtension/ShareViewController:91` (no Dynamic
Type). 9pt `RecipientListView:86`, `IdentityListView:109`; 10/11pt `PostQuantumBadge:21`;
`KeyAvatarView:32`; 14pt `FileInfoCard:69`, `OnboardingView:201`; 15pt
`GenerateIdentityView:580`; 18pt `NotesView:115`, `SignersView:256`, `GenerateIdentityView:563`;
22pt `NoteDetailView:101`, `EncryptFlow:245`.
Hero icons 44-72pt (24): `PlaceholderView:22`, `HomeView:184`, `RootView:475`, `NotesView:70`,
`InspectFlow:78`, `MigrateFlow:115,211`, `FilesView:31`, `EncryptFlow:184,394`,
`DecryptFlow:129,230`, `RecipientListView:21`, `IdentityListView:24`, `TextModeView:27`,
`SignersView:138`, `SignFileView:134,155,253`, `VerifiedBadge:23`, `WalkthroughView:141`,
`OnboardingView:171,225`, `Services/PrivacyShield:85`.
5+ sizes: Onboarding Welcome (`OnboardingView:166-191`), EncryptFlow done (`:390-453`),
DecryptFlow ready plus FileInfoCard (`:159-200`), GenerateIdentityView, VerifiedBadge plus
result (`VerifyFileView:181-213`), identity and recipient rows (4 sizes in one row).
bodyEmph on row titles: `RecentlyDeletedView:116`, `InfoPages:171`, `NoteDetailView:104`,
`NotesView:121`, `FileInfoCard:24`, `RecipientPickerView:267,288`, `EncryptFlow:250,279,303`,
`PortabilityCommon:200`, `RecipientListView:80`, `AddRecipientView:224`, `IdentityListView:103`,
`TextEncryptView:104`, `SignersView:171,261`, `SignFileView:181`, `VerifyFileView:152`,
`WalkthroughView:75`; headline as row title `GenerateIdentityView:569`.

## 3. Uppercase
"ACTIVE" `IdentityListView:108`; "PASTE"/"QR"/"GITHUB"/"CONTACTS"/"SELF"
`RecipientListView:106-111`; "UNPROTECTED:" on the PDF `PaperBackupView:282`.

## 4. Cards
`AgePonyKeyBlock:40-46` inside Form rows (card in card) at `GenerateIdentityView:165`,
`IdentityDetailView:61,72,87`, `RecipientDetailView:75`. `FileInfoCard:44-52` at
`DecryptFlow:163`, `InspectFlow:110`, `MigrateFlow:136` (in a Form); `TextDecryptView:323-381`
has a second plain-Form version of the same content. Radio cards `EncryptFlow:239-268`.
ScrollView screens instead of Forms: `DecryptFlow:159-200` (custom field r10 at `:176-180`),
`InspectFlow:106-137`. Callout on gradient `RootView:491-496`; custom SecureField
`RootView:511-517`; material boxes `AddRecipientView:426-432`, `SendKeysView:139-142`,
`PaperRestoreView:138-142`.

## 5. Eyebrow near-misses
Stat-trio captions `FileInfoCard:29-34,55-64`, `TextDecryptView:328-332,357-365`; wordmark
over status `RootView:477-482`; wordmark plus tagline `OnboardingView:173-178`.

## 6. Custom chrome
Nav bar hidden on Files, Text, Settings (`HomeView:49,64,79`); in-content largeTitles
`FilesView:34-35`, `TextModeView:30-31`; Settings untitled; `navigationTitle("")` on Notes and
Identities (`HomeView:56,71`). Button hubs `FilesView:29-93`, `TextModeView:24-58`. Hero-icon
pick stages `EncryptFlow:180-199`, `DecryptFlow:125-144`, `InspectFlow:74-93`,
`MigrateFlow:111-130`, `SignFileView:130-170`. Custom done screens `EncryptFlow:390`,
`DecryptFlow:226`, `MigrateFlow:207`, `SignFileView:249`, `VerifyFileView:181`;
`AddIdentityView:29-53`. Walkthrough custom Skip (`:72-79`) and dots (`:89`, `:109-120`).
Gradient screens `RootView:429-443`, `:445-556`, `OnboardingView:162-194`, `PrivacyShield:80-90`,
share extension. Scanner with capsule Cancel `AddRecipientView:405-437`. Segmented header
`IdentitiesView:33-41`.

## 7. Segmented controls
`PassphraseModeView:51-54` (3 long segments, worst), `IdentitiesView:26-38`,
`ImportIdentityView:58-63`, `AddRecipientView:100-105`, `LockSettingsView:449-453` (fine).

## 8. Grid and radii
Off-grid spacing: 18 x22, 14 x13, 10 x8, 6 x5, 22, 3, 1, and 2 x23 (row stacks). Off-grid
padding: 14 (`AgePonyKeyBlock:54`, `EncryptFlow:261`), 6 (`RecipientListView:88`,
`IdentityListView:111`), 2, 10 (`AddRecipientView:418`), 6 top (`DecryptFlow:247`), 5/7 and
2/3 (`PostQuantumBadge:28-29`). Radii: 12 x7, 14 x6, 10 x3, 16 x1, plus capsules.

## 9. Color
Gradients: definition `AgePonyColors:48-52`; `RootView:432,471`, `WalkthroughView:68`,
`OnboardingView:167`, `PrivacyShield:83`, `AgePonyShareExtension/ShareViewController:45-58`
(hex duplicated), `KeyAvatarView:21-28`. Magenta destructive at `AgePonyButton:61,66`,
`NoteDetailView:121,179`, `CreateNoteView:93`, `RecipientPickerView:188,234`,
`AddRecipientView:129,161,185`, `VerifiedBadge:105`, `ImportIdentityView:170`; `.red` at
`LockSettingsView:373,465`, `SendKeysView:64,164`, `PaperBackupView:63,113,122,133`,
`PaperRestoreView:44`, `PortabilityCommon:111,207`, `ReceiveKeysView:97,145,194,201`,
`SecurityKeyPinPrompt:38`; system red on `role: .destructive`. `.indigo` and rainbow icons
`SettingsView:417-437`. Status color on whole paragraphs: `ReceiveKeysView:143-145,192-194`,
`PaperBackupView:120-122,131-133,177-179`, `SendKeysView:162-164`; orange icons/text
`GenerateIdentityView:186`, `FileInfoCard:85`, `EncryptFlow:483`, `VerifiedBadge:104`;
"Unsaved changes" in magenta `NoteDetailView:178-179`. Decorative teal: every hero icon; row
icons `NotesView:116`, `SignersView:257`, `FileInfoCard:22,70`, `TextDecryptView:338`,
`RecipientPickerView:158`, `EncryptFlow:276`, `SignFileView:178`, `VerifyFileView:149`,
`InspectFlow:142`, `NoteDetailView:100`; text `FileInfoCard:89`, `TextDecryptView:346`,
`RecipientPickerView:166-167`; success headings `SendKeysView:199,213`, `PaperBackupView:167`,
`ReceiveKeysView:314`, `PaperRestoreView:118`.

## 10-12. Pills, icons, motion
Pills: `PostQuantumBadge` (at `RecipientListView:83`, `IdentityListView:105`), ACTIVE
`IdentityListView:108-115`, source pill `RecipientListView:85-92`; custom dots
`WalkthroughView:109-120`. Sparkle-type "wand.and.stars" `CreateNoteView:85`. Gradient avatar
circles `RecipientListView:75`, `IdentityListView:97`, `RecentlyDeletedView:114`. No
decorative motion.

## 13. Copy
Em dashes (21): `NoteDetailView:178`, `InspectFlow:82`, `MigrateFlow:119`,
`RecipientPickerView:239`, `EncryptFlow:325,326,409`, `RecipientDetailView:102`,
`SecurityKeyPinPrompt:40`, `AddRecipientView:166`, `SignFileView:452`, `ImportIdentityView:345`,
`GenerateIdentityView:306`, `WalkthroughView:40,45,55`, `OnboardingView:299`,
`Services/FIDO/SecurityKeyTransport:92`, `Vault/VaultModels:339,341`. "→" `EncryptFlow:512`,
`MigrateFlow:222`. "Get started" `WalkthroughView:95`, `OnboardingView:187`. Slogans
`OnboardingView:176,182`, `WalkthroughView:59-60`, `SettingsView:435`. Title Case
`IdentitiesView:26`, `SettingsView:292`, `VaultModels:58-59`,
`Intents/EncryptWithPassphraseIntent:23,36`, `Intents/AgePonyShortcuts:23`. Copy bug:
`RecipientPickerView:148,220,221` mention a "Recipients tab" that doesn't exist.

## 14-15. Placeholders and states
"alice@example.com" `AddSignerView:51` (DemoSeed is DEBUG only). Generic errors
`LockSettingsView:342`, `RootView:405`, `PaperRestoreView:201`, `PassphraseModeView:337`,
`HomeView:186`. Thin empty states `IdentityListView:22-27`, `RecipientListView:19-27`; bare
`SignersView:160-163`, `SendKeysView:88`; two empty-state patterns (custom VStack vs
ContentUnavailableView at `RecentlyDeleted:34`, `IdentityDetail:144`, `RecipientDetail:106`,
`QRCodeView:42`).

## 16. Raw error text (about 75 sites)
`localizedDescription`: `SettingsView:503`, `LockSettingsView:346`, `RootView:281,408`,
`NoteDetailView:280,312`, `CreateNoteView:175`, `InspectFlow:174,197`, `MigrateFlow:278,301`,
`RecipientPickerView:417`, `EncryptFlow:578,688,842`, `DecryptFlow:290,441,466`,
`SendKeysView:276,303,310`, `PaperBackupView:222`, `PaperRestoreView:215`,
`PortabilityCommon:53`, `ReceiveKeysView:349,397,469`, `AddRecipientView:342,376,388`,
`IdentityDetailView:190`, `TextDecryptView:233,312,319`, `AddSignerView:161`,
`SignersView:228`, `SignFileView:323,340,455`, `VerifyFileView:226`,
`ImportIdentityView:206,366`, `GenerateIdentityView:362,376,485,537`,
`OnboardingView:90,123,125,145`, `AgePonyShareExtension/ShareViewController:286`,
`Services/YubiKeyDecrypt:109`. `String(describing:)`: `PassphraseModeView:340-342`,
`NoteDetailView:286`, `CreateNoteView:181`, `MigrateFlow:287,350`, `TextEncryptView:245`,
`DecryptFlow:456`. `(\(e))`: `RecipientPickerView:415`, `AddRecipientView:374`,
`ImportIdentityView:355`. Raw `\(m)`: `EncryptFlow:815-821,829-831` (from
`FileEncryptor:165,262,273,357,482,499,772`, `FileSigner:94,111,123`), `DecryptFlow:437,452-455`,
`InspectFlow:193`, `TextDecryptView:307`, `SignFileView:449-451`, `AddRecipientView:369,383,395`,
`SendKeysView:135`, `PaperRestoreView:134`, `ShareViewController:279-280`,
`FileVerifier:111,170,228`, `LanLink:44`.

## 17. Localization
All English literals in Swift. No catalog, no `.lproj`, `knownRegions = (en, Base)`, 0
`String(localized:)`. Enum rawValues as labels `IdentitiesView:26-27`,
`PassphraseModeView:27-29`, `ImportIdentityView:41-43`; `sectionTitle` in `VaultModels:48+,391+`.
Concatenations `NotesView:135`, `NoteDetailView:106`, `SettingsView:465-472`,
`PaperBackupView:173-174`, `ReceiveKeysView:316-318`, `RecentlyDeletedView:136-137`,
`MigrateFlow:80`. Manual plurals `AddRecipientView:244`, `SignersView:226`, `PaperRestoreView:116`.

## 18. Targets and hidden actions
Small: footnote Done `EncryptFlow:437-441`, `SignFileView:277-281`, `VerifyFileView:204-208`;
gradient footnote buttons `RootView:506-508,526-528,535-537`; `RecipientPickerView:170-175`;
`RecentlyDeletedView:122-124`; KeyBlock buttons `:67-87`; pencils `IdentityDetailView:39-44`,
`RecipientDetailView:36-41`; Skip `WalkthroughView:74-78`. Swipe-only: remove signer
`SignersView:109-115`; delete one trashed item `RecentlyDeletedView:126-130`.

## Bugs found
tealInk text invisible in dark mode; white on tealCore fails contrast; KeyBlock buttons may all
fire on one tap; "Recipients tab" copy; dead `PlaceholderView`; fixed 17pt share-extension label.
