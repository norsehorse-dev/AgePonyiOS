# AgePony 5.1.0 UI plan: no generated look (Rev 1)

Restyle of both apps to the human-grade-app-ui rules. Works from the two inventories:
`AgePony_5.1.0_UI_Inventory_iOS.md` (this repo) and `AgePony_5.1.0_UI_Inventory_Android.md`
(Android repo). Items are U1 to U9 so they don't collide with the shared items 1 to 5, C1 or
E1 to E9.

Last updated: 2026-10-26 (Rev 1). Decided: the restyle is in 5.1.0, and the questions at the end are answered.

---

## Where the apps stand

Both apps show the cluster people read as generated, not one stray tell:

- **iOS:** a full-screen teal gradient on the lock, welcome, privacy cover and share screens;
  purple-magenta for errors next to two other reds; tinted bordered cards inside Form rows; a
  large teal SF Symbol above nearly every stage (24); ALL CAPS "ACTIVE" and source pills; slogans
  ("Zero accounts. Zero cloud. Zero telemetry.", "Modern file encryption."); "Get started"; 21 em
  dashes; nav bars hidden on three tabs with titles drawn in content.
- **Android:** no TopAppBar and no BackHandler anywhere (system back exits the app from every
  sub-screen); a half-pinned color scheme, so the nav indicator, dialogs, menus and switches fall
  back to M3 lavender; the untouched template Type.kt; about 35 Unicode glyphs (✓ ⚠ ↗ ›) standing in
  for icons; gradient rainbow avatars; 6 bottom tabs; 18 em dashes.
- **Both:** raw error text in about 75 (iOS) and 71 (Android) places, and no localization at all
  (all strings hard-coded English; Android strings.xml has 2 entries, iOS has no catalog).

The raw-error habit is the same one that hid "KeychainError error 0" for two releases (C1), so
U5 is a reliability fix as much as a style one.

## Shared direction (both platforms)

- **Surfaces neutral.** iOS system grouped backgrounds; Android neutral grays in place of the
  teal-tinted dark surfaces (#06302F, TealInk). No gradients anywhere.
- **One accent, used for actions.** Teal for the primary action, selection, links and focus
  only. Light: #0E7D7A (white text on it is about 5:1; #14B8B0 is about 2.4:1 and fails). Dark:
  #38CFE8 with dark text. No teal hero icons, row icons, headings or paragraphs.
- **Status colors carry state only:** one red for failure and destructive (system red on iOS,
  a pinned error role on Android; the magenta #C046DC goes), green for a match, amber for a
  warning. Icon plus word, never a whole paragraph or a tinted capsule.
- **Type:** platform text styles only, 3 to 4 per screen, regular body rows, headings at least
  as large as their rows. Monospace only for keys, fingerprints, digests, file names, codes.
- **Lists are lists.** Form/List on iOS; rows with dividers or ListItem on Android. Key and file
  details become rows, not tinted cards.
- **Platform chrome.** iOS: a nav bar with a title on every tab and screen, system sheets,
  ContentUnavailableView for empty states. Android: TopAppBar on every screen, BackHandler,
  imePadding, insets, at most 5 bottom tabs.
- **Copy.** No em dashes, slogans, "Get started", Title Case labels, "Danger zone". Plain
  labels that name the action.

## Work, in the skill's order

### U1. Strings into resources (both, English only)

Every user-visible string into a String Catalog (iOS `Localizable.xcstrings`) or `strings.xml`
with `plurals` (Android), fixing em dashes, slogans, Title Case and hand-built plurals as each
string moves. No new locales in 5.1.0; this is what makes them possible later.

- iOS: all Swift literals, enum rawValues used as labels, `sectionTitle`, concatenations and
  the 3 manual plurals (inventory section 17), App Intents titles.
- Android: 405 `Text("...")` literals, data-list copy (Help, SecurityInfo, Licenses,
  Onboarding), tab labels, 12 plurals, `replaceFirstChar{uppercase}` cases.
- Multi-agent: one agent per screen group, each given the existing in-app terms as a glossary;
  then a script checks every reference resolves and no literal is left.

### U2. Theme and shared components

- iOS `DesignSystem`: colors as asset colors with light and dark values (fixes tealInk text in
  dark mode); buttons on system styles (`.borderedProminent` tinted, `.bordered`, role
  destructive) with no stacked tint and border; one status view (icon plus word); one verdict
  row; KeyBlock as plain rows with mono value and `.borderless` buttons (fixes the multi-fire
  tap); PostQuantumBadge as an icon plus word.
- Android: pin every color role (surfaceContainer*, secondaryContainer, error roles, inverse,
  scrim); real Type.kt; delete the purple_*/teal_* leftovers; light windowBackground; a shared
  components file on the HashPony pattern (`SectionHeader`, `ListDivider`, `StatusText`,
  `VerdictPanel`, `ChoiceField`, `PrimaryAction`/`SecondaryAction`/`QuietAction`, `EmptyState`,
  `ErrorText`), replacing the per-file copies.

### U3. Navigation chrome

- iOS: nav bars back on Files, Text and Settings; titles on Notes and Identities; Files and
  Text hubs become Lists of rows; pick and done stages become Forms; the walkthrough uses system
  page dots and a toolbar Skip; the scanner in AddRecipientView gets a NavigationStack and
  toolbar Cancel like the other two.
- Android: TopAppBar on every screen with the back arrow driving sub-screens and flows,
  BackHandler throughout (fixes back exiting the app), the 20 in-content "‹ Back" buttons
  removed, imePadding and scrolling on every screen with fields, insets on VaultGate and
  onboarding, 5 bottom tabs (Q3).

### U4. Screens

- Cards to rows (iOS KeyBlock, FileInfoCard and its duplicate, EncryptFlow radio cards, the
  ScrollView screens in DecryptFlow and InspectFlow).
- Remove the 24 hero icons and the 96dp onboarding icon circles; gradient screens become plain
  system screens.
- Pills to icon plus word; ALL CAPS words to sentence case; glyphs (✓ ⚠ ↗ › → •) to SF Symbols /
  Material Symbols; the Android verdict stops keying color off a "⚠" prefix.
- Segmented controls whose labels will grow (iOS PassphraseModeView, IdentitiesView,
  ImportIdentityView) to menus or list sections; Android fake segmented Password/PIN to a
  ChoiceField.
- Whole rows toggle (10 Android switch rows, checkbox and radio rows); 48dp targets; iOS small
  footnote buttons and pencils to toolbar or standard buttons; swipe-only actions get a visible
  button (iOS remove signer, delete one trashed item).
- Avatars (Q4).
- Spacing on the 4pt/4dp grid; two corner radii.

### U5. Errors and states

- No raw error text. Each platform maps failures to a plain message from resources. Where a
  code helps a report (OSStatus, NFC status word), it's shown as a code after the message, as
  C1 now does, never as an exception's own text or class name.
- Core wrappers that build "Decrypt failed: ${e.message}" return typed errors instead.
- Specific empty states (what an identity or recipient is, and how to add one), one empty-state
  pattern per platform, and a "found none" message for the GitHub fetch.
- Android deletes on Recipients and Notes get a confirmation.

### U6. Bugs found by the inventory

iOS: tealInk text in dark mode; primary button contrast; KeyBlock multi-fire; "Recipients tab"
copy; dead PlaceholderView; fixed 17pt share-extension label. Android: back exits the app;
keyboard covers fields; dark splash in light mode; "1 identities"; duplicate copy confirmation on
API 33+; version fallback "1.0" hard-coded.

### U7. Checks

Every string reference resolves; no user-visible literal left in Swift or Kotlin (script);
`grep -rhoE "[0-9]+\.dp"` and the SwiftUI equivalents on grid; no stale component names;
`xcodebuild test` and `./gradlew :app:compileDebugKotlin testDebugUnitTest` green.

### U8. Independent review

A separate agent that did no restyle work reviews the source, and screenshots when there are
some, against the skill's reviewer checklist and a compile check. Fix what it finds.

### U9. Device pass and screenshots

NorseHorse builds and looks at both apps on devices, light and dark. Commit only after he says
it looks right, with no AI attribution. New captioned store screenshots and unframed F-Droid
screenshots afterwards, since every screen changes.

## RC placement (proposed, Q1)

The restyle touches every screen on both platforms. Building items 1, 3 and E6 on the old
components and then restyling them is double work, so the proposal is foundations first:

- RC1: C1 (if it doesn't ship as 5.0.2, Q2) plus U1 to U3 and U6 on both platforms.
- RC2: U4, U5 plus items 1 and 3, E6 and E7, built on the new components.
- RC3: E8 (CryptoKit and Enclave ML-KEM) and item 2 if its hardware has arrived.
- U8 and U9 run at the end of each RC.

One RC at a time.

## Decisions (Oct 26 2026)

- **Q1 RC order:** foundations first, as above. RC1 = C1 plus U1 to U3 and U6 on both
  platforms; RC2 = U4, U5, items 1 and 3, E6, E7; RC3 = E8 and item 2.
- **Q2 C1:** ships in 5.1.0 RC1 only, no 5.0.2.
- **Q3 Android tabs:** Sign folds into Files, as on iOS. Five tabs.
- **Q4 avatars:** flat circle with the same per-key hue and initials, no gradient.
