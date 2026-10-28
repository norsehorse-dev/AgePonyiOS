//
//  WalkthroughView.swift
//  AgePony
//
//  Implements the testers' "User Onboarding Dynamic Walkthrough" request.
//  This is distinct from OnboardingView: OnboardingView bootstraps the
//  vault and creates the first identity (a required setup gate), whereas
//  this is a swipeable feature tour that orients a new user around what
//  each tab does. It is:
//
//    • Dynamic:    paged carousel the user swipes through (or taps Next).
//    • Skippable:  a "Skip" affordance is always visible (testers asked
//                   for this explicitly).
//    • Replayable: reachable any time from Settings, "Show walkthrough
//                   again", so it isn't a one-shot.
//
//  Presentation: HomeView shows this as a full-screen cover on the first
//  unlocked launch (gated by Vault.hasSeenWalkthrough), and SettingsView
//  presents the same view on demand. Both call onFinish() to dismiss.
//
//  Styling mirrors OnboardingView.WelcomeStage (plain system background,
//  default text colors, one primary button), with system page dots and a
//  toolbar Skip.
//

import SwiftUI

struct WalkthroughView: View {

    /// Called when the user finishes the last page, taps Skip, or taps
    /// Done. The presenter is responsible for marking it seen / dismissing.
    let onFinish: () -> Void

    @State private var index: Int = 0

    private let pages: [WalkthroughPage] = [
        WalkthroughPage(
            symbol: "shield.lefthalf.filled",
            title: "Welcome to AgePony",
            body: "Encrypt files, notes, and text for the people you trust, using the age encryption format. Here's a quick tour."
        ),
        WalkthroughPage(
            symbol: "doc.badge.gearshape",
            title: "Encrypt files",
            body: "Pick any file in the Files tab, choose who can open it, and AgePony makes a .age file you can share anywhere, even over channels you don't control."
        ),
        WalkthroughPage(
            symbol: "note.text",
            title: "Notes and text",
            body: "Keep encrypted notes inside the app, or encrypt a snippet of text in the Text tab to paste into chat or email. Both stay sealed until the right person opens them."
        ),
        WalkthroughPage(
            symbol: "key",
            title: "Identities and recipients",
            body: "The Identities tab holds your keys. Add the public keys of people you send to as recipients (age and SSH keys both work), so encrypting to them is one tap."
        ),
        WalkthroughPage(
            symbol: "lock.shield",
            title: "Your keys stay here",
            body: "Everything stays on your device, behind Face ID or your passcode. There's no account, and nothing is sent to a server. You can replay this tour anytime from Settings."
        )
    ]

    private var isLastPage: Bool { index == pages.count - 1 }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // System page dots; the background keeps them visible on a
                // light screen.
                TabView(selection: $index) {
                    ForEach(pages.indices, id: \.self) { i in
                        WalkthroughPageView(page: pages[i])
                            .tag(i)
                    }
                }
                .tabViewStyle(.page(indexDisplayMode: .always))
                .indexViewStyle(.page(backgroundDisplayMode: .always))
                .animation(.easeInOut, value: index)

                Group {
                    if isLastPage {
                        Button("Continue", action: onFinish)
                    } else {
                        Button("Next") {
                            withAnimation { index += 1 }
                        }
                    }
                }
                .buttonStyle(.agePonyPrimary)
                .padding(.horizontal, 32)
                .padding(.top, 16)
                .padding(.bottom, 40)
            }
            .background(Color(.systemBackground))
            .toolbar {
                // Skip is always visible, per the testers' request.
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Skip", action: onFinish)
                }
            }
        }
    }
}

// MARK: - Page model

private struct WalkthroughPage: Identifiable {
    let id = UUID()
    let symbol: String
    let title: LocalizedStringResource
    let body: LocalizedStringResource
}

// MARK: - Single page

private struct WalkthroughPageView: View {
    let page: WalkthroughPage

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            // No hero symbol (5.1.0, U4): the title and text carry the page.
            Text(page.title)
                .font(AgePonyTypography.title)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
            Text(page.body)
                .font(AgePonyTypography.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
