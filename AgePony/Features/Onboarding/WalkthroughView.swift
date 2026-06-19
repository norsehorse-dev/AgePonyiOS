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
//    • Dynamic    — paged carousel the user swipes through (or taps Next).
//    • Skippable  — a "Skip" affordance is always visible (testers asked
//                   for this explicitly).
//    • Replayable — reachable any time from Settings → "Show walkthrough
//                   again", so it isn't a one-shot.
//
//  Presentation: HomeView shows this as a full-screen cover on the first
//  unlocked launch (gated by Vault.hasSeenWalkthrough), and SettingsView
//  presents the same view on demand. Both call onFinish() to dismiss.
//
//  Styling mirrors OnboardingView.WelcomeStage — brand gradient hero,
//  white type, primary button — so first-run feels like one coherent
//  flow rather than two unrelated screens.
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
            body: "Encrypt files, notes, and text for the people you trust — using the modern age encryption format. Here's a quick tour."
        ),
        WalkthroughPage(
            symbol: "doc.badge.gearshape",
            title: "Encrypt files",
            body: "Pick any file in the Files tab, choose who can open it, and AgePony produces a .age file you can share anywhere — even over channels you don't control."
        ),
        WalkthroughPage(
            symbol: "note.text",
            title: "Notes & text",
            body: "Keep encrypted notes inside the app, or encrypt a snippet of text in the Text tab to paste into chat or email. Both stay sealed until the right person opens them."
        ),
        WalkthroughPage(
            symbol: "key",
            title: "Identities & recipients",
            body: "The Identities tab holds your keys. Add the public keys of people you send to as recipients — including age and SSH keys — so encrypting to them is one tap."
        ),
        WalkthroughPage(
            symbol: "lock.shield",
            title: "Private by design",
            body: "Everything stays on your device, gated behind Face ID or your passcode. No accounts, no cloud, no telemetry. You can replay this tour anytime from Settings."
        )
    ]

    private var isLastPage: Bool { index == pages.count - 1 }

    var body: some View {
        ZStack {
            AgePonyColors.brandGradient.ignoresSafeArea()

            VStack(spacing: 0) {
                // Skip — always visible, per the testers' request.
                HStack {
                    Spacer()
                    Button("Skip", action: onFinish)
                        .font(AgePonyTypography.bodyEmph)
                        .foregroundStyle(.white.opacity(0.9))
                        .padding(.horizontal, 20)
                        .padding(.top, 12)
                }

                // Swipeable pages. We hide the system page dots and draw our
                // own below so they don't collide with the action button.
                TabView(selection: $index) {
                    ForEach(pages.indices, id: \.self) { i in
                        WalkthroughPageView(page: pages[i])
                            .tag(i)
                    }
                }
                .tabViewStyle(.page(indexDisplayMode: .never))
                .animation(.easeInOut, value: index)

                pageIndicator
                    .padding(.bottom, 24)

                Button(isLastPage ? "Get started" : "Next") {
                    if isLastPage {
                        onFinish()
                    } else {
                        withAnimation { index += 1 }
                    }
                }
                .buttonStyle(.agePonyPrimary)
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
            }
        }
    }

    private var pageIndicator: some View {
        HStack(spacing: 8) {
            ForEach(pages.indices, id: \.self) { i in
                Circle()
                    .fill(i == index ? Color.white : Color.white.opacity(0.35))
                    .frame(width: 8, height: 8)
                    .animation(.easeInOut(duration: 0.2), value: index)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Page \(index + 1) of \(pages.count)")
    }
}

// MARK: - Page model

private struct WalkthroughPage: Identifiable {
    let id = UUID()
    let symbol: String
    let title: String
    let body: String
}

// MARK: - Single page

private struct WalkthroughPageView: View {
    let page: WalkthroughPage

    var body: some View {
        VStack(spacing: 22) {
            Spacer()
            Image(systemName: page.symbol)
                .font(.system(size: 68, weight: .light))
                .foregroundStyle(.white)
                .accessibilityHidden(true)
            Text(page.title)
                .font(AgePonyTypography.largeTitle)
                .foregroundStyle(.white)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
            Text(page.body)
                .font(AgePonyTypography.body)
                .foregroundStyle(.white.opacity(0.92))
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
