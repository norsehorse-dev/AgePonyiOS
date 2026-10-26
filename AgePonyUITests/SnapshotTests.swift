//
//  SnapshotTests.swift
//  AgePonyUITests
//
//  Drives the app through the screens used for App Store screenshots. Run by
//  fastlane snapshot through the AgePonySnapshots scheme; the plain AgePony
//  scheme skips it, so `xcodebuild test` never runs it.
//
//  The app is launched with -seedDemoVault, which opens a fresh, unlocked demo
//  vault (AgePony/Debug/DemoSeed.swift). Rows are found by DemoSeed's names
//  ("Personal", "Quantum-safe", "Recovery phrase"), so keep the two in sync.
//  AgePony is English only, so screen chrome is found by its visible labels.
//

import XCTest

final class SnapshotTests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testCaptureScreenshots() throws {
        let app = XCUIApplication()
        setupSnapshot(app)
        app.launchArguments += ["-seedDemoVault"]
        // Should iOS ask for the local network on the Receive keys screen.
        addUIInterruptionMonitor(withDescription: "Local network") { alert in
            let allow = alert.buttons["Allow"]
            if allow.exists { allow.tap(); return true }
            return false
        }
        app.launch()

        // 1. Files, the landing tab.
        XCTAssertTrue(app.tabBars.buttons["Files"].waitForExistence(timeout: 30))
        snapshot("01Files")

        // 2. Identities.
        app.tabBars.buttons["Identities"].tap()
        XCTAssertTrue(app.staticTexts["Quantum-safe"].waitForExistence(timeout: 10))
        snapshot("02Identities")

        // 3. Settings > Receive keys from another device: the QR code and its code.
        app.tabBars.buttons["Settings"].tap()
        let receive = app.buttons["Receive keys from another device"]
        scrollTo(receive, in: app)
        receive.tap()
        XCTAssertTrue(app.navigationBars["Receive keys"].waitForExistence(timeout: 10))
        app.tap() // lets the interruption monitor run if an alert came up
        sleep(3) // the QR code renders off the main thread
        snapshot("03ReceiveKeys")
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // 4. Identities > Personal > Paper backup.
        app.tabBars.buttons["Identities"].tap()
        XCTAssertTrue(app.staticTexts["Personal"].waitForExistence(timeout: 10))
        app.staticTexts["Personal"].tap()
        XCTAssertTrue(app.navigationBars["Personal"].waitForExistence(timeout: 10))
        let paper = app.buttons["Paper backup"]
        scrollTo(paper, in: app)
        paper.tap()
        XCTAssertTrue(app.navigationBars["Paper backup"].waitForExistence(timeout: 10))
        snapshot("04PaperBackup")

        // 5. Notes.
        app.tabBars.buttons["Notes"].tap()
        XCTAssertTrue(app.staticTexts["Recovery phrase"].waitForExistence(timeout: 10))
        snapshot("05Notes")
    }

    /// Swipe up until `element` is on screen and tappable.
    @MainActor
    private func scrollTo(_ element: XCUIElement, in app: XCUIApplication, attempts: Int = 8) {
        var tries = 0
        while !(element.exists && element.isHittable) && tries < attempts {
            app.swipeUp()
            tries += 1
        }
        XCTAssertTrue(element.exists && element.isHittable, "Couldn't scroll to \(element)")
    }
}
