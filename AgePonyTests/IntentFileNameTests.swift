//
//  IntentFileNameTests.swift
//  AgePonyTests
//
//  5.1.1 (M-5): the Shortcuts action stages its input under the file's name.
//  The name is reduced to a plain last component, and cleanup only removes a
//  temp folder the action made, never a path built from the name.
//

import XCTest
@testable import AgePony

@MainActor
final class IntentFileNameTests: XCTestCase {

    func testNameIsReducedToALastComponent() {
        XCTAssertEqual(AgePonyIntentSupport.safeName("report.pdf"), "report.pdf")
        XCTAssertEqual(AgePonyIntentSupport.safeName(""), "input")
        for hostile in ["../../Library/Application Support/AgePony/x", "a/b.txt", "..", ".", "/", "../"] {
            let name = AgePonyIntentSupport.safeName(hostile)
            XCTAssertFalse(name.contains("/"), hostile)
            XCTAssertNotEqual(name, "..", hostile)
            XCTAssertNotEqual(name, ".", hostile)
            XCTAssertFalse(name.isEmpty, hostile)
        }
    }

    func testCleanupRemovesOnlyItsOwnFolder() throws {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory
        let own = tmp.appendingPathComponent(AgePonyIntentSupport.stagingPrefix + "test", isDirectory: true)
        let other = tmp.appendingPathComponent("NotOurs-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try fm.createDirectory(at: own, withIntermediateDirectories: true)
        try fm.createDirectory(at: other, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: other) }

        AgePonyIntentSupport.removeTempFolder(other, prefix: AgePonyIntentSupport.stagingPrefix)
        XCTAssertTrue(fm.fileExists(atPath: other.path), "a folder without our prefix stays")

        let nested = own.appendingPathComponent(AgePonyIntentSupport.stagingPrefix + "inner", isDirectory: true)
        AgePonyIntentSupport.removeTempFolder(nested, prefix: AgePonyIntentSupport.stagingPrefix)
        XCTAssertTrue(fm.fileExists(atPath: own.path), "only folders directly in tmp are removed")

        AgePonyIntentSupport.removeTempFolder(own, prefix: AgePonyIntentSupport.stagingPrefix)
        XCTAssertFalse(fm.fileExists(atPath: own.path))
    }
}
