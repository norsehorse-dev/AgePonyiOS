//
//  TempSweepTests.swift
//  AgePonyTests
//
//  5.1.1 (M-2): decrypted output and other plaintext folders in tmp are swept
//  at launch and on lock. The sweep removes the listed prefixes, directly in the
//  folder it is given, and nothing else.
//

import XCTest
@testable import AgePony

@MainActor
final class TempSweepTests: XCTestCase {

    private var dir: URL!

    override func setUpWithError() throws {
        // A folder of our own, so tests running beside this one keep their tmp files.
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SweepTest-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    func testPrefixesCoverThePlaintextFolders() {
        XCTAssertEqual(
            Set(TempFileCleanup.sessionPrefixes),
            ["AgePonyShare-", "AgePonyBatch-", "AgePonyFlatten-", "AgePonyIntent-", "AgePonySigners-"]
        )
    }

    func testSweepRemovesListedPrefixesAndNothingElse() throws {
        let fm = FileManager.default
        var swept: [URL] = []
        for prefix in TempFileCleanup.sessionPrefixes {
            let folder = dir.appendingPathComponent(prefix + "1A2B3C4D", isDirectory: true)
            try fm.createDirectory(at: folder, withIntermediateDirectories: true)
            try Data("plaintext".utf8).write(to: folder.appendingPathComponent("secret.txt"))
            swept.append(folder)
        }
        let looseFile = dir.appendingPathComponent("AgePonyShare-loose.txt")
        try Data("x".utf8).write(to: looseFile)
        swept.append(looseFile)

        let kept = [
            "AgePonyKeys-1234",      // key transfers: swept on lock by sweepKeyFiles
            "IncomingShare",         // claimed shares: SharedContainer's job
            "NotOurs-1234",
            "xAgePonyShare-1234",    // prefix must lead the name
            "ageponyshare-1234",     // and match its case
        ].map { dir.appendingPathComponent($0, isDirectory: true) }
        for folder in kept {
            try fm.createDirectory(at: folder, withIntermediateDirectories: true)
        }
        // Only items directly in the folder are swept.
        let nested = dir.appendingPathComponent("NotOurs-1234/AgePonyShare-inner", isDirectory: true)
        try fm.createDirectory(at: nested, withIntermediateDirectories: true)

        TempFileCleanup.sweep(prefixes: TempFileCleanup.sessionPrefixes, in: dir)

        for url in swept {
            XCTAssertFalse(fm.fileExists(atPath: url.path), url.lastPathComponent)
        }
        for url in kept {
            XCTAssertTrue(fm.fileExists(atPath: url.path), url.lastPathComponent)
        }
        XCTAssertTrue(fm.fileExists(atPath: nested.path))
    }

    func testSweepOfMissingFolderDoesNothing() {
        let missing = dir.appendingPathComponent("does-not-exist", isDirectory: true)
        TempFileCleanup.sweep(prefixes: TempFileCleanup.sessionPrefixes, in: missing)
        XCTAssertFalse(FileManager.default.fileExists(atPath: missing.path))
    }
}
