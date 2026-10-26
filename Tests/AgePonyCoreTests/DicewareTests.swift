//
//  DicewareTests.swift
//  AgePonyCoreTests
//
//  Tests the diceware generator and EFF-format parser against Android's
//  `Diceware.kt` behavior. The real 7776-word list is an app resource, so these
//  use a small synthetic list; only the list-independent logic is under test.
//

import XCTest
@testable import AgePonyCore

final class DicewareTests: XCTestCase {

    private let words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]

    func testGenerateProducesRequestedWordCount() throws {
        let phrase = try Diceware.generate(words: words, wordCount: 5, separator: "-")
        XCTAssertEqual(phrase.split(separator: "-").count, 5)
        for w in phrase.split(separator: "-") {
            XCTAssertTrue(words.contains(String(w)))
        }
    }

    func testWordCountIsClampedToRange() throws {
        let low = try Diceware.generate(words: words, wordCount: 1)
        XCTAssertEqual(low.split(separator: "-").count, Diceware.minWordCount)
        let high = try Diceware.generate(words: words, wordCount: 99)
        XCTAssertEqual(high.split(separator: "-").count, Diceware.maxWordCount)
    }

    func testGenerateRejectsTinyList() {
        XCTAssertThrowsError(try Diceware.generate(words: ["only"])) { error in
            XCTAssertEqual(error as? Diceware.DicewareError, .listTooSmall)
        }
    }

    func testEntropyBits() {
        XCTAssertEqual(Diceware.entropyBits(listSize: 7776, wordCount: 6), 77.549, accuracy: 0.01)
        XCTAssertEqual(Diceware.entropyBits(listSize: 7776, wordCount: 1), 12.925, accuracy: 0.01)
        XCTAssertEqual(Diceware.entropyBits(listSize: 1, wordCount: 6), 0)
    }

    func testParseWordlistTabFormat() throws {
        let text = "11111\tabacus\n11112\tabdomen\n# comment\n\n11113\tabdominal\n"
        XCTAssertEqual(try Diceware.parseWordlist(text), ["abacus", "abdomen", "abdominal"])
    }

    func testParseWordlistPlainWords() throws {
        XCTAssertEqual(try Diceware.parseWordlist("apple\nberry\ncherry"), ["apple", "berry", "cherry"])
    }

    func testParseWordlistRejectsBadEntry() {
        XCTAssertThrowsError(try Diceware.parseWordlist("11111\tAbacus\n11112\tabdomen")) { error in
            guard case .unusableEntry = (error as? Diceware.DicewareError) else {
                return XCTFail("expected .unusableEntry")
            }
        }
    }
}
