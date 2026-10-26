//
//  Diceware.swift
//  AgePonyCore
//
//  Diceware passphrase generation. Mirrors Android's `core/crypto/Diceware.kt`.
//
//  A passphrase is a number of words drawn uniformly and independently from a
//  word list, so its strength is exactly `wordCount * log2(listSize)` and does
//  not depend on the words themselves. With the EFF long list (7776 words) each
//  word is worth 12.925 bits, so six words is 77.5 bits.
//
//  This type holds no list of its own: the caller supplies the words, which
//  keeps AgePonyCore free of resources and lets the app own where the list came
//  from (and hide the generator when the list is absent).
//

import Foundation

public enum Diceware {

    public static let defaultWordCount = 6
    public static let minWordCount = 4
    public static let maxWordCount = 12
    public static let defaultSeparator = "-"

    /// Size of the EFF long wordlist, for callers that want to check they loaded
    /// the real thing rather than a shrunken list that would silently weaken
    /// every passphrase.
    public static let effLongListSize = 7776

    public enum DicewareError: Error, Equatable {
        case listTooSmall
        case unusableEntry(String)
        case emptyList
    }

    /// Bits of entropy in a passphrase of `wordCount` words drawn from a list of
    /// `listSize`.
    public static func entropyBits(listSize: Int, wordCount: Int) -> Double {
        if listSize < 2 || wordCount < 1 { return 0 }
        return Double(wordCount) * log2(Double(listSize))
    }

    /// Draw `wordCount` words from `words`, uniformly and with replacement.
    /// `Int.random(in:)` is CSPRNG-backed and unbiased; `random % size` would
    /// quietly favor the front of the list and cost entropy. Words may repeat,
    /// which is what makes the strength calculation exact.
    public static func generate(
        words: [String],
        wordCount: Int = defaultWordCount,
        separator: String = defaultSeparator
    ) throws -> String {
        guard words.count >= 2 else { throw DicewareError.listTooSmall }
        let count = min(max(wordCount, minWordCount), maxWordCount)
        return (0..<count)
            .map { _ in words[Int.random(in: 0..<words.count)] }
            .joined(separator: separator)
    }

    /// Read a word list in EFF format: one entry per line, either
    /// `11111<tab>abacus` or just the word. Blank lines and `#` comments are
    /// skipped, and anything that is not a plain lowercase a-z word is rejected
    /// rather than silently skipped, so a mangled or truncated file is caught at
    /// load time instead of quietly shrinking the keyspace.
    public static func parseWordlist(_ text: String) throws -> [String] {
        var words: [String] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let word = substringAfterLast(substringAfterLast(line, "\t"), " ")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !word.isEmpty, word.allSatisfy({ $0 >= "a" && $0 <= "z" }) else {
                throw DicewareError.unusableEntry(line)
            }
            words.append(word)
        }
        guard words.count >= 2 else { throw DicewareError.emptyList }
        return words
    }

    private static func substringAfterLast(_ s: String, _ separator: Character) -> String {
        if let idx = s.lastIndex(of: separator) {
            return String(s[s.index(after: idx)...])
        }
        return s
    }
}
