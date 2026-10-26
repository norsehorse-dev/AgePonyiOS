//
//  Wordlist.swift
//  AgePony
//
//  Loads the bundled EFF long diceware word list (7776 words) for the passphrase
//  generator. Mirrors Android's `vault/Wordlist.kt`: the list is an app resource,
//  and a missing or malformed file yields an empty list so the generator simply
//  does not appear rather than falling back to a weaker list.
//
//  To enable the generator, add `eff_large_wordlist.txt` (the EFF long list,
//  CC BY 3.0 US) to the app target and credit it in NOTICE. Without it the
//  diceware code is inert, matching Android's current state.
//

import Foundation
import AgePonyCore

enum Wordlist {
    static let resourceName = "eff_large_wordlist"

    private static var cached: [String]?

    /// The EFF long list, or an empty list if the resource is missing or does not
    /// look like the real 7776-word list. Callers hide the generator when empty.
    static func effLong() -> [String] {
        if let cached { return cached }
        let loaded: [String]
        if let url = Bundle.main.url(forResource: resourceName, withExtension: "txt"),
           let text = try? String(contentsOf: url, encoding: .utf8),
           let words = try? Diceware.parseWordlist(text),
           words.count == Diceware.effLongListSize {
            loaded = words
        } else {
            loaded = []
        }
        cached = loaded
        return loaded
    }
}
