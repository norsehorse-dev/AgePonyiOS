//
//  AgePonyIntentSupport.swift
//  AgePony — App Intents
//
//  Shared helpers and the user-facing error type for AgePony's App Intents.
//

import Foundation
import AppIntents

/// Errors surfaced to Shortcuts / Siri. LocalizedError so the system shows a
/// readable message rather than a type dump.
@available(iOS 16.0, *)
enum AgePonyIntentError: Error, LocalizedError {
    case emptyPassphrase
    case couldNotReadInput
    case operationFailed(String)

    var errorDescription: String? {
        switch self {
        case .emptyPassphrase:
            return "Enter a passphrase to encrypt with."
        case .couldNotReadInput:
            return "Couldn't read the input file."
        case .operationFailed(let message):
            return message
        }
    }
}

@available(iOS 16.0, *)
enum AgePonyIntentSupport {

    /// Write an incoming IntentFile's bytes to a fresh temp file and return its
    /// URL. The original filename is preserved so the output is named sensibly
    /// (e.g. report.pdf -> report.pdf.age).
    static func stageInput(_ file: IntentFile) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgePonyIntent-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let name = file.filename.isEmpty ? "input" : file.filename
        let url = dir.appendingPathComponent(name)
        do {
            try file.data.write(to: url, options: [.atomic])
        } catch {
            throw AgePonyIntentError.couldNotReadInput
        }
        return url
    }

    /// Remove the temp directory created by `stageInput`.
    static func cleanup(_ url: URL) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: dir)
    }
}
