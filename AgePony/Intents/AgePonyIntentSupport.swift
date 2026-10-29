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
            return String(localized: "Enter a passphrase to encrypt with.")
        case .couldNotReadInput:
            return String(localized: "Couldn't read the input file.")
        case .operationFailed(let message):
            return message
        }
    }
}

@available(iOS 16.0, *)
enum AgePonyIntentSupport {

    static let stagingPrefix = "AgePonyIntent-"

    /// An incoming file written to its own temp folder. `cleanup` removes that
    /// folder and nothing else.
    struct Staged {
        let folder: URL
        let input: URL
    }

    /// The name to stage an incoming file under: its last path component only,
    /// with nothing a path resolver could use (5.1.1, M-5). The original name is
    /// kept otherwise, so the output is named sensibly (report.pdf -> report.pdf.age).
    static func safeName(_ raw: String) -> String {
        raw.isEmpty ? "input" : SharedContainer.sanitizedFilename(raw)
    }

    /// Write an incoming IntentFile's bytes to a fresh temp folder.
    static func stageInput(_ file: IntentFile) throws -> Staged {
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent(stagingPrefix + String(UUID().uuidString.prefix(8)), isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)

        let url = folder.appendingPathComponent(safeName(file.filename), isDirectory: false)
        // Belt and braces: the joined path must still sit directly in the folder.
        // Not standardized: the file doesn't exist yet, and standardizing only
        // drops /private from paths that exist, so the two would never match.
        guard url.deletingLastPathComponent().path == folder.path else {
            try? FileManager.default.removeItem(at: folder)
            throw AgePonyIntentError.couldNotReadInput
        }
        do {
            try file.data.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
        } catch {
            try? FileManager.default.removeItem(at: folder)
            throw AgePonyIntentError.couldNotReadInput
        }
        return Staged(folder: folder, input: url)
    }

    /// Remove the folder `stageInput` made. Never a path derived from the file
    /// name (5.1.1, M-5): only a folder directly in tmp whose name we gave it.
    static func cleanup(_ staged: Staged) {
        removeTempFolder(staged.folder, prefix: stagingPrefix)
    }

    static func removeTempFolder(_ folder: URL, prefix: String) {
        let tmp = FileManager.default.temporaryDirectory.standardizedFileURL.path
        let f = folder.standardizedFileURL
        guard f.deletingLastPathComponent().path == tmp, f.lastPathComponent.hasPrefix(prefix) else { return }
        try? FileManager.default.removeItem(at: f)
    }
}
