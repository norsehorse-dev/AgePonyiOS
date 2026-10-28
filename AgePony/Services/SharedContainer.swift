//
//  SharedContainer.swift
//  AgePony
//
//  KEEP IN SYNC with AgePonyShareExtension/SharedContainer.swift: the two
//  files are identical below this header (each target compiles its own copy).
//
//  App Group plumbing for the share hand-off. The share extension copies a
//  shared file (or the shared text) into the container under
//  `share/<token>/` with a manifest, and opens AgePony with
//  `agepony://share?token=<uuid>`. The extension never touches the vault or
//  the Keychain; everything that needs keys happens in the app.
//
//  5.0.1 (audit M-7, L-24, L-25):
//    - Files are copied, never read whole into memory (the extension has a
//      tight memory ceiling, and a large file used to be loaded twice).
//    - Everything staged is written with complete file protection and the
//      share directory is kept out of backups.
//    - The token must be a UUID before it becomes part of a path.
//    - Direction comes from the content: armored or binary age means decrypt,
//      anything else means encrypt, whatever the file is called.
//    - The app claims a payload as soon as it receives the token: the file
//      moves into the app's own temporary directory and the container copy is
//      gone before any flow runs. Unclaimed payloads are swept on launch, on
//      lock and by the duress wipe.
//

import Foundation

public enum SharedContainerError: Error, Equatable {
    case containerUnavailable
    case writeFailed(String)
    case readFailed(String)
    case malformedManifest
    case unknownToken
}

public struct SharedPayload: Codable, Equatable {
    public enum Direction: String, Codable, Equatable {
        /// Plaintext input — produce an encrypted .age
        case encrypt
        /// .age input — produce plaintext
        case decrypt
    }

    public enum Kind: String, Codable, Equatable {
        case file
        case text
    }

    public let token: String
    public let direction: Direction
    public let kind: Kind
    /// For file payloads: original filename, sanitized. For text payloads: nil.
    public let originalFilename: String?
    /// For text payloads: the text. nil for file payloads.
    public let textPayload: String?
    /// For file payloads: the file's name inside the token directory.
    public let fileRelativePath: String?
    /// Used by the sweep to drop abandoned payloads.
    public let createdAt: Date

    public init(
        token: String,
        direction: Direction,
        kind: Kind,
        originalFilename: String? = nil,
        textPayload: String? = nil,
        fileRelativePath: String? = nil,
        createdAt: Date = Date()
    ) {
        self.token = token
        self.direction = direction
        self.kind = kind
        self.originalFilename = originalFilename
        self.textPayload = textPayload
        self.fileRelativePath = fileRelativePath
        self.createdAt = createdAt
    }
}

/// A payload the app has taken out of the App Group container. A file now lives
/// in the app's own temporary directory; `discard()` removes it.
public struct ClaimedShare: Identifiable, Equatable {
    public let id: String
    public let direction: SharedPayload.Direction
    public let kind: SharedPayload.Kind
    public let text: String?
    public let fileURL: URL?

    public func discard() {
        guard let fileURL else { return }
        try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent())
    }
}

public enum SharedContainer {

    /// Must match the App Group identifier in both targets' entitlements.
    public static let appGroupIdentifier = "group.com.agepony.app"

    static let armorBegin = "-----BEGIN AGE ENCRYPTED FILE-----"
    static let binaryMagic = "age-encryption.org/v1\n"

    // MARK: - URLs

    public static func containerURL() throws -> URL {
        guard let url = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) else {
            throw SharedContainerError.containerUnavailable
        }
        return url
    }

    private static func shareDirURL() throws -> URL {
        var dir = try containerURL().appendingPathComponent("share", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? dir.setResourceValues(values)
        }
        return dir
    }

    /// The directory for `token`, which must be a UUID (L-24): a token is part of
    /// a path, and it arrives in a URL anyone can open.
    private static func tokenDirURL(_ token: String, create: Bool) throws -> URL {
        guard let uuid = UUID(uuidString: token) else { throw SharedContainerError.unknownToken }
        let dir = try shareDirURL().appendingPathComponent(uuid.uuidString, isDirectory: true)
        if create, !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir
    }

    // MARK: - Direction

    /// Armored or binary age means decrypt; anything else means encrypt.
    public static func direction(ofFileAt url: URL) -> SharedPayload.Direction {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return .encrypt }
        defer { try? handle.close() }
        let head = (try? handle.read(upToCount: 1024)) ?? Data()
        return direction(ofPrefix: head)
    }

    public static func direction(ofText text: String) -> SharedPayload.Direction {
        text.contains(armorBegin) ? .decrypt : .encrypt
    }

    static func direction(ofPrefix head: Data) -> SharedPayload.Direction {
        if head.starts(with: Data(binaryMagic.utf8)) { return .decrypt }
        let text = String(decoding: head, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.hasPrefix(armorBegin) ? .decrypt : .encrypt
    }

    // MARK: - Write (extension side)

    /// Stage a file. The bytes are copied file to file, never loaded whole.
    public static func writeFilePayload(sourceFileURL: URL, originalFilename: String) throws -> SharedPayload {
        let token = UUID().uuidString
        let dir = try tokenDirURL(token, create: true)
        let safeName = sanitizedFilename(originalFilename)
        let destURL = dir.appendingPathComponent(safeName)
        let direction: SharedPayload.Direction
        do {
            let scoped = sourceFileURL.startAccessingSecurityScopedResource()
            defer { if scoped { sourceFileURL.stopAccessingSecurityScopedResource() } }
            try FileManager.default.copyItem(at: sourceFileURL, to: destURL)
            try protect(destURL)
            direction = self.direction(ofFileAt: destURL)
        } catch {
            try? FileManager.default.removeItem(at: dir)
            throw SharedContainerError.writeFailed(failure(String(localized: "Couldn't copy the shared file into AgePony."), error))
        }
        let payload = SharedPayload(
            token: token,
            direction: direction,
            kind: .file,
            originalFilename: safeName,
            fileRelativePath: safeName
        )
        try writeManifest(payload: payload)
        return payload
    }

    /// Stage text. It lives in the manifest itself.
    public static func writeTextPayload(text: String) throws -> SharedPayload {
        let token = UUID().uuidString
        _ = try tokenDirURL(token, create: true)
        let payload = SharedPayload(
            token: token,
            direction: direction(ofText: text),
            kind: .text,
            textPayload: text
        )
        try writeManifest(payload: payload)
        return payload
    }

    private static func writeManifest(payload: SharedPayload) throws {
        let dir = try tokenDirURL(payload.token, create: true)
        let manifestURL = dir.appendingPathComponent("manifest.json")
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(payload)
            try data.write(to: manifestURL, options: [.atomic, .completeFileProtection])
        } catch {
            try? FileManager.default.removeItem(at: dir)
            throw SharedContainerError.writeFailed(failure(String(localized: "Couldn't save the shared item."), error))
        }
    }

    /// A finished sentence for `writeFailed`/`readFailed`: `message`, or a
    /// plainer one for a full disk, plus the error's domain and code for a
    /// report. Never the error's own text (5.1.0, U5).
    static func failure(_ message: String, _ error: Error) -> String {
        if let cocoa = error as? CocoaError, cocoa.code == .fileWriteOutOfSpace {
            return String(localized: "There isn't enough free storage on this iPhone.")
        }
        guard type(of: error) is NSError.Type else { return message }
        let ns = error as NSError
        return "\(message) (\(ns.domain) \(ns.code))"
    }

    private static func protect(_ url: URL) throws {
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    }

    // MARK: - Read (app side)

    public static func readPayload(token: String) throws -> SharedPayload {
        let dir = try tokenDirURL(token, create: false)
        let manifestURL = dir.appendingPathComponent("manifest.json")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            throw SharedContainerError.unknownToken
        }
        do {
            let data = try Data(contentsOf: manifestURL)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let payload = try decoder.decode(SharedPayload.self, from: data)
            guard payload.token.uppercased() == token.uppercased() else { throw SharedContainerError.malformedManifest }
            return payload
        } catch {
            throw SharedContainerError.malformedManifest
        }
    }

    /// Take a payload out of the container (M-7): a file moves into the app's own
    /// temporary directory, text comes along in memory, and the container copy
    /// is deleted before any flow sees it.
    public static func claim(token: String) throws -> ClaimedShare {
        let payload = try readPayload(token: token)
        let dir = try tokenDirURL(token, create: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        switch payload.kind {
        case .text:
            return ClaimedShare(id: payload.token, direction: payload.direction, kind: .text,
                                text: payload.textPayload ?? "", fileURL: nil)
        case .file:
            guard let rel = payload.fileRelativePath else { throw SharedContainerError.malformedManifest }
            let source = dir.appendingPathComponent(sanitizedFilename(rel))
            let destDir = claimedDirectory().appendingPathComponent(UUID().uuidString, isDirectory: true)
            let dest = destDir.appendingPathComponent(sanitizedFilename(payload.originalFilename ?? rel))
            do {
                try FileManager.default.createDirectory(at: destDir, withIntermediateDirectories: true)
                try FileManager.default.moveItem(at: source, to: dest)
                try? protect(dest)
            } catch {
                try? FileManager.default.removeItem(at: destDir)
                throw SharedContainerError.readFailed(failure(String(localized: "Couldn't move the shared file into AgePony."), error))
            }
            return ClaimedShare(id: payload.token, direction: payload.direction, kind: .file,
                                text: nil, fileURL: dest)
        }
    }

    /// Tokens of payloads still waiting, newest first, no older than `maxAge`.
    /// Picks a share up when the extension couldn't open the app.
    public static func pendingTokens(maxAge: TimeInterval) -> [String] {
        guard let shareDir = try? shareDirURL(),
              let children = try? FileManager.default.contentsOfDirectory(
                at: shareDir, includingPropertiesForKeys: [.creationDateKey], options: [.skipsHiddenFiles])
        else { return [] }
        let cutoff = Date().addingTimeInterval(-maxAge)
        return children
            .compactMap { url -> (String, Date)? in
                guard UUID(uuidString: url.lastPathComponent) != nil,
                      let created = try? url.resourceValues(forKeys: [.creationDateKey]).creationDate,
                      created >= cutoff else { return nil }
                return (url.lastPathComponent, created)
            }
            .sorted { $0.1 > $1.1 }
            .map(\.0)
    }

    /// Where claimed files wait while a flow uses them.
    public static func claimedDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("IncomingShare", isDirectory: true)
    }

    /// Delete every claimed file (on launch and on lock).
    public static func removeClaimed() {
        try? FileManager.default.removeItem(at: claimedDirectory())
    }

    // MARK: - Cleanup

    /// Delete a single token's directory.
    public static func cleanup(token: String) {
        guard let dir = try? tokenDirURL(token, create: false) else { return }
        try? FileManager.default.removeItem(at: dir)
    }

    /// Sweep payloads older than `maxAge` that nobody claimed.
    public static func sweepStale(maxAge: TimeInterval = 3600) {
        guard let shareDir = try? shareDirURL() else { return }
        let cutoff = Date().addingTimeInterval(-maxAge)
        guard let children = try? FileManager.default.contentsOfDirectory(
            at: shareDir,
            includingPropertiesForKeys: [.creationDateKey],
            options: [.skipsHiddenFiles]
        ) else { return }
        for child in children {
            let values = try? child.resourceValues(forKeys: [.creationDateKey])
            if let created = values?.creationDate, created < cutoff {
                try? FileManager.default.removeItem(at: child)
            }
        }
    }

    /// Delete every payload, whatever its age (lock and duress, M-7 / M-8).
    public static func removeAll() {
        guard let shareDir = try? shareDirURL() else { return }
        try? FileManager.default.removeItem(at: shareDir)
    }

    // MARK: - Helpers

    static func sanitizedFilename(_ raw: String) -> String {
        // Only the last path component, with nothing a path resolver could use.
        let last = (raw as NSString).lastPathComponent
        var clean = last.replacingOccurrences(of: "/", with: "_")
        clean = clean.replacingOccurrences(of: ":", with: "_")
        clean = String(clean.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        clean = clean.trimmingCharacters(in: .whitespaces)
        if clean.isEmpty || clean == "." || clean == ".." || clean.hasPrefix(".") {
            return "payload" + (clean.isEmpty || clean == "." || clean == ".." ? "" : clean)
        }
        return String(clean.prefix(200))
    }
}
