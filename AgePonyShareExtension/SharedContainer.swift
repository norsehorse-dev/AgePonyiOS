//
//  SharedContainer.swift
//  AgePonyShareExtension
//
//  ┌─────────────────────────────────────────────────────────────────┐
//  │ KEEP IN SYNC with AgePony/Services/SharedContainer.swift.       │
//  │ The two files MUST be byte-identical except for this header.    │
//  │ Xcode 16's FileSystemSynchronizedRootGroup makes auto-including │
//  │ a single file across multiple targets awkward, so we duplicate  │
//  │ the source. Any change to one MUST be mirrored to the other.    │
//  └─────────────────────────────────────────────────────────────────┘
//
//  App Group container plumbing. The share extension drops shared
//  payloads (files or text) into the container under
//  `share/<token>/payload.<ext>` and writes a sidecar JSON describing
//  what to do with them. The main app, on receiving an `agepony://share?
//  token=<uuid>` URL via .onOpenURL, reads back the same files and
//  routes to the appropriate flow.
//
//  Files are cleaned up by the main app after the flow finishes — the
//  extension never deletes its own writes because by the time the main
//  app launches, the extension's process is gone.
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
        case encrypt
        case decrypt
    }

    public enum Kind: String, Codable, Equatable {
        case file
        case text
    }

    public let token: String
    public let direction: Direction
    public let kind: Kind
    public let originalFilename: String?
    public let textPayload: String?
    public let fileRelativePath: String?
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

public enum SharedContainer {

    public static let appGroupIdentifier = "group.com.agepony.app"

    public static func containerURL() throws -> URL {
        guard let url = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) else {
            throw SharedContainerError.containerUnavailable
        }
        return url
    }

    private static func shareDirURL() throws -> URL {
        let dir = try containerURL().appendingPathComponent("share", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir
    }

    private static func tokenDirURL(_ token: String) throws -> URL {
        let dir = try shareDirURL().appendingPathComponent(token, isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir
    }

    public static func writeFilePayload(
        direction: SharedPayload.Direction,
        sourceFileURL: URL,
        originalFilename: String
    ) throws -> SharedPayload {
        let token = UUID().uuidString
        let dir = try tokenDirURL(token)
        let safeName = sanitizedFilename(originalFilename)
        let destURL = dir.appendingPathComponent(safeName)

        do {
            let scoped = sourceFileURL.startAccessingSecurityScopedResource()
            defer { if scoped { sourceFileURL.stopAccessingSecurityScopedResource() } }
            let bytes = try Data(contentsOf: sourceFileURL)
            try bytes.write(to: destURL, options: [.atomic])
        } catch {
            throw SharedContainerError.writeFailed(error.localizedDescription)
        }

        let payload = SharedPayload(
            token: token,
            direction: direction,
            kind: .file,
            originalFilename: safeName,
            textPayload: nil,
            fileRelativePath: safeName
        )
        try writeManifest(payload: payload)
        return payload
    }

    public static func writeTextPayload(
        direction: SharedPayload.Direction,
        text: String
    ) throws -> SharedPayload {
        let token = UUID().uuidString
        _ = try tokenDirURL(token)
        let payload = SharedPayload(
            token: token,
            direction: direction,
            kind: .text,
            originalFilename: nil,
            textPayload: text,
            fileRelativePath: nil
        )
        try writeManifest(payload: payload)
        return payload
    }

    private static func writeManifest(payload: SharedPayload) throws {
        let dir = try tokenDirURL(payload.token)
        let manifestURL = dir.appendingPathComponent("manifest.json")
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(payload)
            try data.write(to: manifestURL, options: [.atomic])
        } catch {
            throw SharedContainerError.writeFailed(error.localizedDescription)
        }
    }

    public static func readPayload(token: String) throws -> SharedPayload {
        let dir = try tokenDirURL(token)
        let manifestURL = dir.appendingPathComponent("manifest.json")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            throw SharedContainerError.unknownToken
        }
        do {
            let data = try Data(contentsOf: manifestURL)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(SharedPayload.self, from: data)
        } catch {
            throw SharedContainerError.malformedManifest
        }
    }

    public static func fileURL(for payload: SharedPayload) throws -> URL {
        guard payload.kind == .file, let rel = payload.fileRelativePath else {
            throw SharedContainerError.malformedManifest
        }
        return try tokenDirURL(payload.token).appendingPathComponent(rel)
    }

    public static func cleanup(token: String) {
        guard let dir = try? tokenDirURL(token) else { return }
        try? FileManager.default.removeItem(at: dir)
    }

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

    private static func sanitizedFilename(_ raw: String) -> String {
        let last = (raw as NSString).lastPathComponent
        var clean = last.replacingOccurrences(of: "/", with: "_")
        clean = clean.replacingOccurrences(of: ":", with: "_")
        if clean.isEmpty || clean == "." || clean == ".." {
            return "payload"
        }
        return clean
    }
}
