//
//  FileEncryptor.swift
//  AgePony
//
//  Encrypt and decrypt files on disk, in bounded memory.
//
//  This used to read the whole input with Data(contentsOf:), hold the whole
//  ciphertext, and hold the armored copy on top of that -- three copies of the
//  file resident at once. On a phone that put a hard ceiling on file size well
//  below the free storage: a 130 MB file could exhaust the heap on a device with
//  gigabytes free.
//
//  Everything now streams from the input file to the output file in 64 KiB
//  chunks, so a 1 GB file costs the same memory as a 1 KB one. Output is
//  byte-identical to the buffered path it replaces.
//
//  Note on output location: unlike the Android app, which must pick a
//  destination before writing because of the Storage Access Framework, iOS
//  writes to a temp file and hands the user a ShareLink. The temp file is the
//  natural place here -- what mattered for memory was streaming to disk instead
//  of building a Data, not where the file ultimately lands.
//

import Foundation
import AgePonyCore

public enum FileEncryptorError: Error, Equatable {
    case noRecipients
    case scryptCannotMixWithRecipients
    case writeFailed(String)
    case readFailed(String)
    case ageError(String)
    case cannotOpenInput(String)
    case cannotOpenOutput(String)
}

/// Reports progress as `(bytesProcessed, totalBytes)`. `totalBytes` is 0 when the
/// input size could not be determined.
public typealias FileProgressHandler = @Sendable (Int64, Int64) -> Void

public enum FileEncryptor {

    /// scrypt work factor used for passphrase encrypts.
    ///
    /// Lower than the age CLI default of 18. At 18 scrypt allocates ~256 MiB and
    /// takes 20-60 seconds on an iPhone; 16 gives N=65536 and ~64 MiB in 2-5
    /// seconds, which is still substantial brute-force resistance. The factor is
    /// written into the file, so any age implementation can still read the result.
    public static let mobileWorkFactor: Int = 16

    private static let copyBuffer = 64 * 1024

    // MARK: - Encrypt

    /// Encrypt `inputURL` to a temp `.age` file, streaming throughout.
    ///
    /// Pass `progress` to receive byte counts as the file is consumed.
    public static func encrypt(
        inputURL: URL,
        recipients: [any AgeRecipient],
        passphrase: String?,
        armor: Bool,
        workFactor: Int = mobileWorkFactor,
        progress: FileProgressHandler? = nil
    ) throws -> URL {
        let usingPassphrase = (passphrase?.isEmpty == false)
        if !usingPassphrase && recipients.isEmpty {
            throw FileEncryptorError.noRecipients
        }
        if usingPassphrase && !recipients.isEmpty {
            throw FileEncryptorError.scryptCannotMixWithRecipients
        }

        let scoped = inputURL.startAccessingSecurityScopedResource()
        defer { if scoped { inputURL.stopAccessingSecurityScopedResource() } }

        let total = fileSize(of: inputURL)
        let outURL = try freshTempURL(named: inputURL.lastPathComponent + ".age")

        guard let rawInput = InputStream(url: inputURL) else {
            throw FileEncryptorError.cannotOpenInput(inputURL.lastPathComponent)
        }
        guard let output = OutputStream(url: outURL, append: false) else {
            throw FileEncryptorError.cannotOpenOutput(outURL.lastPathComponent)
        }

        let input = ProgressInputStream(rawInput, total: total, report: progress)
        input.open()
        output.open()
        defer { input.close(); output.close() }

        let targets: [any AgeRecipient] = usingPassphrase
            ? [ScryptRecipient(passphrase: passphrase ?? "", workFactor: workFactor)]
            : recipients

        do {
            if armor {
                // Single pass: ciphertext goes straight through the armor encoder.
                let sink = try AgeArmor.EncodingSink(output)
                try Age.encryptStream(plaintext: input, to: targets, into: sink)
                try sink.finish()
            } else {
                try Age.encryptStream(plaintext: input, to: targets, into: output)
            }
        } catch {
            cleanupTempFile(at: outURL)
            throw FileEncryptorError.ageError(String(describing: error))
        }

        try protectFile(at: outURL)
        return outURL
    }

    // MARK: - Decrypt (streaming)

    /// Decrypt `inputURL` to a temp file, streaming throughout.
    ///
    /// Handles armored and binary input transparently: the first bytes are sniffed
    /// and, if armored, the file is de-armored on the fly rather than decoded whole.
    ///
    /// Supply either `identities` or `passphrase`.
    public static func decrypt(
        inputURL: URL,
        identities: [any AgeIdentity],
        passphrase: String?,
        progress: FileProgressHandler? = nil
    ) throws -> URL {
        let scoped = inputURL.startAccessingSecurityScopedResource()
        defer { if scoped { inputURL.stopAccessingSecurityScopedResource() } }

        let total = fileSize(of: inputURL)
        let armored = try looksArmored(inputURL)
        let outURL = try freshTempURL(named: plaintextName(for: inputURL.lastPathComponent))

        guard let rawInput = InputStream(url: inputURL) else {
            throw FileEncryptorError.cannotOpenInput(inputURL.lastPathComponent)
        }
        guard let output = OutputStream(url: outURL, append: false) else {
            throw FileEncryptorError.cannotOpenOutput(outURL.lastPathComponent)
        }

        // Progress is measured on the file being consumed, which is the outermost
        // stream, so it counts armored bytes when the input is armored.
        let counted = ProgressInputStream(rawInput, total: total, report: progress)
        counted.open()
        output.open()
        defer { counted.close(); output.close() }

        let source: InputStream = armored ? ArmorDecodingSource(counted) : counted
        source.open()

        let readers: [any AgeIdentity] = (passphrase?.isEmpty == false)
            ? [ScryptIdentity(passphrase: passphrase ?? "")]
            : identities

        do {
            try Age.decryptStream(ciphertext: source, identities: readers, into: output)
        } catch {
            cleanupTempFile(at: outURL)
            // An armor problem surfaces through the decoding source rather than as a
            // read failure, so prefer its error when there is one.
            if let armorError = (source as? ArmorDecodingSource)?.streamError {
                throw FileEncryptorError.readFailed(String(describing: armorError))
            }
            throw FileEncryptorError.ageError(String(describing: error))
        }

        try protectFile(at: outURL)
        return outURL
    }

    // MARK: - Decrypt (buffered)
    //
    // Retained for callers holding bytes rather than a file, such as text mode and
    // the share extension. Prefer the streaming entry point for anything file-sized.

    public static func decryptIdentityBased(
        binaryAgeBytes binary: Data,
        outputBaseName: String,
        identities: [any AgeIdentity]
    ) throws -> URL {
        let plaintext: Data
        do {
            plaintext = try Age.decrypt(ciphertext: binary, identities: identities)
        } catch {
            throw FileEncryptorError.ageError(String(describing: error))
        }
        return try writeToFreshTempDir(
            name: plaintextName(for: outputBaseName),
            bytes: plaintext
        )
    }

    public static func decryptPassphraseBased(
        binaryAgeBytes binary: Data,
        outputBaseName: String,
        passphrase: String
    ) throws -> URL {
        let plaintext: Data
        do {
            plaintext = try Age.decrypt(ciphertext: binary, passphrase: passphrase)
        } catch {
            throw FileEncryptorError.ageError(String(describing: error))
        }
        return try writeToFreshTempDir(
            name: plaintextName(for: outputBaseName),
            bytes: plaintext
        )
    }

    // MARK: - Helpers

    /// Read only the first bytes to decide whether the file is armored, so this
    /// stays instant on a large file.
    private static func looksArmored(_ url: URL) throws -> Bool {
        guard let probe = InputStream(url: url) else {
            throw FileEncryptorError.cannotOpenInput(url.lastPathComponent)
        }
        probe.open()
        defer { probe.close() }
        var buffer = [UInt8](repeating: 0, count: AgeArmor.sniffLength)
        let n = probe.read(&buffer, maxLength: buffer.count)
        guard n > 0 else { return false }
        return AgeArmor.looksArmored(prefix: Data(buffer[0..<n]))
    }

    private static func fileSize(of url: URL) -> Int64 {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.size] as? NSNumber)?.int64Value ?? 0
    }

    private static func plaintextName(for sourceName: String) -> String {
        sourceName.lowercased().hasSuffix(".age")
            ? String(sourceName.dropLast(4))
            : sourceName + " (decrypted)"
    }

    private static func freshTempURL(named name: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgePonyShare-\(UUID().uuidString.prefix(8))", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            throw FileEncryptorError.writeFailed(error.localizedDescription)
        }
        return dir.appendingPathComponent(name)
    }

    /// Apply the same data protection the buffered writer used to set via
    /// `Data.write(options:)`. Streaming writes bypass that, so it is applied after.
    private static func protectFile(at url: URL) throws {
        do {
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.completeUnlessOpen],
                ofItemAtPath: url.path
            )
        } catch {
            throw FileEncryptorError.writeFailed(error.localizedDescription)
        }
    }

    private static func writeToFreshTempDir(name: String, bytes: Data) throws -> URL {
        let url = try freshTempURL(named: name)
        do {
            try bytes.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
        } catch {
            throw FileEncryptorError.writeFailed(error.localizedDescription)
        }
        return url
    }

    public static func cleanupTempFile(at url: URL) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: dir)
    }
}

// MARK: - Progress reporting

/// Wraps an `InputStream` and reports how much of it has been consumed.
///
/// Progress is measured at the source rather than the destination because the
/// input size is known up front, while the output size is not -- armor inflates
/// by a third, and encryption adds a header and per-chunk tags.
final class ProgressInputStream: InputStream {
    private let source: InputStream
    private let total: Int64
    private let report: FileProgressHandler?
    private var consumed: Int64 = 0
    private var lastReported: Int64 = 0

    private var status: Stream.Status = .notOpen
    private weak var streamDelegate: StreamDelegate?

    /// Report at most every 256 KiB, so a large file does not flood the main actor
    /// with UI updates it cannot render.
    private static let reportInterval: Int64 = 256 * 1024

    init(_ source: InputStream, total: Int64, report: FileProgressHandler?) {
        self.source = source
        self.total = total
        self.report = report
        super.init(data: Data())
    }

    override func open() {
        if status == .notOpen {
            status = .open
            if source.streamStatus == .notOpen { source.open() }
        }
    }

    override func close() {
        status = .closed
        source.close()
        flushProgress()
    }

    override var streamStatus: Stream.Status { status }
    override var streamError: Error? { source.streamError }
    override var hasBytesAvailable: Bool { source.hasBytesAvailable }
    override var delegate: StreamDelegate? {
        get { streamDelegate }
        set { streamDelegate = newValue }
    }
    override func schedule(in aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    override func remove(from aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    override func property(forKey key: Stream.PropertyKey) -> Any? { source.property(forKey: key) }
    override func setProperty(_ property: Any?, forKey key: Stream.PropertyKey) -> Bool { false }
    override func getBuffer(
        _ buffer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
        length len: UnsafeMutablePointer<Int>
    ) -> Bool { false }

    override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        let n = source.read(buffer, maxLength: len)
        if n > 0 {
            consumed += Int64(n)
            if consumed - lastReported >= Self.reportInterval { flushProgress() }
        } else if n == 0 {
            flushProgress()
        }
        return n
    }

    private func flushProgress() {
        guard let report, consumed != lastReported else { return }
        lastReported = consumed
        report(consumed, total)
    }
}
