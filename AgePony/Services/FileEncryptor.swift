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
    /// scrypt's allocation will not fit. Carries a message naming the
    /// allocation, because the cause is the passphrase's work factor and not
    /// the size of the file.
    case scryptWontFit(String)
    /// The plaintext announced itself as a signed bundle and then failed to be
    /// one. Distinct from a decrypt failure: the age layer was fine, so the file
    /// is readable but its contents are not what they claim.
    case bundleDamaged(String)
}

/// Reports progress as `(bytesProcessed, totalBytes)`. `totalBytes` is 0 when the
/// input size could not be determined.
public typealias FileProgressHandler = @Sendable (Int64, Int64) -> Void

public enum FileEncryptor {

    /// scrypt work factor used when a caller does not specify one.
    ///
    /// One definition, in ScryptMemory, so the default cannot drift from the
    /// range and cost calculations that describe it to the user.
    public static let mobileWorkFactor: Int = ScryptMemory.defaultWorkFactor

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
        destinationDirectory: URL? = nil,
        progress: FileProgressHandler? = nil
    ) throws -> URL {
        let scoped = inputURL.startAccessingSecurityScopedResource()
        defer { if scoped { inputURL.stopAccessingSecurityScopedResource() } }

        guard let rawInput = InputStream(url: inputURL) else {
            throw FileEncryptorError.cannotOpenInput(inputURL.lastPathComponent)
        }

        return try encrypt(
            source: rawInput,
            totalBytes: fileSize(of: inputURL),
            outputName: inputURL.lastPathComponent + ".age",
            recipients: recipients,
            passphrase: passphrase,
            armor: armor,
            workFactor: workFactor,
            destinationDirectory: destinationDirectory,
            progress: progress
        )
    }

    /// Encrypt whatever `source` yields into a `.age` file named `outputName`.
    ///
    /// The one implementation of "encrypt a stream to a file". A single file, a tar
    /// assembled on the fly, and a signed bundle differ only in what they pull from
    /// -- so the scrypt guard, the armor branch, and the file-protection step live
    /// here once rather than in each caller.
    ///
    /// `totalBytes` is what `progress` reports against; pass 0 when it isn't known.
    /// `source` is opened here and closed on the way out; the caller keeps whatever
    /// security-scoped access the source needs alive across the call.
    public static func encrypt(
        source: InputStream,
        totalBytes: Int64,
        outputName: String,
        recipients: [any AgeRecipient],
        passphrase: String?,
        armor: Bool,
        workFactor: Int = mobileWorkFactor,
        destinationDirectory: URL? = nil,
        progress: FileProgressHandler? = nil
    ) throws -> URL {
        let usingPassphrase = (passphrase?.isEmpty == false)
        if !usingPassphrase && recipients.isEmpty {
            throw FileEncryptorError.noRecipients
        }
        if usingPassphrase && !recipients.isEmpty {
            throw FileEncryptorError.scryptCannotMixWithRecipients
        }
        // Check the allocation before doing any work, rather than failing part
        // way through with an error that looks like a file problem.
        if usingPassphrase, let reason = ScryptMemory.blockingReason(workFactor: workFactor) {
            throw FileEncryptorError.scryptWontFit(reason)
        }

        // A directory we made is ours to remove on failure. A directory handed to
        // us belongs to a batch, and removing it would take the siblings that
        // already succeeded -- so there, only the partial output goes.
        let ownsDirectory = (destinationDirectory == nil)
        let outURL = try destinationDirectory.map { $0.appendingPathComponent(outputName) }
            ?? freshTempURL(named: outputName)

        guard let output = OutputStream(url: outURL, append: false) else {
            throw FileEncryptorError.cannotOpenOutput(outURL.lastPathComponent)
        }

        let input = ProgressInputStream(source, total: totalBytes, report: progress)
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
            if ownsDirectory {
                cleanupTempFile(at: outURL)
            } else {
                try? FileManager.default.removeItem(at: outURL)
            }
            throw FileEncryptorError.ageError(String(describing: error))
        }

        try protectFile(at: outURL)
        return outURL
    }

    // MARK: - Decrypt (streaming)

    /// What came out of a decrypt.
    public struct DecryptOutcome {
        /// The plaintext on disk. For a signed bundle this is the payload alone,
        /// under the name the bundle recorded, with the wrapper already stripped.
        public let url: URL
        /// Present when the plaintext turned out to be a signed bundle. Carries the
        /// signature and the digests taken while the payload streamed past, which is
        /// everything verification needs -- the payload itself is gone by then.
        public let signedBundle: SignedBundle.StreamParsed?

        public var isSigned: Bool { signedBundle != nil }
    }

    /// Decrypt `inputURL` to a temp file, streaming throughout.
    ///
    /// Handles armored and binary input transparently: the first bytes are sniffed
    /// and, if armored, the file is de-armored on the fly rather than decoded whole.
    ///
    /// Supply either `identities` or `passphrase`.
    ///
    /// With `unwrapSignedBundle` (the default), plaintext that turns out to be a
    /// signed bundle has its wrapper stripped as it streams and the outcome carries
    /// what verification needs. Anything else passes through byte for byte, so a
    /// plain file and a 2.0-era file are unaffected. Pass `false` to keep the bundle
    /// intact -- re-encrypting wants that, since rewrapping the same bundle for new
    /// recipients preserves a signature that unwrapping would throw away.
    public static func decrypt(
        inputURL: URL,
        identities: [any AgeIdentity],
        passphrase: String?,
        unwrapSignedBundle: Bool = true,
        progress: FileProgressHandler? = nil
    ) throws -> DecryptOutcome {
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

        // Whether the plaintext is a bundle is not knowable until its first block
        // has arrived, so the decision is made mid-stream by the sink rather than
        // by anything here.
        let unwrapper = unwrapSignedBundle ? SignedBundleUnwrappingSink(payloadOut: output) : nil
        unwrapper?.open()
        let destination: OutputStream = unwrapper ?? output

        do {
            try Age.decryptStream(ciphertext: source, identities: readers, into: destination)
            try unwrapper?.finish()
        } catch {
            cleanupTempFile(at: outURL)
            // An armor problem surfaces through the decoding source rather than as a
            // read failure, so prefer its error when there is one.
            if let armorError = (source as? ArmorDecodingSource)?.streamError {
                throw FileEncryptorError.readFailed(String(describing: armorError))
            }
            throw FileEncryptorError.ageError(String(describing: error))
        }

        let parsed: SignedBundle.StreamParsed?
        do {
            parsed = try unwrapper?.result()
        } catch {
            // The marker was there and the rest was not. The age layer succeeded, so
            // this is not a decrypt failure -- say so, rather than leaving the user
            // with a half-written file and a misleading message.
            cleanupTempFile(at: outURL)
            throw FileEncryptorError.bundleDamaged(String(describing: error))
        }

        try protectFile(at: outURL)

        // A bundle knows what the file was called before it was wrapped, which beats
        // the name derived from stripping `.age`. Best effort: a rename that fails
        // costs a worse filename, not the file.
        var finalURL = outURL
        if let parsed {
            let safe = SignedBundle.safeFileName(parsed.name, fallback: outURL.lastPathComponent)
            let desired = outURL.deletingLastPathComponent().appendingPathComponent(safe)
            if desired != outURL,
               !FileManager.default.fileExists(atPath: desired.path),
               (try? FileManager.default.moveItem(at: outURL, to: desired)) != nil {
                finalURL = desired
            }
        }

        return DecryptOutcome(url: finalURL, signedBundle: parsed)
    }

    // MARK: - Multi-file

    /// One entry per input in a batch encrypt.
    public struct BatchResult {
        public let source: URL
        /// The encrypted file, or nil if this input failed.
        public let output: URL?
        public let error: Error?

        public var succeeded: Bool { output != nil }
    }

    /// Encrypt several inputs as a single tar archive.
    ///
    /// The archive is never built anywhere: `TarArchive.source` produces it
    /// lazily as the encryptor reads, so memory stays flat no matter how many
    /// files are chosen or how large they are, and no intermediate copy is
    /// written to disk.
    public static func encryptArchive(
        inputURLs: [URL],
        archiveName: String = "bundle.tar",
        recipients: [any AgeRecipient],
        passphrase: String?,
        armor: Bool,
        workFactor: Int = mobileWorkFactor,
        progress: FileProgressHandler? = nil
    ) throws -> URL {
        guard !inputURLs.isEmpty else { throw FileEncryptorError.noRecipients }

        // Hold security-scoped access for every input across the whole read.
        // Entries are opened lazily, so access has to outlive the call rather
        // than each individual open.
        let scopedURLs = inputURLs.filter { $0.startAccessingSecurityScopedResource() }
        defer { scopedURLs.forEach { $0.stopAccessingSecurityScopedResource() } }

        var entries: [TarArchive.StreamEntry] = []
        entries.reserveCapacity(inputURLs.count)
        for url in inputURLs {
            let size = fileSize(of: url)
            let name = url.lastPathComponent
            entries.append(TarArchive.StreamEntry(name: name, size: size) {
                InputStream(url: url) ?? InputStream(data: Data())
            })
        }

        let archiveBytes = TarArchive.sizeOf(entries)
        let tar: InputStream
        do {
            tar = try TarArchive.source(entries)
        } catch {
            throw FileEncryptorError.ageError(String(describing: error))
        }

        return try encrypt(
            source: tar,
            totalBytes: archiveBytes,
            outputName: archiveName + ".age",
            recipients: recipients,
            passphrase: passphrase,
            armor: armor,
            workFactor: workFactor,
            progress: progress
        )
    }

    /// Write a tar of `inputURLs` to a temp file, streaming.
    ///
    /// `encryptArchive` never materialises the archive, which is what keeps
    /// memory flat -- but signing needs a concrete file to sign. This produces
    /// one without buffering it: the cost is temp disk, not memory.
    public static func buildArchiveFile(
        inputURLs: [URL],
        archiveName: String = "bundle.tar"
    ) throws -> URL {
        let scopedURLs = inputURLs.filter { $0.startAccessingSecurityScopedResource() }
        defer { scopedURLs.forEach { $0.stopAccessingSecurityScopedResource() } }

        let outURL = try freshTempURL(named: archiveName)
        guard let output = OutputStream(url: outURL, append: false) else {
            throw FileEncryptorError.cannotOpenOutput(archiveName)
        }
        output.open()
        defer { output.close() }

        do {
            for url in inputURLs {
                guard let input = InputStream(url: url) else {
                    throw FileEncryptorError.cannotOpenInput(url.lastPathComponent)
                }
                input.open()
                defer { input.close() }
                try TarArchive.writeEntry(
                    to: output,
                    name: url.lastPathComponent,
                    size: fileSize(of: url),
                    from: input
                )
            }
            try TarArchive.finish(to: output)
        } catch let e as FileEncryptorError {
            cleanupTempFile(at: outURL)
            throw e
        } catch {
            cleanupTempFile(at: outURL)
            throw FileEncryptorError.writeFailed(String(describing: error))
        }

        try protectFile(at: outURL)
        return outURL
    }

    /// Encrypt each input separately into one shared directory.
    ///
    /// Returns a result per input, in order, rather than throwing: one bad file
    /// in a batch of twenty should not discard the other nineteen. Callers show
    /// the per-file outcome.
    ///
    /// `fileProgress` reports `(filesCompleted, filesTotal)`.
    public static func encryptEach(
        inputURLs: [URL],
        recipients: [any AgeRecipient],
        passphrase: String?,
        armor: Bool,
        workFactor: Int = mobileWorkFactor,
        fileProgress: (@Sendable (Int, Int) -> Void)? = nil
    ) throws -> (directory: URL, results: [BatchResult]) {
        guard !inputURLs.isEmpty else { throw FileEncryptorError.noRecipients }

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgePonyBatch-\(UUID().uuidString.prefix(8))", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            throw FileEncryptorError.writeFailed(error.localizedDescription)
        }

        var results: [BatchResult] = []
        results.reserveCapacity(inputURLs.count)

        for (index, url) in inputURLs.enumerated() {
            do {
                let out = try encrypt(
                    inputURL: url,
                    recipients: recipients,
                    passphrase: passphrase,
                    armor: armor,
                    workFactor: workFactor,
                    destinationDirectory: directory
                )
                results.append(BatchResult(source: url, output: out, error: nil))
            } catch {
                results.append(BatchResult(source: url, output: nil, error: error))
            }
            fileProgress?(index + 1, inputURLs.count)
        }

        return (directory, results)
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

    /// Remove the temp directory containing `url`.
    ///
    /// Single outputs each get their own directory, so removing the parent is
    /// correct there. For a batch, whose outputs share one directory, use
    /// `cleanupTempDirectory` instead -- calling this on one member would take
    /// its siblings with it.
    public static func cleanupTempFile(at url: URL) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: dir)
    }

    /// Remove a batch output directory and everything in it.
    public static func cleanupTempDirectory(at directory: URL) {
        try? FileManager.default.removeItem(at: directory)
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
