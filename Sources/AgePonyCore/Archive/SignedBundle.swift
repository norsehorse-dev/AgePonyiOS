//
//  SignedBundle.swift
//  AgePonyCore — archiving
//
//  AgePony's "signed bundle": a small USTAR archive carrying a payload together with a
//  detached SSHSIG over that payload, so an encrypt-and-sign produces a single `.age`
//  file. The whole bundle is age-encrypted — sign-then-encrypt — which keeps the
//  signer's identity hidden inside the ciphertext.
//
//  Entry order:
//    `.agepony-signed`  marker + manifest ("agepony-signed/1\nname=<original>\n")
//    `payload`          the original file bytes, which are what was signed
//    `payload.sig`      the armored SSHSIG over `payload`
//
//  `parse` returns nil for anything that isn't a signed bundle — a plain file, or an
//  ordinary multi-file tar whose first entry isn't the marker — so the decrypt path can
//  safely probe every decrypted output without having to know in advance.
//
//  Why sign-then-encrypt rather than encrypt-then-sign: a detached signature sitting
//  outside the ciphertext tells anyone who intercepts the pair who signed it. Sealing
//  the signature inside means the ciphertext reveals nothing, and the recipient learns
//  the signer only once they can already read the file.
//
//  This format matches the Android implementation byte for byte.
//

import Foundation
import CryptoKit

public enum SignedBundleError: Error, Equatable {
    /// Identified itself with the marker entry, but is malformed after it.
    case damaged(String)
    case missingPayload
    case missingSignature
    case unreadableManifest
}

public enum SignedBundle {

    public static let marker = ".agepony-signed"
    static let payloadName = "payload"
    static let signatureName = "payload.sig"
    static let versionLine = "agepony-signed/1"
    static let manifestPrefix = "agepony-signed/"

    static let maxManifest = 4096
    static let maxSignature = 8192
    static let copyBuffer = 64 * 1024

    // MARK: - Results

    /// A bundle read whole.
    public struct Parsed: Equatable {
        public let name: String
        public let payload: Data
        public let signatureArmored: String
    }

    /// What a streamed bundle carried. The payload itself went to the caller's output, so
    /// verification uses `hash(_:)` rather than the bytes.
    public struct StreamParsed: Equatable {
        public let name: String
        public let signatureArmored: String
        public let payloadSize: Int64
        private let hashes: [SSHSigHash: Data]

        internal init(
            name: String,
            signatureArmored: String,
            payloadSize: Int64,
            hashes: [SSHSigHash: Data]
        ) {
            self.name = name
            self.signatureArmored = signatureArmored
            self.payloadSize = payloadSize
            self.hashes = hashes
        }

        /// The payload's hash under the given SSHSIG hash algorithm.
        ///
        /// Both algorithms are computed while the payload streams past, because which one
        /// the signature uses is only known once the signature entry has been read — and
        /// by then the payload is gone.
        public func hash(_ algorithm: SSHSigHash) -> Data {
            hashes[algorithm] ?? Data()
        }
    }

    // MARK: - Buffered

    /// Build the bundle from a payload and its armored SSHSIG.
    public static func build(
        originalName: String,
        payload: Data,
        signatureArmored: String
    ) throws -> Data {
        let manifest = Data("\(versionLine)\nname=\(sanitize(originalName))\n".utf8)
        return try TarArchive.create([
            TarArchive.Entry(name: marker, data: manifest),
            TarArchive.Entry(name: payloadName, data: payload),
            TarArchive.Entry(name: signatureName, data: Data(signatureArmored.utf8)),
        ])
    }

    /// Parse `bytes` as a signed bundle, or return nil if it isn't one.
    public static func parse(_ bytes: Data) -> Parsed? {
        guard let entries = try? TarArchive.extract(bytes) else { return nil }
        guard let first = entries.first, first.name == marker else { return nil }

        let manifestText = String(decoding: first.data, as: UTF8.self)
        guard manifestText.hasPrefix(manifestPrefix) else { return nil }
        guard let payload = entries.first(where: { $0.name == payloadName }),
              let signature = entries.first(where: { $0.name == signatureName }) else { return nil }

        return Parsed(
            name: name(fromManifest: manifestText),
            payload: payload.data,
            signatureArmored: String(decoding: signature.data, as: UTF8.self)
        )
    }

    /// Does this look like a signed bundle? Cheaper than `parse` when the payload is large.
    public static func looksLikeBundle(_ bytes: Data) -> Bool {
        guard bytes.count >= TarArchive.blockSizeBytes else { return false }
        // `try?` flattens the double optional here: a thrown error and a nil return both
        // become nil, and for this question they mean the same thing — not a bundle.
        guard let header = try? TarArchive.parseStreamHeader(
            Data(bytes.prefix(TarArchive.blockSizeBytes))
        ) else { return false }
        return header.name == marker
    }

    // MARK: - Streaming build

    /// Build the bundle straight into `out`, streaming the payload rather than buffering it.
    ///
    /// `payloadSize` must be the payload's exact byte count. Byte-identical to `build`.
    public static func buildStream(
        into out: OutputStream,
        originalName: String,
        payloadSize: Int64,
        payload: InputStream,
        signatureArmored: String
    ) throws {
        let manifest = Data("\(versionLine)\nname=\(sanitize(originalName))\n".utf8)
        try TarArchive.writeEntry(to: out, name: marker, data: manifest)
        try TarArchive.writeEntry(to: out, name: payloadName, size: payloadSize, from: payload)
        try TarArchive.writeEntry(to: out, name: signatureName, data: Data(signatureArmored.utf8))
        try TarArchive.finish(to: out)
    }

    /// The bundle as something readable, for the encrypt path.
    ///
    /// `Age.encryptStream` pulls its plaintext from an `InputStream`, so sign-and-encrypt
    /// needs the bundle in pull shape. `payload` is read once, when it is reached.
    /// Produces exactly the bytes `build` would.
    public static func bundleSource(
        originalName: String,
        payloadSize: Int64,
        payload: InputStream,
        signatureArmored: String
    ) throws -> InputStream {
        let manifest = Data("\(versionLine)\nname=\(sanitize(originalName))\n".utf8)
        let signature = Data(signatureArmored.utf8)
        return try TarArchive.source([
            TarArchive.StreamEntry(name: marker, size: Int64(manifest.count)) {
                InputStream(data: manifest)
            },
            TarArchive.StreamEntry(name: payloadName, size: payloadSize) { payload },
            TarArchive.StreamEntry(name: signatureName, size: Int64(signature.count)) {
                InputStream(data: signature)
            },
        ])
    }

    /// Exact size of the bundle `bundleSource` will produce, without producing it.
    ///
    /// The encrypt path needs this when the bundle is itself nested inside another
    /// archive whose header must declare a size before the contents exist.
    public static func sizeOf(
        originalName: String,
        payloadSize: Int64,
        signatureArmored: String
    ) -> Int64 {
        let manifest = Data("\(versionLine)\nname=\(sanitize(originalName))\n".utf8)
        let signature = Data(signatureArmored.utf8)
        return TarArchive.sizeOf([
            TarArchive.StreamEntry(name: marker, size: Int64(manifest.count)) { InputStream(data: Data()) },
            TarArchive.StreamEntry(name: payloadName, size: payloadSize) { InputStream(data: Data()) },
            TarArchive.StreamEntry(name: signatureName, size: Int64(signature.count)) { InputStream(data: Data()) },
        ])
    }

    // MARK: - Internals

    static func name(fromManifest text: String) -> String {
        let found = text.split(separator: "\n", omittingEmptySubsequences: false)
            .first { $0.hasPrefix("name=") }
            .map { String($0.dropFirst("name=".count)) }
        guard let found, !found.trimmingCharacters(in: .whitespaces).isEmpty else { return "file" }
        return found
    }

    static func sanitize(_ name: String) -> String {
        let cleaned = name
            .replacingOccurrences(of: "\n", with: "_")
            .replacingOccurrences(of: "\r", with: "_")
            .trimmingCharacters(in: .whitespaces)
        return cleaned.isEmpty ? "file" : cleaned
    }
}

// MARK: - Unwrapping sink

/// An `OutputStream` that takes decrypted plaintext and writes just the payload onward.
///
/// This is the shape the decrypt path needs. `Age.decryptStream` pushes plaintext into an
/// `OutputStream`, and whether that plaintext is a signed bundle is not knowable until the
/// first block has arrived — so the decision has to be made mid-stream. A bundle has its
/// wrapper stripped as it goes and `result()` returns what verification needs; anything
/// else passes through byte for byte with a nil `result()`.
///
/// The signature is the last entry, after the payload, so a verdict can only be reported
/// once the payload has already been written out. A caller must show a failed verdict
/// loudly rather than let the user assume a saved file is a verified one.
///
/// Call `finish()` (or `close()`, which calls it) before `result()`.
public final class SignedBundleUnwrappingSink: OutputStream {

    private enum Phase {
        case sniff, header, data, pad, trailing, passthrough
    }
    private enum Target {
        case manifest, payload, signature, skip
    }

    private let payloadOut: OutputStream

    private var phase: Phase = .sniff
    private var block = Data()
    private var target: Target = .skip
    private var dataLeft: Int64 = 0
    private var padLeft = 0
    private var payloadSize: Int64 = -1
    private var manifest = Data()
    private var signature = Data()
    private var sha256 = SHA256()
    private var sha512 = SHA512()
    private var damage: String?
    private var finished = false
    private var thrown: Error?

    private var status: Stream.Status = .notOpen
    private weak var streamDelegate: StreamDelegate?

    public init(payloadOut: OutputStream) {
        self.payloadOut = payloadOut
        super.init(toMemory: ())
        AgePayload.ensureOpen(payloadOut)
    }

    // MARK: Stream overrides

    public override func open() { if status == .notOpen { status = .open } }
    public override func close() { try? finish() }
    public override var streamStatus: Stream.Status { status }
    public override var streamError: Error? { thrown }
    public override var hasSpaceAvailable: Bool { true }
    public override var delegate: StreamDelegate? {
        get { streamDelegate }
        set { streamDelegate = newValue }
    }
    public override func schedule(in aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    public override func remove(from aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    public override func property(forKey key: Stream.PropertyKey) -> Any? { nil }
    public override func setProperty(_ property: Any?, forKey key: Stream.PropertyKey) -> Bool { false }

    public override func write(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
        if len == 0 { return 0 }
        let data = Data(bytes: buffer, count: len)
        do {
            try consume(data)
            return len
        } catch {
            thrown = error
            status = .error
            return -1
        }
    }

    // MARK: Routing

    private func consume(_ input: Data) throws {
        precondition(!finished, "unwrapping sink is already finished")
        var offset = input.startIndex

        while offset < input.endIndex {
            let left = input.endIndex - offset

            switch phase {
            case .passthrough:
                try AgePayload.writeAll(Data(input[offset...]), to: payloadOut)
                return

            case .trailing:
                // Past the end-of-archive marker: nothing left to route.
                return

            case .sniff, .header:
                let take = min(TarArchive.blockSizeBytes - block.count, left)
                block.append(input[offset..<(offset + take)])
                offset += take
                if block.count == TarArchive.blockSizeBytes { try consumeHeaderBlock() }

            case .data:
                let take = Int(min(Int64(left), dataLeft))
                try route(Data(input[offset..<(offset + take)]))
                offset += take
                dataLeft -= Int64(take)
                if dataLeft == 0 { startPadding() }

            case .pad:
                let take = min(left, padLeft)
                offset += take
                padLeft -= take
                if padLeft == 0 { phase = .header; block.removeAll(keepingCapacity: true) }
            }
        }
    }

    private func consumeHeaderBlock() throws {
        let isFirst = (phase == .sniff)

        let info: TarArchive.StreamHeaderInfo?
        do {
            info = try TarArchive.parseStreamHeader(block)
        } catch {
            // A bad first block just means this was never a tar — pass it through.
            if isFirst { try becomePassthrough(); return }
            damage = damage ?? "malformed tar header"
            phase = .trailing
            return
        }

        guard let header = info else {          // end-of-archive marker
            block.removeAll(keepingCapacity: true)
            phase = .trailing
            return
        }

        if isFirst && (header.name != SignedBundle.marker || header.size > Int64(SignedBundle.maxManifest)) {
            try becomePassthrough()
            return
        }

        block.removeAll(keepingCapacity: true)
        switch header.name {
        case SignedBundle.marker:
            target = .manifest
        case SignedBundle.payloadName:
            payloadSize = header.size
            target = .payload
        case SignedBundle.signatureName:
            target = .signature
        default:
            target = .skip     // unknown entries are ignored so the format can grow
        }

        dataLeft = header.size
        let blockSize = Int64(TarArchive.blockSizeBytes)
        padLeft = Int((blockSize - header.size % blockSize) % blockSize)
        if dataLeft > 0 { phase = .data } else { startPadding() }
    }

    private func startPadding() {
        if padLeft > 0 {
            phase = .pad
        } else {
            phase = .header
            block.removeAll(keepingCapacity: true)
        }
    }

    private func becomePassthrough() throws {
        phase = .passthrough
        if !block.isEmpty {
            try AgePayload.writeAll(block, to: payloadOut)
            block.removeAll(keepingCapacity: true)
        }
    }

    private func route(_ data: Data) throws {
        switch target {
        case .payload:
            try AgePayload.writeAll(data, to: payloadOut)
            sha256.update(data: data)
            sha512.update(data: data)
        case .manifest:
            if manifest.count + data.count <= SignedBundle.maxManifest { manifest.append(data) }
        case .signature:
            if signature.count + data.count <= SignedBundle.maxSignature { signature.append(data) }
        case .skip:
            break
        }
    }

    // MARK: Finishing

    /// Settle the final state. Idempotent, and does not close `payloadOut`.
    public func finish() throws {
        if finished { return }
        finished = true
        switch phase {
        case .sniff:
            // Fewer bytes than one header block ever arrived: it was never a tar.
            if !block.isEmpty {
                try AgePayload.writeAll(block, to: payloadOut)
                block.removeAll(keepingCapacity: true)
                phase = .passthrough
            }
        case .header:
            if !block.isEmpty { damage = damage ?? "truncated header block" }
        case .data, .pad:
            damage = damage ?? "ended in the middle of an entry"
        case .trailing, .passthrough:
            break
        }
        status = .closed
    }

    /// What the bundle carried, or nil if the plaintext was not a signed bundle — in which
    /// case every byte written reached `payloadOut` unchanged.
    ///
    /// Throws if it *was* a bundle but a damaged one: once the marker has been seen, a
    /// malformed remainder is a real error rather than a reason to fall back.
    public func result() throws -> SignedBundle.StreamParsed? {
        precondition(finished, "call finish() before result()")
        if phase == .passthrough || phase == .sniff { return nil }
        if let damage { throw SignedBundleError.damaged(damage) }

        let manifestText = String(decoding: manifest, as: UTF8.self)
        guard manifestText.hasPrefix(SignedBundle.manifestPrefix) else {
            throw SignedBundleError.unreadableManifest
        }
        guard payloadSize >= 0 else { throw SignedBundleError.missingPayload }
        guard !signature.isEmpty else { throw SignedBundleError.missingSignature }

        return SignedBundle.StreamParsed(
            name: SignedBundle.name(fromManifest: manifestText),
            signatureArmored: String(decoding: signature, as: UTF8.self),
            payloadSize: payloadSize,
            hashes: [
                .sha256: Data(sha256.finalize()),
                .sha512: Data(sha512.finalize()),
            ]
        )
    }
}
