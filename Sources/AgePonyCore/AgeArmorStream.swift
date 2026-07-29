//
//  AgeArmorStream.swift
//  AgePonyCore
//
//  Bounded-memory counterparts to AgeArmor.encode / decode.
//
//  `encode` and `decode` hold the whole input and the whole result in memory, which
//  is fine for notes and pasted text but puts a ceiling on file size. These hold one
//  48 KiB working buffer regardless of input size, and produce byte-identical output
//  to the whole-buffer pair for the same input.
//
//  The 48-byte grouping is the whole trick: 48 binary bytes encode to exactly 64
//  base64 characters with no padding, so input can be chunked on 48-byte boundaries
//  and still yield identical lines. Padding can only ever appear in the final group,
//  which is the only group allowed to be short.
//

import Foundation

public extension AgeArmor {

    /// 48 bytes -> exactly 64 base64 characters, unpadded.
    internal static var group: Int { lineLength / 4 * 3 }   // 48
    /// Working buffer for streaming reads.
    internal static var readChunk: Int { group * 1024 }     // 48 KiB
    /// Decode pending base64 in batches this large.
    internal static var flushAt: Int { 64 * 1024 }

    // MARK: - Encoding sink

    /// Wraps an `OutputStream` so everything written to it comes out armored.
    ///
    /// The BEGIN marker is written when the sink is created; `finish()` emits the
    /// trailing short group and the END marker. `finish()` deliberately leaves the
    /// wrapped stream open, so a caller can keep owning it.
    final class EncodingSink: OutputStream {
        private let out: OutputStream
        private var group = Data()
        private var finished = false
        private var status: Stream.Status = .notOpen
        private var thrown: Error?
        private weak var streamDelegate: StreamDelegate?

        public init(_ out: OutputStream) throws {
            self.out = out
            super.init(toMemory: ())
            AgePayload.ensureOpen(out)
            try AgePayload.writeAll(Data((AgeArmor.beginMarker + "\n").utf8), to: out)
            status = .open
        }

        // MARK: OutputStream conformance
        //
        // Being a real OutputStream is the point: it lets Age.encryptStream write
        // ciphertext straight through the armor encoder in one pass, instead of
        // encrypting to a temp file and armoring it afterwards.

        public override func open() { if status == .notOpen { status = .open } }

        /// Marks the stream closed. Deliberately does *not* emit the END marker --
        /// see `finish()`.
        public override func close() { status = .closed }

        public override var streamStatus: Stream.Status { status }
        public override var streamError: Error? { thrown }
        public override var hasSpaceAvailable: Bool { !finished }
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
            do {
                try write(Data(bytes: buffer, count: len))
                return len
            } catch {
                thrown = error
                status = .error
                return -1
            }
        }

        // MARK: Encoding

        /// Append `data` to the armored output.
        public func write(_ data: Data) throws {
            precondition(!finished, "armor sink is already finished")
            guard !data.isEmpty else { return }

            var rest = data

            // Top up a partial group left from a previous write.
            if !group.isEmpty {
                let take = min(AgeArmor.group - group.count, rest.count)
                group.append(rest.prefix(take))
                rest = Data(rest.dropFirst(take))
                if group.count == AgeArmor.group {
                    try emitLines(group)
                    group.removeAll(keepingCapacity: true)
                }
            }

            // Emit everything that lands on a whole number of 48-byte groups.
            let aligned = rest.count - (rest.count % AgeArmor.group)
            if aligned > 0 {
                try emitLines(Data(rest.prefix(aligned)))
                rest = Data(rest.dropFirst(aligned))
            }

            // Hold the remainder; it may be topped up, or become the final short group.
            if !rest.isEmpty { group.append(rest) }
        }

        /// Emit the final partial group and the END marker. Idempotent.
        ///
        /// Must be called explicitly; `close()` will not do it for you, so that a
        /// missed call produces an obviously unterminated file rather than a quietly
        /// truncated one.
        public func finish() throws {
            if finished { return }
            finished = true
            if !group.isEmpty {
                // The only short group, and the only place base64 padding can appear.
                var line = group.base64EncodedString()
                line.append("\n")
                try AgePayload.writeAll(Data(line.utf8), to: out)
                group.removeAll(keepingCapacity: true)
            }
            try AgePayload.writeAll(Data((AgeArmor.endMarker + "\n").utf8), to: out)
        }

        /// `chunk.count` is a multiple of 48, so its base64 is a whole number of
        /// unpadded 64-character lines.
        private func emitLines(_ chunk: Data) throws {
            var offset = chunk.startIndex
            while offset < chunk.endIndex {
                let take = min(AgeArmor.readChunk, chunk.endIndex - offset)
                let encoded = Data(chunk[offset..<(offset + take)]).base64EncodedString()
                var text = ""
                text.reserveCapacity(encoded.count + encoded.count / AgeArmor.lineLength + 1)
                var i = encoded.startIndex
                while i < encoded.endIndex {
                    let end = encoded.index(i, offsetBy: AgeArmor.lineLength, limitedBy: encoded.endIndex)
                        ?? encoded.endIndex
                    text.append(contentsOf: encoded[i..<end])
                    text.append("\n")
                    i = end
                }
                try AgePayload.writeAll(Data(text.utf8), to: out)
                offset += take
            }
        }
    }

    // MARK: - Streaming convenience

    /// Read binary from `binary`, write armored text to `out`, in bounded memory.
    /// Byte-identical to what `encode` would produce. Closes neither stream.
    static func encodeStream(binary: InputStream, into out: OutputStream) throws {
        AgePayload.ensureOpen(binary)
        let sink = try EncodingSink(out)
        while true {
            let chunk = try AgePayload.readFully(binary, maxLength: readChunk)
            if chunk.isEmpty { break }
            try sink.write(chunk)
            if chunk.count < readChunk { break }
        }
        try sink.finish()
    }

    /// Read armored text from `armored`, write decoded binary to `out`, in bounded memory.
    /// Closes neither stream.
    static func decodeStream(armored: InputStream, into out: OutputStream) throws {
        let source = ArmorDecodingSource(armored)
        source.open()
        AgePayload.ensureOpen(out)
        while true {
            let chunk = try source.readChunk(maxLength: readChunk)
            if chunk.isEmpty { break }
            try AgePayload.writeAll(chunk, to: out)
        }
    }
}

// MARK: - Decoding source

/// An `InputStream` that reads armored text and yields the decoded binary, so an
/// armored file can be handed straight to a binary reader — `Age.decryptStream`, say —
/// without being decoded whole first.
///
/// Accepts what `AgeArmor.decode` accepts: CRLF, trailing whitespace, and blank lines
/// around the markers. `close()` leaves the wrapped stream open, since its lifecycle
/// belongs to the caller.
///
/// This subclasses `InputStream` rather than exposing a plain read method because the
/// whole point is to substitute for one wherever a stream is expected. `InputStream` is
/// a class cluster, so every member the streaming code touches is overridden below.
public final class ArmorDecodingSource: InputStream {
    private let lines: ArmorLineReader
    private var pending = ""
    private var buffer = Data()
    private var bufferPos = 0
    private var sawBegin = false
    private var sawEnd = false
    private var sawPadding = false
    private var exhausted = false

    private var status: Stream.Status = .notOpen
    private var error: Error?
    private weak var streamDelegate: StreamDelegate?

    public init(_ input: InputStream) {
        self.lines = ArmorLineReader(input)
        // InputStream's designated initializers all want data or a URL; this one is
        // never used to read from, so an empty backing store is correct.
        super.init(data: Data())
    }

    // MARK: Stream overrides

    public override func open() {
        if status == .notOpen { status = .open }
    }

    public override func close() {
        status = .closed
    }

    public override var streamStatus: Stream.Status { status }
    public override var streamError: Error? { error }

    public override var delegate: StreamDelegate? {
        get { streamDelegate }
        set { streamDelegate = newValue }
    }

    public override var hasBytesAvailable: Bool {
        bufferPos < buffer.count || !exhausted
    }

    public override func schedule(in aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    public override func remove(from aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    public override func property(forKey key: Stream.PropertyKey) -> Any? { nil }
    public override func setProperty(_ property: Any?, forKey key: Stream.PropertyKey) -> Bool { false }
    public override func getBuffer(
        _ buffer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
        length len: UnsafeMutablePointer<Int>
    ) -> Bool { false }

    /// Returns bytes read, 0 at end of the armored body, or -1 on error. On -1,
    /// `streamError` carries the `AgeArmorError` that explains it — worth checking,
    /// because a caller reading through the generic stream API would otherwise only
    /// see "read failed" for what is really malformed armor.
    public override func read(_ target: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        if len == 0 { return 0 }
        do {
            guard try fill() else { return 0 }
        } catch {
            self.error = error
            status = .error
            return -1
        }
        let take = min(len, buffer.count - bufferPos)
        buffer.withUnsafeBytes { raw in
            if let base = raw.bindMemory(to: UInt8.self).baseAddress {
                target.update(from: base + bufferPos, count: take)
            }
        }
        bufferPos += take
        return take
    }

    /// Throwing convenience used by `AgeArmor.decodeStream`, which wants the real error
    /// rather than -1.
    internal func readChunk(maxLength: Int) throws -> Data {
        guard try fill() else { return Data() }
        let take = min(maxLength, buffer.count - bufferPos)
        let out = Data(buffer.dropFirst(bufferPos).prefix(take))
        bufferPos += take
        return out
    }

    // MARK: Decoding

    /// Refill `buffer` when it runs out. Returns false once the body is exhausted.
    private func fill() throws -> Bool {
        while bufferPos >= buffer.count {
            if exhausted { return false }
            buffer = try nextChunk()
            bufferPos = 0
        }
        return true
    }

    private func nextChunk() throws -> Data {
        while true {
            guard let raw = try lines.nextLine() else {
                if !sawBegin { throw AgeArmorError.missingBeginMarker }
                if !sawEnd { throw AgeArmorError.missingEndMarker }
                exhausted = true
                return try decodePending(all: true)
            }
            let line = raw.trimmingCharacters(in: .whitespaces)

            if !sawBegin {
                if line.isEmpty { continue }
                guard line == AgeArmor.beginMarker else { throw AgeArmorError.missingBeginMarker }
                sawBegin = true
                continue
            }

            if !sawEnd {
                // Reading continues past END so trailing junk is still rejected, the way
                // decode() rejects it by requiring END to be the last meaningful line.
                if line == AgeArmor.endMarker { sawEnd = true; continue }
                if line == AgeArmor.beginMarker { throw AgeArmorError.extraDataOutsideArmor }
                if line.isEmpty { continue }
                // Padding means the final group; anything after it is malformed.
                if sawPadding { throw AgeArmorError.invalidBase64 }
                pending += line
                if pending.count >= AgeArmor.flushAt {
                    let chunk = try decodePending(all: false)
                    if !chunk.isEmpty { return chunk }
                }
                continue
            }

            if !line.isEmpty { throw AgeArmorError.extraDataOutsideArmor }
        }
    }

    private func decodePending(all: Bool) throws -> Data {
        // Only whole 4-character base64 quanta can be decoded mid-stream.
        let take = all ? pending.count : pending.count - (pending.count % 4)
        if take == 0 { return Data() }
        let chunk = String(pending.prefix(take))
        pending.removeFirst(take)
        if chunk.contains("=") { sawPadding = true }
        guard let decoded = Data(base64Encoded: chunk, options: []) else {
            throw AgeArmorError.invalidBase64
        }
        return decoded
    }
}

/// Reads LF-terminated lines off an `InputStream` without holding the whole input.
/// Tolerates CRLF by stripping a trailing CR.
final class ArmorLineReader {
    private let input: InputStream
    private var buffer = Data()
    private var atEOF = false

    init(_ input: InputStream) {
        self.input = input
        AgePayload.ensureOpen(input)
    }

    /// The next line without its terminator, or nil at end of input.
    func nextLine() throws -> String? {
        while true {
            if let nl = buffer.firstIndex(of: 0x0A) {
                let lineData = Data(buffer[buffer.startIndex..<nl])
                buffer = Data(buffer[(nl + 1)...])
                return decode(lineData)
            }
            if atEOF {
                if buffer.isEmpty { return nil }
                let lineData = buffer
                buffer = Data()
                return decode(lineData)
            }
            let chunk = try AgePayload.readFully(input, maxLength: 8192)
            if chunk.isEmpty { atEOF = true } else { buffer.append(chunk) }
        }
    }

    private func decode(_ data: Data) -> String {
        var d = data
        if d.last == 0x0D { d = Data(d.dropLast()) }   // CRLF
        return String(decoding: d, as: UTF8.self)
    }
}

// MARK: - Armor sniffing

public extension AgeArmor {
    /// Bytes worth sniffing from the head of a file to recognize armor.
    static var sniffLength: Int { 64 }

    /// Does this look like the start of an armored age file?
    ///
    /// Intended for a caller holding only the first `sniffLength` bytes of a file, so a
    /// large file can be routed to the armored or binary path without being read.
    static func looksArmored(prefix: Data) -> Bool {
        guard let text = String(data: prefix.prefix(sniffLength), encoding: .utf8) else {
            return false
        }
        return text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("-----BEGIN AGE")
    }
}
