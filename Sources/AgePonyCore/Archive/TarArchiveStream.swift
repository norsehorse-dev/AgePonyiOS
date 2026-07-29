//
//  TarArchiveStream.swift
//  AgePonyCore — archiving
//
//  Bounded-memory counterparts to TarArchive.create / extract.
//
//  `create` and `extract` hold the whole archive in memory. These copy one 64 KiB
//  buffer at a time and produce byte-identical archives for the same entries — which
//  is the contract the tests pin, because a multi-file bundle written by the streaming
//  path has to be indistinguishable from one written in memory.
//
//  Two shapes are needed, because the two directions pull opposite ways:
//    - push: `writeEntry` / `finish` append to an OutputStream.
//    - pull: `source` presents entries as a readable archive, because
//      `Age.encryptStream` reads its plaintext *from* an InputStream.
//

import Foundation

public extension TarArchive {

    /// USTAR block size. Public because a streaming reader has to buffer exactly one header.
    static var blockSizeBytes: Int { 512 }

    /// Largest entry a USTAR 12-byte octal size field can express: 8^11 - 1, just under 8 GiB.
    static var maxEntrySize: Int64 { 8_589_934_591 }

    internal static var copyBuffer: Int { 64 * 1024 }

    // MARK: - Streaming write (push)

    /// Append one whole-buffer entry. Same bytes as the matching `create` entry.
    static func writeEntry(to out: OutputStream, name: String, data: Data) throws {
        try AgePayload.writeAll(try streamHeader(name: name, size: Int64(data.count)), to: out)
        try AgePayload.writeAll(data, to: out)
        try writePadding(to: out, size: Int64(data.count))
    }

    /// Append one entry whose contents stream from `data`, without ever holding it in memory.
    ///
    /// `size` must be the exact byte count: USTAR writes the size into the header *before*
    /// the data, so it cannot be discovered while copying.
    ///
    /// Throws if `data` ends early. When `strict` is true (the default) it also reads one byte
    /// past the entry to catch a stream holding *more* than `size` bytes, which would silently
    /// truncate the archived file — pass false when `data` carries further entries and its
    /// position must be preserved.
    static func writeEntry(
        to out: OutputStream,
        name: String,
        size: Int64,
        from data: InputStream,
        strict: Bool = true
    ) throws {
        guard size >= 0 else { throw TarArchiveError.invalidSize }
        guard size <= maxEntrySize else { throw TarArchiveError.entryTooLarge(name) }

        try AgePayload.writeAll(try streamHeader(name: name, size: size), to: out)
        AgePayload.ensureOpen(data)

        var written: Int64 = 0
        while written < size {
            let want = Int(min(Int64(copyBuffer), size - written))
            let chunk = try AgePayload.readFully(data, maxLength: want)
            if chunk.isEmpty {
                throw TarArchiveError.entryEndedEarly(name, written, size)
            }
            try AgePayload.writeAll(chunk, to: out)
            written += Int64(chunk.count)
        }

        if strict {
            let extra = try AgePayload.readFully(data, maxLength: 1)
            if !extra.isEmpty { throw TarArchiveError.entryLongerThanDeclared(name, size) }
        }

        try writePadding(to: out, size: size)
    }

    /// Write the two zero blocks that end an archive. Call once, after the last entry.
    static func finish(to out: OutputStream) throws {
        try AgePayload.writeAll(Data(count: blockSizeBytes * 2), to: out)
    }

    // MARK: - Streaming source (pull)

    /// One entry of a streamed archive.
    ///
    /// `open` is called only when the entry is reached, so a hundred-file archive never has a
    /// hundred files open at once. `size` must be that entry's exact byte count.
    struct StreamEntry {
        public let name: String
        public let size: Int64
        public let open: () -> InputStream

        public init(name: String, size: Int64, open: @escaping () -> InputStream) {
            self.name = name
            self.size = size
            self.open = open
        }
    }

    /// Present `entries` as a single readable archive, without building it anywhere.
    ///
    /// This is the pull-shaped counterpart of `writeEntry`: `Age.encryptStream` reads its
    /// plaintext from an `InputStream`, so a multi-file encrypt needs the tar to be readable
    /// rather than writable. Produces exactly the bytes `create` would for the same entries.
    static func source(_ entries: [StreamEntry]) throws -> InputStream {
        for e in entries {
            guard e.size >= 0 else { throw TarArchiveError.invalidSize }
            guard e.size <= maxEntrySize else { throw TarArchiveError.entryTooLarge(e.name) }
            // Fail now rather than halfway through a read, when the caller has already
            // committed output somewhere.
            _ = try streamHeader(name: e.name, size: e.size)
        }
        return TarSource(entries)
    }

    /// Exact length of the archive `source` will produce for `entries`, without producing it.
    ///
    /// Sign-and-encrypt of a multi-file bundle needs this: the signed bundle's tar header has
    /// to declare the inner archive's size before the inner archive exists.
    static func sizeOf(_ entries: [StreamEntry]) -> Int64 {
        var total: Int64 = 0
        let block = Int64(blockSizeBytes)
        for e in entries {
            total += block + e.size + ((block - e.size % block) % block)
        }
        return total + block * 2
    }

    // MARK: - Streaming read

    /// Walk `input` entry by entry without materializing the archive.
    ///
    /// `handler` receives each entry's name, size, and a reader bounded to that entry's bytes;
    /// whatever the handler leaves unread is skipped before the next entry. The handler must
    /// not use the reader after returning.
    ///
    /// Stops at the end-of-archive marker, or at end of input for an archive truncated after a
    /// complete entry (which `extract` also tolerates).
    static func forEachEntry(
        from input: InputStream,
        handler: (_ name: String, _ size: Int64, _ data: TarEntryReader) throws -> Void
    ) throws {
        AgePayload.ensureOpen(input)
        while true {
            let headerBlock = try AgePayload.readFully(input, maxLength: blockSizeBytes)
            if headerBlock.isEmpty { return }                 // clean end of input
            guard headerBlock.count == blockSizeBytes else { throw TarArchiveError.truncated }
            guard let info = try parseStreamHeader(headerBlock) else { return }  // end-of-archive

            let reader = TarEntryReader(input, remaining: info.size)
            try handler(info.name, info.size, reader)
            try reader.drain()
            try skipFully(input, count: (Int64(blockSizeBytes) - info.size % Int64(blockSizeBytes))
                                        % Int64(blockSizeBytes))
        }
    }

    // MARK: - Internals

    internal static func writePadding(to out: OutputStream, size: Int64) throws {
        let block = Int64(blockSizeBytes)
        let pad = Int((block - size % block) % block)
        if pad > 0 { try AgePayload.writeAll(Data(count: pad), to: out) }
    }

    internal static func skipFully(_ input: InputStream, count: Int64) throws {
        var left = count
        while left > 0 {
            let want = Int(min(Int64(copyBuffer), left))
            let chunk = try AgePayload.readFully(input, maxLength: want)
            if chunk.isEmpty { throw TarArchiveError.truncated }
            left -= Int64(chunk.count)
        }
    }

    /// Build a USTAR header block.
    ///
    /// Octal fields are formatted by hand rather than with `String(format: "%o")`: the
    /// printf `%o` conversion takes a C `unsigned int`, so a 64-bit size would be passed
    /// through varargs incorrectly for entries at or above 4 GiB — right in the range USTAR
    /// still supports and that this streaming work exists to handle.
    internal static func streamHeader(name: String, size: Int64) throws -> Data {
        let nameBytes = Array(name.utf8)
        guard nameBytes.count <= 100 else { throw TarArchiveError.nameTooLong(name) }
        guard size >= 0 else { throw TarArchiveError.invalidSize }
        guard size <= maxEntrySize else { throw TarArchiveError.entryTooLarge(name) }

        var h = [UInt8](repeating: 0, count: blockSizeBytes)

        func put(_ s: String, at offset: Int) {
            for (i, b) in Array(s.utf8).enumerated() { h[offset + i] = b }
        }

        /// Zero-padded octal, exactly `width` digits.
        func octal(_ value: Int64, width: Int) -> String {
            var digits = String(value, radix: 8)
            if digits.count < width {
                digits = String(repeating: "0", count: width - digits.count) + digits
            }
            return digits
        }

        for (i, b) in nameBytes.enumerated() { h[i] = b }     // name (100)
        put("0000644", at: 100)                               // mode + NUL
        put("0000000", at: 108)                               // uid
        put("0000000", at: 116)                               // gid
        put(octal(size, width: 11), at: 124)                  // size + NUL
        put("00000000000", at: 136)                           // mtime 0 + NUL
        for i in 148..<156 { h[i] = 0x20 }                    // checksum field as spaces
        h[156] = 0x30                                         // typeflag '0' regular
        put("ustar", at: 257); h[262] = 0                     // magic "ustar\0"
        h[263] = 0x30; h[264] = 0x30                          // version "00"

        let sum = h.reduce(0) { $0 + Int($1) }
        put(octal(Int64(sum), width: 6), at: 148)
        h[154] = 0
        h[155] = 0x20

        return Data(h)
    }

    internal struct StreamHeaderInfo {
        let name: String
        let size: Int64
    }

    /// Parse a header block. Returns nil for the all-zero end-of-archive marker.
    internal static func parseStreamHeader(_ block: Data) throws -> StreamHeaderInfo? {
        let bytes = [UInt8](block)
        if bytes.allSatisfy({ $0 == 0 }) { return nil }

        // Checksum, computed with the checksum field read as spaces.
        var sum = 0
        for (i, b) in bytes.enumerated() {
            sum += (148..<156).contains(i) ? 0x20 : Int(b)
        }
        guard sum == (try octalValue(bytes, 148, 8)) else { throw TarArchiveError.badChecksum }

        let typeflag = bytes[156]
        guard typeflag == 0x30 || typeflag == 0 else {
            throw TarArchiveError.unsupportedEntryType(typeflag)
        }

        var nameSlice = Array(bytes[0..<100])
        if let nul = nameSlice.firstIndex(of: 0) { nameSlice = Array(nameSlice[..<nul]) }
        let name = String(decoding: nameSlice, as: UTF8.self)
        let size = try octalValue(bytes, 124, 12)

        return StreamHeaderInfo(name: name, size: size)
    }

    private static func octalValue(_ bytes: [UInt8], _ start: Int, _ len: Int) throws -> Int64 {
        var value: Int64 = 0
        for b in bytes[start..<(start + len)] {
            if b == 0 || b == 0x20 { continue }
            guard b >= 0x30 && b <= 0x37 else { throw TarArchiveError.invalidSize }
            value = value * 8 + Int64(b - 0x30)
        }
        return value
    }
}

// MARK: - Bounded entry reader

/// Reads exactly one entry's bytes and no more. Whatever the handler leaves unread is
/// skipped by `forEachEntry` before the next header, so a handler that only wants an
/// entry's first few bytes does not desynchronize the archive.
public final class TarEntryReader {
    private let source: InputStream
    private var remaining: Int64

    internal init(_ source: InputStream, remaining: Int64) {
        self.source = source
        self.remaining = remaining
    }

    /// Bytes not yet read from this entry.
    public var bytesRemaining: Int64 { remaining }

    /// Read up to `maxLength` bytes. Empty at the end of this entry.
    public func read(maxLength: Int) throws -> Data {
        if remaining <= 0 { return Data() }
        let want = Int(min(Int64(maxLength), remaining))
        let chunk = try AgePayload.readFully(source, maxLength: want)
        remaining -= Int64(chunk.count)
        if chunk.isEmpty && remaining > 0 { throw TarArchiveError.truncated }
        return chunk
    }

    /// Read this entry to the end and return it whole. Only for entries known to be small.
    public func readAll() throws -> Data {
        var out = Data()
        while true {
            let chunk = try read(maxLength: 64 * 1024)
            if chunk.isEmpty { break }
            out.append(chunk)
        }
        return out
    }

    /// Copy the rest of this entry to `sink`.
    public func copy(to sink: OutputStream) throws {
        while true {
            let chunk = try read(maxLength: 64 * 1024)
            if chunk.isEmpty { break }
            try AgePayload.writeAll(chunk, to: sink)
        }
    }

    /// Consume whatever the handler left behind, so the next header lines up.
    internal func drain() throws {
        if remaining > 0 {
            try TarArchive.skipFully(source, count: remaining)
            remaining = 0
        }
    }
}

// MARK: - Pull-shaped archive source

/// An `InputStream` that emits a USTAR archive built lazily from its entries: header,
/// payload, padding for each in turn, then the two end-of-archive blocks.
///
/// Subclasses `InputStream` so it can stand in wherever one is expected — chiefly
/// `Age.encryptStream`, which pulls its plaintext from a stream.
final class TarSource: InputStream {
    private let entries: [TarArchive.StreamEntry]
    private var index = 0
    private var part = 0            // 0 header, 1 payload, 2 padding, 3 end blocks, 4 done
    private var pending = Data()
    private var current: InputStream?
    private var payloadLeft: Int64 = 0

    private var status: Stream.Status = .notOpen
    private var error: Error?
    private weak var streamDelegate: StreamDelegate?

    init(_ entries: [TarArchive.StreamEntry]) {
        self.entries = entries
        super.init(data: Data())
    }

    // MARK: Stream overrides

    override func open() { if status == .notOpen { status = .open } }
    override func close() { status = .closed; current = nil }
    override var streamStatus: Stream.Status { status }
    override var streamError: Error? { error }
    override var delegate: StreamDelegate? {
        get { streamDelegate }
        set { streamDelegate = newValue }
    }
    override var hasBytesAvailable: Bool { part < 4 || !pending.isEmpty }
    override func schedule(in aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    override func remove(from aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    override func property(forKey key: Stream.PropertyKey) -> Any? { nil }
    override func setProperty(_ property: Any?, forKey key: Stream.PropertyKey) -> Bool { false }
    override func getBuffer(
        _ buffer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
        length len: UnsafeMutablePointer<Int>
    ) -> Bool { false }

    override func read(_ target: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        if len == 0 { return 0 }
        do {
            guard try fill() else { return 0 }
        } catch {
            self.error = error
            status = .error
            return -1
        }
        let take = min(len, pending.count)
        pending.withUnsafeBytes { raw in
            if let base = raw.bindMemory(to: UInt8.self).baseAddress {
                target.update(from: base, count: take)
            }
        }
        pending = Data(pending.dropFirst(take))
        return take
    }

    // MARK: Assembly

    /// Ensure `pending` holds at least one byte, advancing through the archive parts.
    /// Returns false once the archive is fully emitted.
    private func fill() throws -> Bool {
        while pending.isEmpty {
            switch part {
            case 0:
                guard index < entries.count else { part = 3; continue }
                let e = entries[index]
                pending = try TarArchive.streamHeader(name: e.name, size: e.size)
                payloadLeft = e.size
                current = nil
                part = 1

            case 1:
                if payloadLeft == 0 {
                    current = nil
                    part = 2
                    continue
                }
                if current == nil {
                    let s = entries[index].open()
                    AgePayload.ensureOpen(s)
                    current = s
                }
                let want = Int(min(Int64(TarArchive.copyBuffer), payloadLeft))
                let chunk = try AgePayload.readFully(current!, maxLength: want)
                if chunk.isEmpty {
                    throw TarArchiveError.entryEndedEarly(
                        entries[index].name, entries[index].size - payloadLeft, entries[index].size
                    )
                }
                payloadLeft -= Int64(chunk.count)
                pending = chunk

            case 2:
                let block = Int64(TarArchive.blockSizeBytes)
                let pad = Int((block - entries[index].size % block) % block)
                if pad > 0 { pending = Data(count: pad) }
                index += 1
                part = 0

            case 3:
                pending = Data(count: TarArchive.blockSizeBytes * 2)
                part = 4

            default:
                return false
            }
        }
        return true
    }
}
