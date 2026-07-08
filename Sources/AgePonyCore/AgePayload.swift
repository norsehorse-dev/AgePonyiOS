//
//  AgePayload.swift
//  AgePonyCore
//
//  Encrypt/decrypt the streamed payload of an age v1 file.
//
//  Wire layout (immediately follows the header MAC line):
//
//      <16-byte payload nonce prefix>
//      <chunk 1: ciphertext (≤64 KiB) || 16-byte Poly1305 tag>
//      <chunk 2: ...>
//      ...
//      <final chunk: ciphertext (≤64 KiB) || 16-byte tag>
//
//  Per-chunk nonce (12 bytes):
//
//      bytes 0..10 : 88-bit big-endian counter (starts at 0, incremented per chunk)
//      byte 11     : last-chunk flag (0x01 on the final chunk, 0x00 otherwise)
//
//  Per-chunk key = HKDF-SHA-256(file_key, salt = nonce_prefix, info = "payload", L = 32)
//
//  There is ALWAYS at least one chunk, even for an empty plaintext (in which
//  case the single chunk is empty ciphertext + 16-byte tag with flag = 0x01).
//

import Foundation
import CryptoKit

public enum AgePayloadError: Error, Equatable {
    case missingNoncePrefix
    case emptyPayload
    case truncatedChunk
    case decryptFailed
    case unexpectedExtraBytes
    case streamReadFailed
    case streamWriteFailed
}

public enum AgePayload {

    public static let chunkSize = 64 * 1024
    public static let tagSize = 16
    public static let noncePrefixSize = 16

    /// Encrypt `plaintext` using `fileKey`. The returned bytes are
    /// `noncePrefix || chunk1 || chunk2 || ... || finalChunk`, intended to be
    /// appended directly to the header bytes.
    public static func encrypt(plaintext: Data, fileKey: Data) throws -> Data {
        var noncePrefixBytes = [UInt8](repeating: 0, count: noncePrefixSize)
        for i in 0..<noncePrefixSize {
            noncePrefixBytes[i] = UInt8.random(in: 0...UInt8.max)
        }
        let noncePrefix = Data(noncePrefixBytes)

        let payloadKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey),
            salt: noncePrefix,
            info: Data("payload".utf8),
            outputByteCount: 32
        )

        var output = Data()
        output.reserveCapacity(noncePrefixSize + plaintext.count + ((plaintext.count / chunkSize) + 1) * tagSize)
        output.append(noncePrefix)

        var counter: UInt64 = 0
        var offset = 0
        repeat {
            let remaining = plaintext.count - offset
            let take = min(chunkSize, remaining)
            let isLast = remaining <= chunkSize

            let chunk = plaintext.subdata(in: offset..<(offset + take))
            let nonce = try chunkNonce(counter: counter, last: isLast)
            let sealed = try ChaChaPoly.seal(chunk, using: payloadKey, nonce: nonce, authenticating: Data())
            output.append(sealed.ciphertext)
            output.append(sealed.tag)

            offset += take
            counter = counter &+ 1
            if isLast { break }
        } while true

        return output
    }

    /// Decrypt the payload section. `bytes` is the entire payload — the 16-byte
    /// nonce prefix followed by one or more sealed chunks.
    public static func decrypt(bytes: Data, fileKey: Data) throws -> Data {
        guard bytes.count >= noncePrefixSize + tagSize else {
            throw AgePayloadError.missingNoncePrefix
        }
        let noncePrefix = bytes.prefix(noncePrefixSize)
        let chunks = bytes.suffix(from: bytes.startIndex + noncePrefixSize)

        let payloadKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey),
            salt: Data(noncePrefix),
            info: Data("payload".utf8),
            outputByteCount: 32
        )

        let totalChunkBytes = chunks.count
        guard totalChunkBytes >= tagSize else {
            throw AgePayloadError.emptyPayload
        }

        // Determine chunk layout:
        //   numFullChunks: chunks of exactly (chunkSize + tagSize) bytes that are NOT last
        //   lastChunkSize: bytes in the final chunk (between tagSize and chunkSize+tagSize)
        let chunkWithTag = chunkSize + tagSize
        let numChunks: Int
        let lastChunkSize: Int
        if totalChunkBytes % chunkWithTag == 0 {
            numChunks = totalChunkBytes / chunkWithTag
            lastChunkSize = chunkWithTag
        } else {
            numChunks = totalChunkBytes / chunkWithTag + 1
            lastChunkSize = totalChunkBytes % chunkWithTag
        }
        if lastChunkSize < tagSize {
            throw AgePayloadError.truncatedChunk
        }

        var plaintext = Data()
        plaintext.reserveCapacity(totalChunkBytes - numChunks * tagSize)

        var cursor = chunks.startIndex
        for i in 0..<numChunks {
            let isLast = (i == numChunks - 1)
            let sliceLen = isLast ? lastChunkSize : chunkWithTag
            let sliceEnd = cursor + sliceLen
            guard sliceEnd <= chunks.endIndex else {
                throw AgePayloadError.truncatedChunk
            }
            let chunkBytes = chunks[cursor..<sliceEnd]
            cursor = sliceEnd

            let ctLen = sliceLen - tagSize
            let ciphertext = chunkBytes.prefix(ctLen)
            let tag = chunkBytes.suffix(tagSize)
            let nonce = try chunkNonce(counter: UInt64(i), last: isLast)

            let sealed: ChaChaPoly.SealedBox
            do {
                sealed = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            } catch {
                throw AgePayloadError.decryptFailed
            }
            do {
                let pt = try ChaChaPoly.open(sealed, using: payloadKey, authenticating: Data())
                plaintext.append(pt)
            } catch {
                throw AgePayloadError.decryptFailed
            }
        }

        if cursor != chunks.endIndex {
            throw AgePayloadError.unexpectedExtraBytes
        }

        return plaintext
    }

    // MARK: - Internal

    internal static func chunkNonce(counter: UInt64, last: Bool) throws -> ChaChaPoly.Nonce {
        // 12 bytes: bytes 0..10 are the 88-bit big-endian counter, byte 11 is the flag.
        // We can carry UInt64 in bytes 3..10; bytes 0..2 are always zero for any
        // realistic file size (max counter = 2^64 - 1 chunks).
        var n = [UInt8](repeating: 0, count: 12)
        n[3]  = UInt8(truncatingIfNeeded: counter >> 56)
        n[4]  = UInt8(truncatingIfNeeded: counter >> 48)
        n[5]  = UInt8(truncatingIfNeeded: counter >> 40)
        n[6]  = UInt8(truncatingIfNeeded: counter >> 32)
        n[7]  = UInt8(truncatingIfNeeded: counter >> 24)
        n[8]  = UInt8(truncatingIfNeeded: counter >> 16)
        n[9]  = UInt8(truncatingIfNeeded: counter >> 8)
        n[10] = UInt8(truncatingIfNeeded: counter)
        n[11] = last ? 0x01 : 0x00
        return try ChaChaPoly.Nonce(data: Data(n))
    }

    // MARK: - Streaming payload (bounded memory)
    //
    // Same age v1 payload format as the buffered path above, but reading from an
    // InputStream and writing each sealed chunk to an OutputStream, so memory stays
    // bounded to roughly one 64 KiB chunk plus a one-chunk read-ahead. The read-ahead
    // is what lets the encoder flag the final chunk correctly when the input length is
    // an exact multiple of the chunk size, and what lets the decoder know whether the
    // chunk in hand is the last one (the last-chunk flag lives inside the nonce, so it
    // must be known before the chunk can be sealed or opened).

    /// Stream-encrypt the payload section: writes the 16-byte nonce prefix followed by
    /// the sealed chunks. Intended to be called immediately after the header bytes have
    /// been written to the same sink.
    public static func encryptStream(source: InputStream, fileKey: Data, into sink: OutputStream) throws {
        var noncePrefixBytes = [UInt8](repeating: 0, count: noncePrefixSize)
        for i in 0..<noncePrefixSize {
            noncePrefixBytes[i] = UInt8.random(in: 0...UInt8.max)
        }
        let noncePrefix = Data(noncePrefixBytes)
        let payloadKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey),
            salt: noncePrefix,
            info: Data("payload".utf8),
            outputByteCount: 32
        )
        try writeAll(noncePrefix, to: sink)

        var counter: UInt64 = 0
        var current = try readFully(source, maxLength: chunkSize)
        while true {
            if current.count < chunkSize {
                // EOF reached inside this read: this is the last chunk (possibly empty).
                try sealChunk(current, key: payloadKey, counter: counter, last: true, into: sink)
                break
            }
            let next = try readFully(source, maxLength: chunkSize)
            if next.isEmpty {
                // Input ended exactly on a chunk boundary: current is the final full chunk.
                try sealChunk(current, key: payloadKey, counter: counter, last: true, into: sink)
                break
            } else {
                try sealChunk(current, key: payloadKey, counter: counter, last: false, into: sink)
                counter &+= 1
                current = next
            }
        }
    }

    /// Stream-decrypt the payload section: reads the 16-byte nonce prefix then the sealed
    /// chunks from `source`, writing plaintext to `sink`. `source` must be positioned at
    /// the first payload byte (i.e. the header has already been consumed).
    public static func decryptStream(source: InputStream, fileKey: Data, into sink: OutputStream) throws {
        let noncePrefix = try readFully(source, maxLength: noncePrefixSize)
        guard noncePrefix.count == noncePrefixSize else { throw AgePayloadError.missingNoncePrefix }
        let payloadKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey),
            salt: noncePrefix,
            info: Data("payload".utf8),
            outputByteCount: 32
        )

        let blockSize = chunkSize + tagSize
        var counter: UInt64 = 0
        var current = try readFully(source, maxLength: blockSize)
        // There is always at least one chunk, even for empty plaintext (an empty
        // ciphertext plus a 16-byte tag), so the first block is never shorter than a tag.
        guard current.count >= tagSize else { throw AgePayloadError.emptyPayload }

        while true {
            if current.count == blockSize {
                let next = try readFully(source, maxLength: blockSize)
                if next.isEmpty {
                    // current is a full final chunk.
                    try openChunk(current, key: payloadKey, counter: counter, last: true, into: sink)
                    break
                } else {
                    guard next.count >= tagSize else { throw AgePayloadError.truncatedChunk }
                    try openChunk(current, key: payloadKey, counter: counter, last: false, into: sink)
                    counter &+= 1
                    current = next
                }
            } else {
                // A short block can only be the final chunk.
                try openChunk(current, key: payloadKey, counter: counter, last: true, into: sink)
                break
            }
        }
    }

    // MARK: - Streaming internals

    private static func sealChunk(_ plaintext: Data, key: SymmetricKey, counter: UInt64, last: Bool, into sink: OutputStream) throws {
        let nonce = try chunkNonce(counter: counter, last: last)
        let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: Data())
        try writeAll(sealed.ciphertext, to: sink)
        try writeAll(sealed.tag, to: sink)
    }

    private static func openChunk(_ block: Data, key: SymmetricKey, counter: UInt64, last: Bool, into sink: OutputStream) throws {
        guard block.count >= tagSize else { throw AgePayloadError.truncatedChunk }
        let ctLen = block.count - tagSize
        let ciphertext = block.prefix(ctLen)
        let tag = block.suffix(tagSize)
        let nonce = try chunkNonce(counter: counter, last: last)
        let sealed: ChaChaPoly.SealedBox
        do {
            sealed = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        } catch {
            throw AgePayloadError.decryptFailed
        }
        let pt: Data
        do {
            pt = try ChaChaPoly.open(sealed, using: key, authenticating: Data())
        } catch {
            throw AgePayloadError.decryptFailed
        }
        try writeAll(pt, to: sink)
    }

    /// Open `stream` only if it has not been opened yet. Never closes it; lifecycle of a
    /// caller-supplied stream stays with the caller.
    internal static func ensureOpen(_ stream: Stream) {
        if stream.streamStatus == .notOpen { stream.open() }
    }

    /// Read up to `maxLength` bytes, looping over short reads (which sockets and bridged
    /// streams produce routinely). Returns fewer than `maxLength` bytes only at EOF.
    internal static func readFully(_ input: InputStream, maxLength: Int) throws -> Data {
        if maxLength == 0 { return Data() }
        var data = Data(count: maxLength)
        var total = 0
        try data.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            while total < maxLength {
                let n = input.read(base + total, maxLength: maxLength - total)
                if n < 0 { throw AgePayloadError.streamReadFailed }
                if n == 0 { break }
                total += n
            }
        }
        return total == maxLength ? data : data.subdata(in: 0..<total)
    }

    /// Write every byte of `data`, looping over short writes.
    internal static func writeAll(_ data: Data, to output: OutputStream) throws {
        if data.isEmpty { return }
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            var total = 0
            while total < data.count {
                let n = output.write(base + total, maxLength: data.count - total)
                if n <= 0 { throw AgePayloadError.streamWriteFailed }
                total += n
            }
        }
    }

    /// Read just the age header off `input`, one byte at a time, stopping immediately
    /// after the newline that terminates the "---" MAC line. The header is small, and
    /// reading no further than its final newline leaves `input` positioned exactly at the
    /// first payload byte for the streaming payload decrypt to continue from. Base64 body
    /// lines never begin with "-", and recipient argument lines begin with "-> ", so the
    /// only header line starting with "---" is the MAC line.
    internal static func readHeader(from input: InputStream) throws -> AgeHeader {
        var headerBytes = Data()
        var lineStart = 0
        var byte: [UInt8] = [0]
        while true {
            let n = input.read(&byte, maxLength: 1)
            if n < 0 { throw AgePayloadError.streamReadFailed }
            if n == 0 { throw AgeHeaderError.missingFooter }
            headerBytes.append(byte[0])
            if byte[0] == 0x0A {
                let lineData = headerBytes.subdata(in: lineStart..<(headerBytes.count - 1))
                let line = String(data: lineData, encoding: .utf8) ?? ""
                lineStart = headerBytes.count
                if line.hasPrefix(AgeHeaderConstants.footer) {
                    break
                }
            }
            if headerBytes.count > maxHeaderBytes { throw AgeHeaderError.missingFooter }
        }
        let (header, _) = try AgeHeader.parse(bytes: headerBytes)
        return header
    }

    /// Sanity cap on header size while reading from a stream, to avoid unbounded growth on
    /// malformed input. Real age headers are well under this even with many recipients.
    private static let maxHeaderBytes = 1 << 20
}
