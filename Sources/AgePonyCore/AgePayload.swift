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
}
