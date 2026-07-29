//
//  SSHSigHashStream.swift
//  AgePonyCore — signing
//
//  Bounded-memory message hashing for SSHSIG.
//
//  SSHSIG only ever covers the message *hash* — the signed-data blob carries the digest,
//  not the message — so hashing incrementally is all it takes to sign or verify a file of
//  any size without holding it. This is what lets a 1 GB file be signed on a phone.
//

import Foundation
import CryptoKit

public extension SSHSigHash {

    /// Hash a message read from `source`, 64 KiB at a time. Same result as `digest(_:)`
    /// over the same bytes. Does not close the stream.
    func digest(streaming source: InputStream) throws -> Data {
        AgePayload.ensureOpen(source)
        switch self {
        case .sha256:
            var hasher = SHA256()
            try Self.pump(source) { hasher.update(data: $0) }
            return Data(hasher.finalize())
        case .sha512:
            var hasher = SHA512()
            try Self.pump(source) { hasher.update(data: $0) }
            return Data(hasher.finalize())
        }
    }

    private static func pump(_ source: InputStream, _ absorb: (Data) -> Void) throws {
        while true {
            let chunk = try AgePayload.readFully(source, maxLength: 64 * 1024)
            if chunk.isEmpty { return }
            absorb(chunk)
        }
    }
}
