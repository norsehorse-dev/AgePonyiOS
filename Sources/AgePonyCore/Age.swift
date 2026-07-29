//
//  Age.swift
//  AgePonyCore
//
//  Top-level age encrypt/decrypt API.
//

import Foundation
import CryptoKit

// MARK: - Recipient / Identity protocols

/// Something that can be encrypted *to*: produces a stanza wrapping the file key.
public protocol AgeRecipient {
    func wrap(fileKey: Data) throws -> Stanza
}

/// A recipient carrying labels that constrain which other recipients it may share
/// a file with.
///
/// Per age's labels mechanism, every recipient in a file must agree on the exact
/// same label set, or encryption is refused. This is how a post-quantum recipient
/// (label `postquantum`) declines to be mixed with a classical one that would
/// defeat its quantum resistance — the weakest recipient sets the bar for the file.
///
/// A recipient that does not conform is treated as having an empty label set, so
/// mixing a labeled recipient with an unlabeled one is rejected.
public protocol LabeledAgeRecipient: AgeRecipient {
    var labels: Set<String> { get }
}

/// Something that can attempt to decrypt: returns the file key on match, nil if
/// the stanza wasn't meant for this identity. May throw on malformed input.
public protocol AgeIdentity {
    func unwrap(stanza: Stanza) throws -> Data?
}

// MARK: - Errors

public enum AgeError: Error, Equatable {
    case noRecipients
    case scryptMustBeSoleRecipient
    case mismatchedRecipientLabels
    case noMatchingIdentity
    case wrongPassphrase
    case truncatedFile
    case headerError(AgeHeaderError)
    case payloadError(AgePayloadError)
}

// MARK: - Top-level API

public enum Age {

    /// Size of the symmetric file key (per age v1 spec).
    public static let fileKeySize = 16

    /// Encrypt `plaintext` to one or more recipients.
    /// Recipients may be a mix of X25519 / SSH types; scrypt recipients MUST
    /// appear alone (mixing scrypt with any other recipient is a spec violation).
    public static func encrypt(plaintext: Data, to recipients: [AgeRecipient]) throws -> Data {
        try validateRecipients(recipients)

        // 16 random bytes for the file key.
        var fileKeyBytes = [UInt8](repeating: 0, count: fileKeySize)
        for i in 0..<fileKeySize {
            fileKeyBytes[i] = UInt8.random(in: 0...UInt8.max)
        }
        let fileKey = Data(fileKeyBytes)

        var stanzas: [Stanza] = []
        stanzas.reserveCapacity(recipients.count)
        for r in recipients {
            stanzas.append(try r.wrap(fileKey: fileKey))
        }

        let headerBytes = AgeHeader.serialize(stanzas: stanzas, fileKey: fileKey)
        let payloadBytes = try AgePayload.encrypt(plaintext: plaintext, fileKey: fileKey)

        var out = Data()
        out.reserveCapacity(headerBytes.count + payloadBytes.count)
        out.append(headerBytes)
        out.append(payloadBytes)
        return out
    }

    /// Convenience: encrypt with a passphrase via a scrypt recipient.
    public static func encrypt(plaintext: Data, passphrase: String, workFactor: Int = 18) throws -> Data {
        let recipient = ScryptRecipient(passphrase: passphrase, workFactor: workFactor)
        return try encrypt(plaintext: plaintext, to: [recipient])
    }

    /// Decrypt `ciphertext` using one or more identities. Each identity is
    /// tried against each stanza until one yields a valid file key.
    public static func decrypt(ciphertext: Data, identities: [AgeIdentity]) throws -> Data {
        let (header, payloadOffset): (AgeHeader, Int)
        do {
            (header, payloadOffset) = try AgeHeader.parse(bytes: ciphertext)
        } catch let e as AgeHeaderError {
            throw AgeError.headerError(e)
        }

        guard payloadOffset <= ciphertext.count else { throw AgeError.truncatedFile }

        // Try every identity against every stanza until one returns a fileKey.
        var fileKey: Data?
        outer: for id in identities {
            for stanza in header.stanzas {
                if let key = try id.unwrap(stanza: stanza), key.count == fileKeySize {
                    fileKey = key
                    break outer
                }
            }
        }
        guard let fileKey else { throw AgeError.noMatchingIdentity }

        // Verify header MAC. If this fails the file has been tampered with.
        do {
            try header.verifyMAC(fileKey: fileKey)
        } catch let e as AgeHeaderError {
            throw AgeError.headerError(e)
        }

        // Decrypt payload.
        let payloadBytes = ciphertext.suffix(from: ciphertext.startIndex + payloadOffset)
        do {
            return try AgePayload.decrypt(bytes: Data(payloadBytes), fileKey: fileKey)
        } catch let e as AgePayloadError {
            throw AgeError.payloadError(e)
        }
    }

    /// Convenience: decrypt with a passphrase.
    public static func decrypt(ciphertext: Data, passphrase: String) throws -> Data {
        let identity = ScryptIdentity(passphrase: passphrase)
        // If the file uses scrypt and the passphrase is wrong, ScryptIdentity.unwrap
        // returns nil (same as "not for me"), which becomes noMatchingIdentity here.
        // Translate to a friendlier error: if every stanza is scrypt, this is a
        // wrong-passphrase error specifically.
        do {
            return try decrypt(ciphertext: ciphertext, identities: [identity])
        } catch AgeError.noMatchingIdentity {
            // Inspect the header to disambiguate.
            if let (header, _) = try? AgeHeader.parse(bytes: ciphertext),
               header.stanzas.allSatisfy({ $0.type == "scrypt" }) {
                throw AgeError.wrongPassphrase
            }
            throw AgeError.noMatchingIdentity
        }
    }

    /// Shared precondition check for both the buffered and streaming encrypt paths.
    ///
    /// Enforces two rules: scrypt must be the only recipient, and every recipient
    /// must agree on the same label set.
    static func validateRecipients(_ recipients: [AgeRecipient]) throws {
        guard !recipients.isEmpty else { throw AgeError.noRecipients }

        if recipients.count > 1 {
            for r in recipients where r is ScryptRecipient {
                throw AgeError.scryptMustBeSoleRecipient
            }
        }

        // Labels: all recipients must declare an identical set. An unlabeled
        // recipient declares the empty set, so mixing labeled with unlabeled fails.
        let labelSets = recipients.map { ($0 as? LabeledAgeRecipient)?.labels ?? [] }
        if let first = labelSets.first, labelSets.contains(where: { $0 != first }) {
            throw AgeError.mismatchedRecipientLabels
        }
    }

    // MARK: - Header-only probe
    //
    // Reading just the header answers "what is this file encrypted to, and can I open
    // it?" without decrypting anything. The header is bounded and sits at the front, so
    // this is instant on a file of any size — which is the point: a 1 GB file should not
    // have to be read to tell the user which key it needs.
    //
    // Recipient stanzas are public information. Anyone holding the file already has
    // them, so surfacing them reveals nothing the holder did not have.

    /// Parse just the header of `ciphertext`, leaving the stream positioned at the first
    /// payload byte. Throws the usual header errors for input that is not an age file.
    public static func parseHeaderStream(ciphertext source: InputStream) throws -> AgeHeader {
        AgePayload.ensureOpen(source)
        do {
            return try AgePayload.readHeader(from: source)
        } catch let e as AgeHeaderError {
            throw AgeError.headerError(e)
        } catch let e as AgePayloadError {
            throw AgeError.payloadError(e)
        }
    }

    /// Parse just the header of a buffered age file.
    public static func parseHeader(ciphertext: Data) throws -> AgeHeader {
        do {
            let (header, _) = try AgeHeader.parse(bytes: ciphertext)
            return header
        } catch let e as AgeHeaderError {
            throw AgeError.headerError(e)
        }
    }

    /// True if any of `identities` can unwrap this file's header.
    ///
    /// Reads the header and stops, leaving `source` positioned at the first payload byte,
    /// so a caller can find out which key a file needs without decrypting it.
    public static func canDecryptStream(
        ciphertext source: InputStream,
        identities: [AgeIdentity]
    ) throws -> Bool {
        guard !identities.isEmpty else { return false }
        let header = try parseHeaderStream(ciphertext: source)
        for stanza in header.stanzas {
            for id in identities where try id.unwrap(stanza: stanza) != nil {
                return true
            }
        }
        return false
    }

    /// True if any of `identities` can unwrap this buffered file's header.
    public static func canDecrypt(ciphertext: Data, identities: [AgeIdentity]) throws -> Bool {
        guard !identities.isEmpty else { return false }
        let header = try parseHeader(ciphertext: ciphertext)
        for stanza in header.stanzas {
            for id in identities where try id.unwrap(stanza: stanza) != nil {
                return true
            }
        }
        return false
    }

    // MARK: - Streaming API (bounded memory)
    //
    // Mirror of the buffered encrypt/decrypt above for large inputs, e.g. file transfer,
    // where holding the whole plaintext and the whole ciphertext in memory at once is not
    // acceptable. The age header is small and stays buffered; only the payload streams,
    // one 64 KiB chunk at a time. Output bytes are identical in format to the buffered
    // path, so a streamed file decrypts with the buffered API and vice versa.

    /// Encrypt bytes read from `source` to one or more recipients, writing the age file to
    /// `sink`. Opens both streams if needed and leaves them open for the caller to close.
    public static func encryptStream(
        plaintext source: InputStream,
        to recipients: [AgeRecipient],
        into sink: OutputStream
    ) throws {
        try validateRecipients(recipients)

        AgePayload.ensureOpen(source)
        AgePayload.ensureOpen(sink)

        var fileKeyBytes = [UInt8](repeating: 0, count: fileKeySize)
        for i in 0..<fileKeySize {
            fileKeyBytes[i] = UInt8.random(in: 0...UInt8.max)
        }
        let fileKey = Data(fileKeyBytes)

        var stanzas: [Stanza] = []
        stanzas.reserveCapacity(recipients.count)
        for r in recipients {
            stanzas.append(try r.wrap(fileKey: fileKey))
        }

        let headerBytes = AgeHeader.serialize(stanzas: stanzas, fileKey: fileKey)
        do {
            try AgePayload.writeAll(headerBytes, to: sink)
            try AgePayload.encryptStream(source: source, fileKey: fileKey, into: sink)
        } catch let e as AgePayloadError {
            throw AgeError.payloadError(e)
        }
    }

    /// Decrypt an age file read from `source` using one or more identities, writing the
    /// plaintext to `sink`. Opens both streams if needed and leaves them open.
    public static func decryptStream(
        ciphertext source: InputStream,
        identities: [AgeIdentity],
        into sink: OutputStream
    ) throws {
        AgePayload.ensureOpen(source)
        AgePayload.ensureOpen(sink)

        let header: AgeHeader
        do {
            header = try AgePayload.readHeader(from: source)
        } catch let e as AgeHeaderError {
            throw AgeError.headerError(e)
        } catch let e as AgePayloadError {
            throw AgeError.payloadError(e)
        }

        var fileKey: Data?
        outer: for id in identities {
            for stanza in header.stanzas {
                if let key = try id.unwrap(stanza: stanza), key.count == fileKeySize {
                    fileKey = key
                    break outer
                }
            }
        }
        guard let fileKey else { throw AgeError.noMatchingIdentity }

        do {
            try header.verifyMAC(fileKey: fileKey)
        } catch let e as AgeHeaderError {
            throw AgeError.headerError(e)
        }

        do {
            try AgePayload.decryptStream(source: source, fileKey: fileKey, into: sink)
        } catch let e as AgePayloadError {
            throw AgeError.payloadError(e)
        }
    }
}
