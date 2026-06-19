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

/// Something that can attempt to decrypt: returns the file key on match, nil if
/// the stanza wasn't meant for this identity. May throw on malformed input.
public protocol AgeIdentity {
    func unwrap(stanza: Stanza) throws -> Data?
}

// MARK: - Errors

public enum AgeError: Error, Equatable {
    case noRecipients
    case scryptMustBeSoleRecipient
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
        guard !recipients.isEmpty else { throw AgeError.noRecipients }
        if recipients.count > 1 {
            for r in recipients where r is ScryptRecipient {
                throw AgeError.scryptMustBeSoleRecipient
            }
        }

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
}
