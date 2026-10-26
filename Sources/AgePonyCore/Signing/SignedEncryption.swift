//
//  SignedEncryption.swift
//  AgePonyCore
//
//  Sign-then-encrypt with a v2 `SignatureStanza` (audit L-8), in two steps so the
//  signer (which may prompt, or need an NFC tap) runs between them:
//
//      let enc = try SignedEncryption.prepare(to: recipients)       // file key made and wrapped
//      let toSign = enc.messageHash(plaintextSHA512: sha512)         // SHA-512 of the v2 message
//      let sig = try SSHSigner.signEd25519(messageHash: toSign, ..., namespace: SignatureStanza.namespaceV2)
//      let ageFile = try enc.encrypt(plaintext: plaintext, signatureArmored: sig)
//
//  The v2 message covers the recipient stanzas, which only exist once the file key is
//  wrapped, so this can't be one call. The output is an ordinary age file: plain age
//  ignores the sig stanza.
//
//  An instance holds a file key in memory. Use it for one file and drop it.
//
//  Mirrors Android agepony-core `signing/SignedEncryption.kt`.
//

import Foundation
import CryptoKit

public enum SignedEncryptionError: Error, Equatable {
    case passphraseRecipient
    case signatureDoesNotCoverMessage(String)
    case plaintextChanged
}

public final class SignedEncryption {

    private let fileKey: Data

    /// The wrapped recipient stanzas, in header order. The v2 signature covers these.
    public let recipientStanzas: [Stanza]

    private init(fileKey: Data, recipientStanzas: [Stanza]) {
        self.fileKey = fileKey
        self.recipientStanzas = recipientStanzas
    }

    /// Make a file key and wrap it to `recipients`. Same recipient rules as
    /// `Age.encrypt`; refuses a passphrase recipient, since an scrypt stanza must stand
    /// alone (a passphrase file carries its signature in a `SignedBundle`).
    public static func prepare(to recipients: [AgeRecipient]) throws -> SignedEncryption {
        try Age.validateRecipients(recipients)
        if recipients.contains(where: { $0 is ScryptRecipient }) {
            throw SignedEncryptionError.passphraseRecipient
        }
        var keyBytes = [UInt8](repeating: 0, count: Age.fileKeySize)
        for i in 0..<keyBytes.count { keyBytes[i] = UInt8.random(in: 0...UInt8.max) }
        let fileKey = Data(keyBytes)
        let stanzas = try recipients.map { try $0.wrap(fileKey: fileKey) }
        if stanzas.contains(where: { $0.type == "scrypt" }) {
            throw SignedEncryptionError.passphraseRecipient
        }
        precondition(!stanzas.contains { $0.type == SignatureStanza.type }, "a recipient produced a signature stanza")
        return SignedEncryption(fileKey: fileKey, recipientStanzas: stanzas)
    }

    /// The v2 signed message for a plaintext whose SHA-512 is `plaintextSHA512`.
    public func message(plaintextSHA512: Data) -> Data {
        SignatureStanza.v2Message(plaintextSHA512: plaintextSHA512, headerStanzas: recipientStanzas)
    }

    /// SHA-512 of `message`: what a hashed signer takes, with namespace
    /// `SignatureStanza.namespaceV2` and hash algorithm sha512.
    public func messageHash(plaintextSHA512: Data) -> Data {
        SSHSigHash.sha512.digest(message(plaintextSHA512: plaintextSHA512))
    }

    /// Encrypt `plaintext` with `signatureArmored` in a v2 sig stanza (binary age). The
    /// signature is checked first, so one made over the wrong message or namespace fails
    /// here rather than on the recipient's phone.
    public func encrypt(plaintext: Data, signatureArmored: String) throws -> Data {
        try checkSignature(signatureArmored, plaintextSHA512: Data(SHA512.hash(data: plaintext)))
        var out = AgeHeader.serialize(stanzas: try headerStanzas(signatureArmored), fileKey: fileKey)
        out.append(try AgePayload.encrypt(plaintext: plaintext, fileKey: fileKey))
        return out
    }

    /// Streaming `encrypt` for a plaintext read a second time after hashing.
    /// `plaintextSHA512` is the hash the signature was made over; the stream is hashed
    /// again on the way through and a mismatch throws at the end, in which case `sink`
    /// holds a file whose signature won't verify and the caller must discard it.
    /// Opens both streams if needed and leaves them open.
    public func encryptStream(
        plaintext source: InputStream,
        plaintextSHA512: Data,
        signatureArmored: String,
        into sink: OutputStream
    ) throws {
        try checkSignature(signatureArmored, plaintextSHA512: plaintextSHA512)
        AgePayload.ensureOpen(source)
        AgePayload.ensureOpen(sink)
        let header = AgeHeader.serialize(stanzas: try headerStanzas(signatureArmored), fileKey: fileKey)
        let hashing = SHA512HashingInputStream(source)
        do {
            try AgePayload.writeAll(header, to: sink)
            try AgePayload.encryptStream(source: hashing, fileKey: fileKey, into: sink)
        } catch let e as AgePayloadError {
            throw AgeError.payloadError(e)
        }
        guard hashing.digest() == plaintextSHA512 else { throw SignedEncryptionError.plaintextChanged }
    }

    private func headerStanzas(_ signatureArmored: String) throws -> [Stanza] {
        recipientStanzas + [try SignatureStanza.buildV2(fileKey: fileKey, signatureArmored: signatureArmored)]
    }

    private func checkSignature(_ signatureArmored: String, plaintextSHA512: Data) throws {
        do {
            try SSHSigVerifier.verify(
                message: message(plaintextSHA512: plaintextSHA512),
                armoredSignature: signatureArmored,
                expectedNamespace: SignatureStanza.namespaceV2
            )
        } catch {
            throw SignedEncryptionError.signatureDoesNotCoverMessage(String(describing: error))
        }
    }
}

/// An `InputStream` that passes another stream through and hashes it with SHA-512.
final class SHA512HashingInputStream: InputStream {
    private let inner: InputStream
    private var hasher = SHA512()
    private var status: Stream.Status = .notOpen
    private weak var streamDelegate: StreamDelegate?

    init(_ inner: InputStream) {
        self.inner = inner
        super.init(data: Data())
    }

    func digest() -> Data { Data(hasher.finalize()) }

    override func open() { if status == .notOpen { status = .open }; AgePayload.ensureOpen(inner) }
    override func close() { status = .closed }
    override var streamStatus: Stream.Status { inner.streamStatus == .error ? .error : status }
    override var streamError: Error? { inner.streamError }
    override var delegate: StreamDelegate? {
        get { streamDelegate }
        set { streamDelegate = newValue }
    }
    override var hasBytesAvailable: Bool { inner.hasBytesAvailable }
    override func schedule(in aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    override func remove(from aRunLoop: RunLoop, forMode mode: RunLoop.Mode) {}
    override func property(forKey key: Stream.PropertyKey) -> Any? { nil }
    override func setProperty(_ property: Any?, forKey key: Stream.PropertyKey) -> Bool { false }
    override func getBuffer(
        _ buffer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
        length len: UnsafeMutablePointer<Int>
    ) -> Bool { false }

    override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        let n = inner.read(buffer, maxLength: len)
        if n > 0 {
            hasher.update(bufferPointer: UnsafeRawBufferPointer(start: buffer, count: n))
        }
        return n
    }
}
