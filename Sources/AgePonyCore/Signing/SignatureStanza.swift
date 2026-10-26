//
//  SignatureStanza.swift
//  AgePonyCore
//
//  AgePony's signature stanza, `agepony.com/sig` (v1 from Android 5.0.0, v2 from 5.0.1).
//
//  A signed-and-encrypted file carries its SSHSIG in an extra age header stanza rather
//  than in a wrapper around the payload (the older approach is `SignedBundle`). The
//  signature is encrypted under a key derived from the file key, so:
//
//    - plain age ignores the unrecognized stanza and returns the bare payload,
//    - only a recipient who can unwrap the file key can read or verify the signature,
//      so the signer stays out of the cleartext header,
//    - the age header MAC already covers every stanza, so the signature can't be
//      swapped for another without decrypt noticing.
//
//  age requires an scrypt stanza to stand alone, so this is only used with public-key
//  recipients. Passphrase files keep the `SignedBundle` wrapper.
//
//  Body (both versions): 12-byte random nonce || ChaCha20-Poly1305(key, nonce, armored
//  SSHSIG), no associated data. key = HKDF-SHA256(ikm = file key, salt = empty,
//  info = "agepony.com/sig-v1" or "agepony.com/sig-v2", L = 32).
//
//  What the SSHSIG covers:
//
//    v1 (`-> agepony.com/sig v1`): the plaintext, namespace "agepony". Doesn't cover the
//    recipients, so a recipient could re-wrap the file to someone else and the signature
//    would still check (audit L-8). Read only; AgePony no longer writes it.
//
//    v2 (`-> agepony.com/sig v2`, exactly one argument): the message M below, namespace
//    "agepony-sig-v2". `string` is SSH wire framing (uint32 BE length, then the bytes).
//
//      M = string "agepony.com/sig v2"
//          string SHA-512(plaintext)
//          string SHA-512(R)
//          string original file name (always empty for this stanza)
//
//      R = uint32 n, then for each header stanza whose type isn't "agepony.com/sig",
//          in header order: string type, uint32 argc, argc x string arg, string body
//          (the decoded body bytes).
//
//  Byte-for-byte mirror of Android agepony-core `signing/SignatureStanza.kt`. The layout
//  and test vectors are in the Android repo's docs/SIGNATURE_FORMATS_v2.md.
//

import Foundation
import CryptoKit

public enum SignatureStanza {

    public static let type = "agepony.com/sig"
    public static let versionV1 = "v1"
    public static let versionV2 = "v2"

    /// SSHSIG namespace of a v2 signature stanza. Detached signatures keep "agepony".
    public static let namespaceV2 = "agepony-sig-v2"

    /// First field of the v2 signed message.
    public static let messageDomainV2 = "agepony.com/sig v2"

    static let keyInfoV1 = "agepony.com/sig-v1"
    static let keyInfoV2 = "agepony.com/sig-v2"
    static let keyLength = 32
    static let nonceLength = 12
    static let tagLength = 16

    /// Largest armored signature a stanza may carry (matches Android's verifier cap).
    public static let maxSignatureBytes = 16 * 1024

    // MARK: - Build

    /// A v1 stanza. Kept for tests and fixtures; new files are written as v2.
    public static func buildV1(fileKey: Data, signatureArmored: String) throws -> Stanza {
        try seal(fileKey: fileKey, info: keyInfoV1, version: versionV1, signatureArmored: signatureArmored)
    }

    /// A v2 stanza carrying `signatureArmored`, an SSHSIG over `v2Message` under
    /// `namespaceV2`. `SignedEncryption` is the usual way in.
    public static func buildV2(fileKey: Data, signatureArmored: String) throws -> Stanza {
        try seal(fileKey: fileKey, info: keyInfoV2, version: versionV2, signatureArmored: signatureArmored)
    }

    // MARK: - Open

    /// What a header's signature stanza holds (audit L-9).
    public enum Opening: Equatable {
        /// No signature stanza: the file is simply unsigned.
        case absent
        /// A signature stanza is present but can't be read. Show it as a failed
        /// signature, never as unsigned.
        case unreadable(String)
        /// The stanza opened.
        case opened(Opened)

        /// The opened signature, if any.
        public var opened: Opened? {
            if case .opened(let o) = self { return o }
            return nil
        }
    }

    /// An opened signature stanza. Verify with `verify(plaintext:)`, or hand
    /// `namespace` and `messageDigest(plaintextHash:)` to a hashed verify.
    public struct Opened: Equatable {
        public let signatureArmored: String
        /// 1 or 2.
        public let version: Int
        let recipientsDigest: Data

        /// SSHSIG namespace this version signs under.
        public var namespace: String { version >= 2 ? SignatureStanza.namespaceV2 : SSHSig.defaultNamespace }

        /// True for v2: the signature also covers this file's recipient stanzas. A v1
        /// signature covers only the plaintext, which the UI should say.
        public var coversRecipients: Bool { version >= 2 }

        /// The exact message the SSHSIG covers, given the decrypted plaintext.
        public func signedMessage(plaintext: Data) -> Data {
            guard version >= 2 else { return plaintext }
            return SignatureStanza.v2Message(
                plaintextSHA512: Data(SHA512.hash(data: plaintext)),
                recipientsDigest: recipientsDigest,
                originalName: ""
            )
        }

        /// H(signed message) under `algorithm`, for a streaming verify. `plaintextHash`
        /// returns the plaintext's hash under an algorithm; v2 only ever asks for sha512.
        public func messageDigest(
            _ algorithm: SSHSigHash,
            plaintextHash: (SSHSigHash) throws -> Data
        ) throws -> Data {
            guard version >= 2 else { return try plaintextHash(algorithm) }
            let message = SignatureStanza.v2Message(
                plaintextSHA512: try plaintextHash(.sha512),
                recipientsDigest: recipientsDigest,
                originalName: ""
            )
            return algorithm.digest(message)
        }

        /// Verify the signature over `plaintext` under this version's namespace and message.
        @discardableResult
        public func verify(plaintext: Data) throws -> SSHSigVerification {
            try SSHSigVerifier.verify(
                message: signedMessage(plaintext: plaintext),
                armoredSignature: signatureArmored,
                expectedNamespace: namespace
            )
        }

        /// Verify when the plaintext has streamed past and only its hashes are left.
        @discardableResult
        public func verify(plaintextHash: (SSHSigHash) throws -> Data) throws -> SSHSigVerification {
            try SSHSigVerifier.verify(
                armoredSignature: signatureArmored,
                expectedNamespace: namespace,
                messageHash: { try messageDigest($0, plaintextHash: plaintextHash) }
            )
        }
    }

    /// The signature stanza among `stanzas`, or nil.
    public static func find(in stanzas: [Stanza]) -> Stanza? {
        stanzas.first { $0.type == type }
    }

    /// Three-way read of a header's signature stanza. `stanzas` is the whole parsed
    /// header (v2 needs it to rebuild what was signed). The header MAC must already
    /// have been checked under `fileKey`.
    public static func openHeader(fileKey: Data, stanzas: [Stanza]) -> Opening {
        let sigs = stanzas.filter { $0.type == type }
        if sigs.isEmpty { return .absent }
        if sigs.count > 1 { return .unreadable("the header has more than one signature stanza") }
        return openOne(fileKey: fileKey, stanza: sigs[0], headerStanzas: stanzas)
    }

    // MARK: - v2 message

    /// The v2 signed message for a plaintext whose SHA-512 is `plaintextSHA512`,
    /// encrypted to `headerStanzas` (any sig stanza among them is skipped).
    public static func v2Message(plaintextSHA512: Data, headerStanzas: [Stanza], originalName: String = "") -> Data {
        v2Message(plaintextSHA512: plaintextSHA512, recipientsDigest: recipientsDigest(headerStanzas), originalName: originalName)
    }

    /// SHA-512(R) over every non-signature stanza of `headerStanzas`, in order.
    public static func recipientsDigest(_ headerStanzas: [Stanza]) -> Data {
        let kept = headerStanzas.filter { $0.type != type }
        var w = SSHWireWriter()
        w.writeUInt32(UInt32(kept.count))
        for s in kept {
            w.writeString(Data(s.type.utf8))
            w.writeUInt32(UInt32(s.args.count))
            for a in s.args { w.writeString(Data(a.utf8)) }
            w.writeString(s.body)
        }
        return Data(SHA512.hash(data: w.data))
    }

    static func v2Message(plaintextSHA512: Data, recipientsDigest: Data, originalName: String) -> Data {
        precondition(plaintextSHA512.count == 64, "plaintext hash must be SHA-512 (64 bytes)")
        var w = SSHWireWriter()
        w.writeString(Data(messageDomainV2.utf8))
        w.writeString(plaintextSHA512)
        w.writeString(recipientsDigest)
        w.writeString(Data(originalName.utf8))
        return w.data
    }

    // MARK: - Internals

    static func key(fileKey: Data, info: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: fileKey),
            salt: Data(),
            info: Data(info.utf8),
            outputByteCount: keyLength
        )
    }

    static func seal(fileKey: Data, info: String, version: String, signatureArmored: String) throws -> Stanza {
        let box = try ChaChaPoly.seal(
            Data(signatureArmored.utf8),
            using: key(fileKey: fileKey, info: info),
            nonce: ChaChaPoly.Nonce()
        )
        // `combined` is nonce || ciphertext || tag, which is the stanza body layout.
        return Stanza(type: type, args: [version], body: box.combined)
    }

    static func openOne(fileKey: Data, stanza: Stanza, headerStanzas: [Stanza]) -> Opening {
        let version: Int
        let info: String
        switch stanza.args.first {
        case versionV1:
            // v1 readers never looked past the first argument; keep that.
            version = 1; info = keyInfoV1
        case versionV2:
            guard stanza.args.count == 1 else { return .unreadable("v2 signature stanza has unexpected arguments") }
            version = 2; info = keyInfoV2
        case nil:
            return .unreadable("signature stanza has no version")
        case let other?:
            return .unreadable("unsupported signature stanza version '\(other)'")
        }
        guard stanza.body.count >= nonceLength + tagLength else {
            return .unreadable("signature stanza body is too short")
        }
        let plain: Data
        do {
            let box = try ChaChaPoly.SealedBox(combined: stanza.body)
            plain = try ChaChaPoly.open(box, using: key(fileKey: fileKey, info: info))
        } catch {
            return .unreadable("signature stanza does not open under this file's key")
        }
        guard plain.count <= maxSignatureBytes else { return .unreadable("signature stanza is too large") }
        return .opened(Opened(
            signatureArmored: String(decoding: plain, as: UTF8.self),
            version: version,
            recipientsDigest: version >= 2 ? recipientsDigest(headerStanzas) : Data()
        ))
    }
}
