//
//  SSHSigVerifier.swift
//  AgePonyCore
//
//  Verifies SSHSIG detached signatures. A0 handles ssh-ed25519; rsa-sha2-512
//  (D0) and ecdsa-sha2-nistp256 (E0) branch in later.
//
//  Important distinction: this verifies *cryptographic validity* — that the
//  signature was made by whoever holds the private half of the public key
//  embedded in the signature, over this exact message and namespace. That is
//  NOT a trust decision. Anyone can sign anything with their own key. The
//  trust step — "is this signer one I allow?" — is done by the caller
//  matching `result.publicKeyWire` against the trusted-signers list
//  (see AllowedSigners). Keeping the two separate is deliberate.
//

import Foundation
import CryptoKit
import Security

public struct SSHSigVerification: Equatable {
    /// Signer public key in SSH wire format (match this against trusted signers).
    public let publicKeyWire: Data
    /// Key algorithm, e.g. "ssh-ed25519".
    public let keyType: String
    /// Namespace carried by the signature.
    public let namespace: String
    /// Hash algorithm used for the message digest.
    public let hash: SSHSigHash
    /// For an `sk-*` signature, the FIDO authenticator-data flags byte; nil otherwise.
    public let skFlags: UInt8?

    public init(publicKeyWire: Data, keyType: String, namespace: String, hash: SSHSigHash, skFlags: UInt8? = nil) {
        self.publicKeyWire = publicKeyWire
        self.keyType = keyType
        self.namespace = namespace
        self.hash = hash
        self.skFlags = skFlags
    }

    /// For an `sk-*` signature: whether the key saw a touch (UP, flags bit 0). Nil otherwise.
    public var userPresent: Bool? { skFlags.map { $0 & SSHSigVerifier.skFlagUserPresent != 0 } }

    /// For an `sk-*` signature: whether the key verified the user (UV, flags bit 2: a PIN
    /// or on-key biometric). Nil otherwise. `verify-required` signers need it.
    public var userVerified: Bool? { skFlags.map { $0 & SSHSigVerifier.skFlagUserVerified != 0 } }
}

public enum SSHSigVerifier {

    /// FIDO authenticator-data flags.
    public static let skFlagUserPresent: UInt8 = 0x01
    public static let skFlagUserVerified: UInt8 = 0x04

    /// Largest armored signature accepted. A real SSHSIG is a few hundred bytes (about
    /// 2 KiB for RSA-8192), so this only turns away crafted blobs.
    public static let maxSignatureBytes = 16 * 1024

    /// OpenSSH's RSA modulus bounds for signers.
    public static let rsaMinModulusBits = 1024
    public static let rsaMaxModulusBits = 16384

    /// Verify an armored signature over `message`.
    ///
    /// - Parameters:
    ///   - message: the exact bytes that were signed.
    ///   - armoredSignature: the `-----BEGIN SSH SIGNATURE-----` text.
    ///   - expectedNamespace: if non-nil, the signature's namespace must match
    ///     (defaults to AgePony's brand). Pass nil to accept any namespace and
    ///     read it back from the result.
    /// - Returns: details of the (cryptographically valid) signer.
    /// - Throws: `SSHSigError.signatureInvalid` if the math doesn't check out,
    ///   `.namespaceMismatch` if the namespace is wrong, or a parse error.
    ///
    /// `allowNoTouch`: an `sk-*` signature made without a touch (UP flag clear) throws
    /// `.userPresenceRequired` unless this is true, as OpenSSH only accepts one when the
    /// signer's allowed_signers entry says `no-touch-required` (audit L-7).
    @discardableResult
    public static func verify(
        message: Data,
        armoredSignature: String,
        expectedNamespace: String? = SSHSig.defaultNamespace,
        allowNoTouch: Bool = false
    ) throws -> SSHSigVerification {
        try verify(
            armoredSignature: armoredSignature,
            expectedNamespace: expectedNamespace,
            allowNoTouch: allowNoTouch,
            messageHash: { $0.digest(message) }
        )
    }

    /// Verify against a digest supplied on demand, rather than the message.
    ///
    /// SSHSIG covers only the hash, so a message that cannot be held -- or that
    /// has already streamed past, as a signed bundle's payload has by the time
    /// its signature entry is read -- can still be verified.
    ///
    /// `messageHash` is asked for the algorithm named in the signature, which
    /// is not known until the signature has been parsed. Callers that computed
    /// digests ahead of time should have computed every algorithm they might be
    /// asked for; `SignedBundle.StreamParsed` does exactly that.
    @discardableResult
    public static func verify(
        armoredSignature: String,
        expectedNamespace: String? = SSHSig.defaultNamespace,
        allowNoTouch: Bool = false,
        messageHash: (SSHSigHash) throws -> Data
    ) throws -> SSHSigVerification {
        guard armoredSignature.utf8.count <= maxSignatureBytes else { throw SSHSigError.malformedBlob }
        let blob = try SSHSig.parseArmored(armoredSignature)

        if let expected = expectedNamespace, expected != blob.namespace {
            throw SSHSigError.namespaceMismatch(expected: expected, found: blob.namespace)
        }

        let keyType = try SSHSig.publicKeyType(blob.publicKeyWire)
        let (innerType, rawSig) = try SSHSig.parseInnerSignature(blob.signature)

        let digest = try messageHash(blob.hash)
        try blob.hash.validate(digest: digest)
        let signed = SSHSig.signedData(
            messageHash: digest,
            namespace: blob.namespace,
            hash: blob.hash
        )

        var skFlags: UInt8?
        switch keyType {
        case "ssh-ed25519":
            guard innerType == "ssh-ed25519" else { throw SSHSigError.malformedInnerSignature }
            guard rawSig.count == 64 else { throw SSHSigError.malformedInnerSignature }
            let rawPub = try SSHSig.ed25519RawPublicKey(fromWire: blob.publicKeyWire)
            let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawPub)
            guard pubKey.isValidSignature(rawSig, for: signed) else {
                throw SSHSigError.signatureInvalid
            }
        case "ssh-rsa":
            guard innerType == "rsa-sha2-512" else { throw SSHSigError.malformedInnerSignature }
            let (e, n) = try SSHSig.rsaComponents(fromWire: blob.publicKeyWire)
            // Refuse weak or DoS-shaped RSA keys before any modular arithmetic.
            try checkRSASigner(e: e, n: n)
            let pubKey = try RSAKey.makePublic(n: n, e: e)
            var err: Unmanaged<CFError>?
            let ok = SecKeyVerifySignature(
                pubKey,
                .rsaSignatureMessagePKCS1v15SHA512,
                signed as CFData,
                rawSig as CFData,
                &err
            )
            guard ok else { throw SSHSigError.signatureInvalid }
        case "ecdsa-sha2-nistp256":
            guard innerType == "ecdsa-sha2-nistp256" else { throw SSHSigError.malformedInnerSignature }
            let q = try SSHSig.ecdsaP256X963(fromWire: blob.publicKeyWire)
            let pubKey = try P256.Signing.PublicKey(x963Representation: q)
            let rawRS = try Self.ecdsaRawRS(fromInner: rawSig)
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: rawRS)
            guard pubKey.isValidSignature(signature, for: signed) else {
                throw SSHSigError.signatureInvalid
            }
        case "sk-ssh-ed25519@openssh.com":
            let (innerT, sig, flags, counter) = try SSHSig.parseSkInnerSignature(blob.signature)
            guard innerT == "sk-ssh-ed25519@openssh.com", sig.count == 64 else {
                throw SSHSigError.malformedInnerSignature
            }
            let (rawPub, app) = try SSHSig.skEd25519Components(fromWire: blob.publicKeyWire)
            let authMsg = SSHSig.skAuthenticatorMessage(
                application: app, flags: flags, counter: counter, signedData: signed
            )
            let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawPub)
            guard pubKey.isValidSignature(sig, for: authMsg) else {
                throw SSHSigError.signatureInvalid
            }
            skFlags = flags

        case "sk-ecdsa-sha2-nistp256@openssh.com":
            let (innerT, sigBlob, flags, counter) = try SSHSig.parseSkInnerSignature(blob.signature)
            guard innerT == "sk-ecdsa-sha2-nistp256@openssh.com" else {
                throw SSHSigError.malformedInnerSignature
            }
            let (q, app) = try SSHSig.skEcdsaP256Components(fromWire: blob.publicKeyWire)
            let authMsg = SSHSig.skAuthenticatorMessage(
                application: app, flags: flags, counter: counter, signedData: signed
            )
            let pubKey = try P256.Signing.PublicKey(x963Representation: q)
            let rawRS = try Self.ecdsaRawRS(fromInner: sigBlob)
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: rawRS)
            guard pubKey.isValidSignature(signature, for: authMsg) else {
                throw SSHSigError.signatureInvalid
            }
            skFlags = flags

        default:
            throw SSHSigError.unsupportedKeyType(keyType)
        }

        if let skFlags, skFlags & skFlagUserPresent == 0, !allowNoTouch {
            throw SSHSigError.userPresenceRequired
        }

        return SSHSigVerification(
            publicKeyWire: blob.publicKeyWire,
            keyType: keyType,
            namespace: blob.namespace,
            hash: blob.hash,
            skFlags: skFlags
        )
    }

    /// OpenSSH's limits on an RSA signer: 1024 to 16384 bits, odd exponent 3 <= e < 2^32.
    static func checkRSASigner(e: Data, n: Data) throws {
        let nb = Array(n.drop(while: { $0 == 0 }))
        let bits = nb.isEmpty ? 0 : (nb.count - 1) * 8 + (8 - nb[0].leadingZeroBitCount)
        guard bits >= rsaMinModulusBits, bits <= rsaMaxModulusBits else { throw SSHSigError.unsupportedKeyType("ssh-rsa (\(bits) bits)") }
        let eb = Array(e.drop(while: { $0 == 0 }))
        guard !eb.isEmpty, eb.count <= 4, eb.last! & 1 == 1 else { throw SSHSigError.malformedPublicKey }
        let ev = eb.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        guard ev >= 3 else { throw SSHSigError.malformedPublicKey }
    }

    /// Verify, and additionally require that the signer is trusted for the
    /// given principal in `allowedSigners`. Returns the matched signer entry.
    @discardableResult
    public static func verify(
        message: Data,
        armoredSignature: String,
        principal: String,
        allowedSigners: [AllowedSigner],
        expectedNamespace: String? = SSHSig.defaultNamespace
    ) throws -> (verification: SSHSigVerification, signer: AllowedSigner) {
        let result = try verify(
            message: message,
            armoredSignature: armoredSignature,
            expectedNamespace: expectedNamespace,
            allowNoTouch: true // the matched entry's options decide below
        )
        guard let match = allowedSigners.first(where: { signer in
            signer.matches(principal: principal, publicKeyWire: result.publicKeyWire)
                && signer.accepts(result)
        }) else {
            throw SSHSigError.signatureInvalid
        }
        return (result, match)
    }

    /// Decode the ECDSA inner signature blob (`string(mpint r) || string(mpint s)`)
    /// into a fixed 64-byte `r || s` for CryptoKit's rawRepresentation.
    private static func ecdsaRawRS(fromInner inner: Data) throws -> Data {
        var reader = SSHWireReader(inner)
        guard let r = try? reader.readMPInt(),
              let s = try? reader.readMPInt(),
              let r32 = pad32(r),
              let s32 = pad32(s) else {
            throw SSHSigError.malformedInnerSignature
        }
        return r32 + s32
    }

    /// Strip leading zeros, then left-pad to exactly 32 bytes. Returns nil if
    /// the value is wider than 32 bytes (invalid for P-256).
    private static func pad32(_ value: Data) -> Data? {
        var v = value
        while v.count > 32, v.first == 0 { v = v.dropFirst() }
        guard v.count <= 32 else { return nil }
        return Data(repeating: 0, count: 32 - v.count) + v
    }
}
