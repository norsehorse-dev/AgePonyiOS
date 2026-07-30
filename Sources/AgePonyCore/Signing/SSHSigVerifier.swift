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

    public init(publicKeyWire: Data, keyType: String, namespace: String, hash: SSHSigHash) {
        self.publicKeyWire = publicKeyWire
        self.keyType = keyType
        self.namespace = namespace
        self.hash = hash
    }
}

public enum SSHSigVerifier {

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
    @discardableResult
    public static func verify(
        message: Data,
        armoredSignature: String,
        expectedNamespace: String? = SSHSig.defaultNamespace
    ) throws -> SSHSigVerification {
        try verify(
            armoredSignature: armoredSignature,
            expectedNamespace: expectedNamespace,
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
        messageHash: (SSHSigHash) throws -> Data
    ) throws -> SSHSigVerification {
        let blob = try SSHSig.parseArmored(armoredSignature)

        if let expected = expectedNamespace, expected != blob.namespace {
            throw SSHSigError.namespaceMismatch(expected: expected, found: blob.namespace)
        }

        let keyType = try SSHSig.publicKeyType(blob.publicKeyWire)
        let (innerType, rawSig) = try SSHSig.parseInnerSignature(blob.signature)

        let signed = SSHSig.signedData(
            messageHash: try messageHash(blob.hash),
            namespace: blob.namespace,
            hash: blob.hash
        )

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

        default:
            throw SSHSigError.unsupportedKeyType(keyType)
        }

        return SSHSigVerification(
            publicKeyWire: blob.publicKeyWire,
            keyType: keyType,
            namespace: blob.namespace,
            hash: blob.hash
        )
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
            expectedNamespace: expectedNamespace
        )
        guard let match = allowedSigners.first(where: { signer in
            signer.matches(principal: principal, publicKeyWire: result.publicKeyWire)
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
