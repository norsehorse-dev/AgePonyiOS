//
//  SSHSigner.swift
//  AgePonyCore
//
//  Produces SSHSIG detached signatures. Ed25519 only in A0 (CryptoKit
//  signs Ed25519 natively); rsa-sha2-512 lands in D0 and ecdsa-sha2-nistp256
//  (Secure Enclave) in E0. The signing key dispatch is structured so those
//  phases slot in without reshaping the call sites.
//
//  Ed25519 signs the signed-data blob directly: Ed25519 performs its own
//  internal SHA-512 over whatever bytes it's handed, and the message is
//  already pre-hashed into the blob per the SSHSIG spec, so there's no
//  double-hash to reconcile. The result is byte-compatible with
//  `ssh-keygen -Y sign`.
//

import Foundation
import CryptoKit
import Security

public enum SSHSigner {

    /// Sign `message` with an Ed25519 key, returning an armored SSH signature
    /// (`-----BEGIN SSH SIGNATURE-----`).
    ///
    /// - Parameters:
    ///   - message: the exact bytes being signed (e.g. a file, or an
    ///     already-encrypted `.age` payload for the sign+encrypt flow).
    ///   - seed: 32-byte Ed25519 private seed (the OpenSSH private half).
    ///   - publicKey: 32-byte raw Ed25519 public key.
    ///   - namespace: signature namespace (defaults to AgePony's brand).
    ///   - hash: message hash algorithm (defaults to sha512, ssh-keygen's default).
    public static func signEd25519(
        message: Data,
        seed: Data,
        publicKey: Data,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        try signEd25519(
            messageHash: hash.digest(message),
            seed: seed,
            publicKey: publicKey,
            namespace: namespace,
            hash: hash
        )
    }

    /// Sign a message *digest* with an Ed25519 key.
    ///
    /// SSHSIG only ever covers the hash, so a file too large to hold in memory can be
    /// signed from `hash.digest(streaming:)` over it. `messageHash` must be a digest
    /// under `hash`; a wrong-length one is rejected rather than signed.
    public static func signEd25519(
        messageHash: Data,
        seed: Data,
        publicKey: Data,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        guard seed.count == 32 else { throw SSHSigError.malformedPublicKey }
        guard publicKey.count == 32 else { throw SSHSigError.malformedPublicKey }
        try hash.validate(digest: messageHash)

        let signed = SSHSig.signedData(messageHash: messageHash, namespace: namespace, hash: hash)

        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let rawSig = try key.signature(for: signed)   // 64 bytes

        // Inner SSH signature wire format.
        var inner = SSHWireWriter()
        inner.writeString("ssh-ed25519")
        inner.writeString(rawSig)

        let blob = SSHSig.Blob(
            publicKeyWire: SSHSig.ed25519PublicKeyWire(publicKey),
            namespace: namespace,
            hash: hash,
            signature: inner.data
        )
        return SSHSig.armor(SSHSig.serialize(blob: blob))
    }

    /// Convenience for the vault's stored Ed25519 private material, which is
    /// laid out as `seed(32) || pub(32)` (64 bytes).
    public static func signEd25519(
        message: Data,
        privateMaterial: Data,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        try signEd25519(
            messageHash: hash.digest(message),
            privateMaterial: privateMaterial,
            namespace: namespace,
            hash: hash
        )
    }

    /// Digest-taking form of the stored-material convenience.
    public static func signEd25519(
        messageHash: Data,
        privateMaterial: Data,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        guard privateMaterial.count == 64 else { throw SSHSigError.malformedPublicKey }
        let seed = privateMaterial.prefix(32)
        let pub  = privateMaterial.suffix(32)
        return try signEd25519(
            messageHash: messageHash,
            seed: Data(seed),
            publicKey: Data(pub),
            namespace: namespace,
            hash: hash
        )
    }

    /// Sign `message` with an RSA key, producing an `rsa-sha2-512` SSHSIG
    /// (matching `ssh-keygen -Y sign` for ssh-rsa keys). The RSA signature is
    /// RSASSA-PKCS1-v1_5 with SHA-512 over the SSHSIG signed-data blob; the
    /// `hash` parameter governs only the message digest inside that blob.
    ///
    /// - Parameters:
    ///   - privateSecKey: the RSA private key (e.g. SSHRSAIdentity.privateSecKey).
    ///   - publicKeyWire: the signer's `ssh-rsa` public-key wire blob
    ///     (e.g. SSHRSAIdentity.wireBlob).
    public static func signRSA(
        message: Data,
        privateSecKey: SecKey,
        publicKeyWire: Data,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        try signRSA(
            messageHash: hash.digest(message),
            privateSecKey: privateSecKey,
            publicKeyWire: publicKeyWire,
            namespace: namespace,
            hash: hash
        )
    }

    /// Digest-taking form of `signRSA`. See `signEd25519(messageHash:...)`.
    public static func signRSA(
        messageHash: Data,
        privateSecKey: SecKey,
        publicKeyWire: Data,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        try hash.validate(digest: messageHash)
        let signed = SSHSig.signedData(messageHash: messageHash, namespace: namespace, hash: hash)

        var err: Unmanaged<CFError>?
        guard let rawSig = SecKeyCreateSignature(
            privateSecKey,
            .rsaSignatureMessagePKCS1v15SHA512,
            signed as CFData,
            &err
        ) as Data? else {
            let msg = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? "unknown"
            throw SSHSigError.signingFailed(msg)
        }

        var inner = SSHWireWriter()
        inner.writeString("rsa-sha2-512")
        inner.writeString(rawSig)

        let blob = SSHSig.Blob(
            publicKeyWire: publicKeyWire,
            namespace: namespace,
            hash: hash,
            signature: inner.data
        )
        return SSHSig.armor(SSHSig.serialize(blob: blob))
    }

    // MARK: - ECDSA P-256 (ecdsa-sha2-nistp256)

    /// Build the ECDSA inner SSH signature from a 64-byte raw `r || s`
    /// (CryptoKit's ECDSASignature.rawRepresentation). The inner form is
    /// `string("ecdsa-sha2-nistp256") || string(string(mpint r) || string(mpint s))`.
    public static func ecdsaP256InnerSignature(rawRS: Data) throws -> Data {
        guard rawRS.count == 64 else { throw SSHSigError.malformedInnerSignature }
        let r = rawRS.prefix(32)
        let s = rawRS.suffix(32)
        var rs = SSHWireWriter()
        rs.writeMPInt(Data(r))
        rs.writeMPInt(Data(s))
        var inner = SSHWireWriter()
        inner.writeString("ecdsa-sha2-nistp256")
        inner.writeString(rs.data)
        return inner.data
    }

    /// Assemble an armored ECDSA SSHSIG from an already-computed raw signature.
    /// This is the path a Secure Enclave key takes: the app signs the
    /// signed-data blob with its SE key, then hands the raw `r || s` and the
    /// key's `x963` public point here. No private key crosses this boundary.
    ///
    /// - Parameters:
    ///   - rawRS: 64-byte `r || s` over `SSHSig.signedData(...)`.
    ///   - publicKeyX963: the signer's P-256 public key as `0x04 || X || Y`.
    public static func assembleECDSAP256(
        rawRS: Data,
        publicKeyX963: Data,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        let inner = try ecdsaP256InnerSignature(rawRS: rawRS)
        let blob = SSHSig.Blob(
            publicKeyWire: SSHSig.ecdsaP256PublicKeyWire(x963Q: publicKeyX963),
            namespace: namespace,
            hash: hash,
            signature: inner
        )
        return SSHSig.armor(SSHSig.serialize(blob: blob))
    }

    // MARK: - FIDO security keys (sk-*)

    /// Append `byte(flags) || uint32(counter)` to a `string(type)||string(sig)`
    /// prefix to form a FIDO inner signature.
    private static func skInner(typeAndSig: Data, flags: UInt8, counter: UInt32) -> Data {
        var out = typeAndSig
        out.append(flags)
        var cw = SSHWireWriter()
        cw.writeUInt32(counter)
        out.append(cw.data)
        return out
    }

    /// Assemble an armored `sk-ssh-ed25519@openssh.com` SSHSIG from the pieces a
    /// FIDO authenticator returns over NFC: the raw 64-byte Ed25519 signature
    /// (over `SSHSig.skAuthenticatorMessage(...)`), plus the flags and counter
    /// from the authenticator data. No private key crosses this boundary.
    public static func assembleSkEd25519(
        publicKey: Data,
        application: Data,
        rawSig: Data,
        flags: UInt8,
        counter: UInt32,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        guard rawSig.count == 64 else { throw SSHSigError.malformedInnerSignature }
        var w = SSHWireWriter()
        w.writeString("sk-ssh-ed25519@openssh.com")
        w.writeString(rawSig)
        let inner = skInner(typeAndSig: w.data, flags: flags, counter: counter)
        let blob = SSHSig.Blob(
            publicKeyWire: SSHSig.skEd25519PublicKeyWire(rawPublicKey: publicKey, application: application),
            namespace: namespace,
            hash: hash,
            signature: inner
        )
        return SSHSig.armor(SSHSig.serialize(blob: blob))
    }

    /// Assemble an armored `sk-ecdsa-sha2-nistp256@openssh.com` SSHSIG. `rawRS`
    /// is the 64-byte `r || s` the authenticator produced (ECDSA-SHA256 over
    /// `SSHSig.skAuthenticatorMessage(...)`).
    public static func assembleSkEcdsaP256(
        publicKeyX963: Data,
        application: Data,
        rawRS: Data,
        flags: UInt8,
        counter: UInt32,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        guard rawRS.count == 64 else { throw SSHSigError.malformedInnerSignature }
        let r = rawRS.prefix(32)
        let sBytes = rawRS.suffix(32)
        var rs = SSHWireWriter()
        rs.writeMPInt(Data(r))
        rs.writeMPInt(Data(sBytes))
        var w = SSHWireWriter()
        w.writeString("sk-ecdsa-sha2-nistp256@openssh.com")
        w.writeString(rs.data)
        let inner = skInner(typeAndSig: w.data, flags: flags, counter: counter)
        let blob = SSHSig.Blob(
            publicKeyWire: SSHSig.skEcdsaP256PublicKeyWire(x963Q: publicKeyX963, application: application),
            namespace: namespace,
            hash: hash,
            signature: inner
        )
        return SSHSig.armor(SSHSig.serialize(blob: blob))
    }

    /// Sign with an in-process P-256 key (used by tests, and usable for any
    /// non-Secure-Enclave P-256 identity). CryptoKit's `signature(for:)`
    /// performs ECDSA over SHA-256 of the bytes it's given; the signed-data
    /// blob has already folded in the message hash per the SSHSIG spec.
    public static func signECDSAP256(
        message: Data,
        privateKey: P256.Signing.PrivateKey,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        try signECDSAP256(
            messageHash: hash.digest(message),
            privateKey: privateKey,
            namespace: namespace,
            hash: hash
        )
    }

    /// Digest-taking form of `signECDSAP256`. See `signEd25519(messageHash:...)`.
    public static func signECDSAP256(
        messageHash: Data,
        privateKey: P256.Signing.PrivateKey,
        namespace: String = SSHSig.defaultNamespace,
        hash: SSHSigHash = .sha512
    ) throws -> String {
        try hash.validate(digest: messageHash)
        let signed = SSHSig.signedData(messageHash: messageHash, namespace: namespace, hash: hash)
        let sig = try privateKey.signature(for: signed)
        return try assembleECDSAP256(
            rawRS: sig.rawRepresentation,
            publicKeyX963: privateKey.publicKey.x963Representation,
            namespace: namespace,
            hash: hash
        )
    }
}
