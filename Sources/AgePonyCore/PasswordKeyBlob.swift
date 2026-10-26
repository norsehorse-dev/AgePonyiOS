//
//  PasswordKeyBlob.swift
//  AgePonyCore
//
//  The app-owned password/PIN unlock path (4.0.0, Feature B) and the duress
//  check that rides on it. Pure blob logic: the app's Vault owns the files
//  (vault.key.pw and vault.key.duress) and the lifecycle; this type only makes
//  and opens their contents. Mirrors Android `security/PasswordVault.kt`.
//
//  Blob layout, both files: `version(1) ‖ logN(1) ‖ salt(16) ‖ sealed`, where
//  `sealed` is ChaCha20-Poly1305's `nonce(12) ‖ ciphertext ‖ tag(16)` under a
//  key-encryption key (KEK).
//    - The real blob seals the 32-byte vault key (VK).
//    - The duress blob seals 32 random bytes. Its content is never used; a
//      successful open IS the duress signal.
//
//  KEK by version:
//    - v1 (4.0.0 to 5.0.0): KEK = scrypt(secret, salt, 2^logN). Software only, so
//      a copy of the blob could be guessed offline (audit M-2). Still opened, and
//      re-wrapped as v2 by the caller after the next successful unlock
//      (`needsRewrap`).
//    - v2 (5.0.1): KEK = HMAC-SHA256(deviceKey, label ‖ scrypt(secret, salt,
//      2^logN)). The device key is a random secret the app keeps in the Keychain
//      as a this-device-only item (`PasswordDeviceBinding`), so a copy of the blob
//      taken off the phone can't be guessed anywhere else.
//
//  Duress design (settled in the 4.0.0 plan): entering the decoy wipes
//  everything and silently re-bootstraps an empty vault whose real password is
//  the decoy just entered. That orchestration lives in the app's Vault; the
//  contract here is `tryUnlock`'s three-way answer. The duress answer carries the
//  scrypt output already computed for the decoy, so sealing the new vault's key
//  under it costs no second scrypt run and the duress path stays close to a wrong
//  attempt in time (audit M-8).
//
//  Timing discipline: `tryUnlock` runs the same work regardless of which (if
//  either) secret matched and whether either blob exists: one device-key check,
//  then for each slot one scrypt worth 2^16 and one HMAC, against a dummy salt
//  when a blob is absent, with both AEAD opens attempted. A legacy blob at a
//  lower work factor is padded with dummy scrypt runs up to the same cost.
//
//  A PIN is just a password with a numeric keyboard; the app stores which kind
//  the user chose so the unlock screen shows the right input, and nothing here
//  differs between the two apart from the policy for new secrets.
//

import Foundation
import CryptoKit

/// The device-held key mixed into the v2 KEK. The app's implementation keeps a
/// random 32-byte secret in the Keychain; tests pass a software stand-in.
public protocol PasswordDeviceBinding {
    /// Make sure the key exists. Returns true if it had to be created just now.
    func ensureKey() throws -> Bool
    /// HMAC-SHA256 of `data` under the device key. Throws if the key is unusable.
    func mac(_ data: Data) throws -> Data
}

/// A device binding over a key held in memory. Used by tests, and by the app once
/// it has loaded its Keychain secret.
public final class SoftwareDeviceBinding: PasswordDeviceBinding, @unchecked Sendable {
    public private(set) var key: Data?
    private var justCreated: Bool

    /// `justCreated` tells `tryUnlock` the key was made moments ago (the app
    /// found none in the Keychain), so a v2 blob that fails is reported as
    /// `deviceKeyMissing` rather than a wrong password.
    public init(key: Data? = nil, justCreated: Bool = false) {
        self.key = key
        self.justCreated = justCreated
    }

    public func ensureKey() throws -> Bool {
        if key != nil {
            defer { justCreated = false }
            return justCreated
        }
        key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        return true
    }

    public func mac(_ data: Data) throws -> Data {
        guard let key else { throw PasswordKeyBlob.BlobError.deviceKeyMissing }
        return Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    public func forget() { key = nil }
}

public enum PasswordKeyBlob {

    public enum BlobError: Error, Equatable {
        case tooShort
        case unknownVersion(UInt8)
        case implausibleWorkFactor(Int)
        /// A v2 blob whose device key is gone (or was just recreated). It can
        /// never open again; the app offers a reset instead of "wrong password"
        /// forever.
        case deviceKeyMissing
        case shortMAC
        case duressMaterialUsed
    }

    /// Result of checking a secret against the stored blobs.
    public enum Outcome: Sendable {
        /// The real secret: here is the recovered 32-byte vault key. `needsRewrap`
        /// is true for a v1 blob or one below the current work factor; the caller
        /// re-wraps it with `wrapVaultKey` while it still has the secret.
        case real(vaultKey: Data, needsRewrap: Bool)
        /// The decoy secret: the caller wipes and re-bootstraps, sealing the new
        /// vault key with `DuressMaterial.wrapNewVaultKey`.
        case duress(DuressMaterial)
        /// Neither secret matched.
        case wrong

        public var isWrong: Bool { if case .wrong = self { return true }; return false }
        public var isDuress: Bool { if case .duress = self { return true }; return false }
    }

    /// The decoy's salt and scrypt output from `tryUnlock`, usable once.
    public final class DuressMaterial: @unchecked Sendable {
        private var stretched: [UInt8]
        private let salt: Data
        private let logN: Int
        private var used = false

        init(stretched: [UInt8], salt: Data, logN: Int) {
            self.stretched = stretched
            self.salt = salt
            self.logN = logN
        }

        deinit { wipe() }

        /// Build a v2 real blob sealing `vaultKey` under the decoy secret, reusing
        /// the decoy's salt and scrypt output with `binding` (normally a freshly
        /// rotated device key). Wipes the held material afterwards.
        public func wrapNewVaultKey(_ vaultKey: Data, binding: PasswordDeviceBinding) throws -> Data {
            guard !used else { throw BlobError.duressMaterialUsed }
            defer { wipe() }
            _ = try binding.ensureKey()
            let kek = try PasswordKeyBlob.bind(binding, stretched)
            var blob = Data([PasswordKeyBlob.versionV2, UInt8(logN)])
            blob.append(salt)
            blob.append(try PasswordKeyBlob.seal(kek: kek, plaintext: vaultKey))
            return blob
        }

        public func wipe() {
            for i in stretched.indices { stretched[i] = 0 }
            used = true
        }
    }

    static let versionV1: UInt8 = 1
    static let versionV2: UInt8 = 2
    /// Work factor for new blobs. 2^16 with r=8 is 64 MiB and a few hundred ms per
    /// derivation. Unlock pays two derivations (real + duress) by design, so this
    /// stays below the age-file default of 2^18; since 5.0.1 the KEK also needs
    /// this device's key, so the work factor only has to slow on-device guessing,
    /// which the failed-attempt backoff (`UnlockAttempts`) limits as well. 4.0.0 to
    /// 5.0.0 used 2^15.
    static let logN: Int = 16
    static let r: Int = 8
    static let p: Int = 1
    static let saltLen = 16
    static let keyLen = 32
    /// Smallest parseable blob: header(2) + salt(16) + nonce(12) + tag(16).
    static let minBlobSize = 2 + 16 + 12 + 16
    static let bindLabel = Data("AgePony password KEK v2".utf8)

    /// Minimum lengths for a new or changed secret (audit M-1). Existing shorter
    /// ones still unlock.
    public static let minPINLength = 6
    public static let minPasswordLength = 8

    // MARK: - Policy

    /// Why `secret` can't be used as a new or changed secret, or nil if it can. A
    /// PIN must be digits only, since the unlock screen shows a number pad for it.
    public static func policyError(secret: String, isPIN: Bool) -> String? {
        if isPIN {
            if secret.contains(where: { !("0"..."9").contains($0) }) { return "A PIN can only contain digits." }
            if secret.count < minPINLength { return "Use at least \(minPINLength) digits." }
            return nil
        }
        return secret.count < minPasswordLength ? "Use at least \(minPasswordLength) characters." : nil
    }

    // MARK: - Build

    /// Build the real blob (v2): `vaultKey` sealed under a KEK derived from `secret`.
    public static func wrapVaultKey(secret: String, vaultKey: Data, binding: PasswordDeviceBinding) throws -> Data {
        try buildBlob(secret: secret, plaintext: vaultKey, binding: binding)
    }

    /// Build the duress blob (v2): 32 random bytes sealed under the decoy-derived KEK.
    public static func duressBlob(secret: String, binding: PasswordDeviceBinding) throws -> Data {
        let filler = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        return try buildBlob(secret: secret, plaintext: filler, binding: binding)
    }

    /// The format version of a stored blob, nil if it is too short to say.
    public static func version(of blob: Data) -> UInt8? {
        blob.count >= minBlobSize ? blob[blob.startIndex] : nil
    }

    // MARK: - Unlock

    /// Check `secret` against both blobs, constant-shape. Pass nil for a blob that
    /// is not set; the corresponding derivation still runs against a dummy salt so
    /// absence does not change the work done. Real wins over duress by fixed order
    /// (enrollment refuses a duress secret equal to the real one).
    public static func tryUnlock(secret: String, realBlob: Data?, duressBlob: Data?,
                                 binding: PasswordDeviceBinding) throws -> Outcome {
        // One key check up front whatever blobs exist, so the call pattern doesn't
        // depend on them. A failure here only matters to v2 blobs (their HMAC fails).
        let keyCreated = (try? binding.ensureKey()) ?? false
        var real = try attempt(secret: secret, blob: realBlob, binding: binding)
        var duress = try attempt(secret: secret, blob: duressBlob, binding: binding)
        defer {
            for i in real.stretched.indices { real.stretched[i] = 0 }
            for i in duress.stretched.indices { duress.stretched[i] = 0 }
        }
        if let vaultKey = real.opened { return .real(vaultKey: vaultKey, needsRewrap: real.legacy) }
        if duress.opened != nil {
            return .duress(DuressMaterial(stretched: duress.stretched, salt: duress.salt, logN: duress.logN))
        }
        if real.version == versionV2 && (real.bindingFailed || keyCreated) { throw BlobError.deviceKeyMissing }
        return .wrong
    }

    /// A 4.0.0-style v1 blob, for migration tests only.
    static func legacyV1Blob(secret: String, plaintext: Data, logN v1LogN: Int = 15) throws -> Data {
        let salt = SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }
        let kek = SymmetricKey(data: Data(try derive(secret: secret, salt: salt, logN: v1LogN)))
        var blob = Data([versionV1, UInt8(v1LogN)])
        blob.append(salt)
        blob.append(try seal(kek: kek, plaintext: plaintext))
        return blob
    }

    // MARK: - Internals

    private struct Attempt {
        var opened: Data?
        var stretched: [UInt8]
        var salt: Data
        var logN: Int
        var version: UInt8
        var legacy: Bool
        var bindingFailed: Bool
    }

    private static func buildBlob(secret: String, plaintext: Data, binding: PasswordDeviceBinding) throws -> Data {
        _ = try binding.ensureKey()
        let salt = SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }
        var stretched = try derive(secret: secret, salt: salt, logN: logN)
        defer { for i in stretched.indices { stretched[i] = 0 } }
        let kek = try bind(binding, stretched)
        var blob = Data([versionV2, UInt8(logN)])
        blob.append(salt)
        blob.append(try seal(kek: kek, plaintext: plaintext))
        return blob
    }

    /// Derive against `blob`'s own salt and try to open it. When `blob` is nil the
    /// derivation and HMAC run against a dummy salt and the open is skipped.
    private static func attempt(secret: String, blob: Data?, binding: PasswordDeviceBinding) throws -> Attempt {
        guard let blob else {
            let dummy = Data(count: saltLen)
            let stretched = try derive(secret: secret, salt: dummy, logN: logN)
            _ = try? bind(binding, stretched)
            return Attempt(opened: nil, stretched: stretched, salt: dummy, logN: logN, version: 0,
                           legacy: false, bindingFailed: false)
        }
        guard blob.count >= minBlobSize else { throw BlobError.tooShort }
        let base = blob.startIndex
        let version = blob[base]
        guard version == versionV1 || version == versionV2 else { throw BlobError.unknownVersion(version) }
        let blobLogN = Int(blob[base + 1])
        guard blobLogN >= 10, blobLogN <= 22 else { throw BlobError.implausibleWorkFactor(blobLogN) }
        let saltStart = base + 2
        let salt = Data(blob[saltStart ..< saltStart + saltLen])
        let sealed = Data(blob[(saltStart + saltLen)...])
        let stretched = try derive(secret: secret, salt: salt, logN: blobLogN)
        try padWork(secret: secret, logN: blobLogN)
        // Always one HMAC, so a v1 blob costs the same work as a v2 one.
        let bound = try? bind(binding, stretched)
        let kek: SymmetricKey? = version == versionV2 ? bound : SymmetricKey(data: Data(stretched))
        return Attempt(opened: kek.flatMap { open(kek: $0, sealed: sealed) },
                       stretched: stretched, salt: salt, logN: blobLogN, version: version,
                       legacy: version == versionV1 || blobLogN < logN,
                       bindingFailed: version == versionV2 && bound == nil)
    }

    /// Bring a blob below `logN` up to the same scrypt cost with dummy runs at its
    /// own work factor (scrypt time is linear in N), so an old 2^15 duress blob next
    /// to a new 2^16 real one doesn't show in unlock timing.
    private static func padWork(secret: String, logN blobLogN: Int) throws {
        guard blobLogN < logN else { return }
        for _ in 0 ..< ((1 << (logN - blobLogN)) - 1) {
            var d = try derive(secret: secret, salt: Data(count: saltLen), logN: blobLogN)
            for i in d.indices { d[i] = 0 }
        }
    }

    static func bind(_ binding: PasswordDeviceBinding, _ stretched: [UInt8]) throws -> SymmetricKey {
        var input = bindLabel
        input.append(contentsOf: stretched)
        defer { input.resetBytes(in: 0 ..< input.count) }
        let out = try binding.mac(input)
        guard out.count >= keyLen else { throw BlobError.shortMAC }
        return SymmetricKey(data: out.prefix(keyLen))
    }

    private static func derive(secret: String, salt: Data, logN: Int) throws -> [UInt8] {
        var pw = Array(secret.utf8)
        defer { for i in pw.indices { pw[i] = 0 } }
        return try Scrypt.scrypt(password: pw, salt: Array(salt), n: 1 << logN, r: r, p: p, dkLen: keyLen)
    }

    static func seal(kek: SymmetricKey, plaintext: Data) throws -> Data {
        try ChaChaPoly.seal(plaintext, using: kek).combined // nonce(12) ‖ ciphertext ‖ tag(16)
    }

    private static func open(kek: SymmetricKey, sealed: Data) -> Data? {
        guard let box = try? ChaChaPoly.SealedBox(combined: sealed) else { return nil }
        return try? ChaChaPoly.open(box, using: kek)
    }
}
