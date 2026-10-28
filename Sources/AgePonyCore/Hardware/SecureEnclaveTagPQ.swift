//
//  SecureEnclaveTagPQ.swift
//  AgePonyCore
//
//  The private material the app's vault keeps for an `age1tagpq1` hardware key
//  (`StoredIdentityType.secureEnclaveTagPQ`), and how a key is made and rebuilt from it.
//
//  Two layouts share the one stored type:
//
//    5.0.1 ("vault seed"), every key made before 5.1.0 or below iOS 26:
//        ML-KEM seed (64 bytes, d || z) || P-256 Enclave dataRepresentation
//
//    5.1.0 on iOS 26 and later ("Enclave"), both halves in the Secure Enclave:
//        "AGPNSE2\0" (8 bytes: magic and layout version)
//        || UInt32 big-endian length of the ML-KEM Enclave blob || ML-KEM Enclave blob
//        || P-256 Enclave dataRepresentation (the rest)
//
//  Why not a new stored type: 5.0.1 decodes `StoredIdentityType` as a strict Codable
//  enum inside one `[StoredIdentity]` array, so an unknown case would make the whole
//  vault fail to open after a downgrade (TestFlight back to 5.0.1, or an older backup
//  of the app). With the same type and a new layout, a 5.0.1 build opens the vault, lists
//  the key, shows its recipient and encrypts to it; only decrypting with it fails, and
//  per key: 5.0.1 reads the first 64 bytes as an ML-KEM seed (a wrong key, so a wrong
//  secret, never a crash) and the rest as a P-256 blob the Enclave refuses, which throws
//  `SecureEnclaveKeyError.invalidKeyData` from that one identity.
//
//  Telling them apart: the Enclave layout is recognised only when the magic matches AND
//  the length field fits (a blob of 1...65536 bytes, with a non-empty P-256 blob after
//  it). Anything else is the 5.0.1 layout. A random 64-byte seed starts with the 8 magic
//  bytes with probability 2^-64, and would then also need a fitting length field.
//

import Foundation
#if os(iOS) || os(macOS)
import LocalAuthentication
#endif

public enum SecureEnclaveTagPQMaterialError: Error, Equatable {
    /// Too short for either layout, or an Enclave blob outside the allowed size.
    case malformed
}

public enum SecureEnclaveTagPQMaterial: Equatable {
    /// 5.0.1 layout: the ML-KEM half is a 64-byte seed in the vault.
    case vaultSeed(mlkemSeed: Data, p256Blob: Data)
    /// 5.1.0 layout (iOS 26 and later): both halves are Secure Enclave keys.
    case enclave(mlkemBlob: Data, p256Blob: Data)

    /// Length of the ML-KEM seed at the front of the 5.0.1 layout.
    public static let mlkemSeedSize = 64
    /// "AGPNSE2" and a zero byte: AgePony, Secure Enclave, layout 2.
    public static let magic = Data("AGPNSE2\0".utf8)
    static let lengthFieldSize = 4
    /// Upper bound on either Enclave blob (ML-KEM was 1489 bytes in the spike, P-256 324).
    static let maxBlobSize = 1 << 16

    /// Whether the ML-KEM half is in the Secure Enclave.
    public var mlkemInEnclave: Bool {
        if case .enclave = self { return true }
        return false
    }

    public var p256Blob: Data {
        switch self {
        case .vaultSeed(_, let blob), .enclave(_, let blob): return blob
        }
    }

    /// The bytes to store as `privateKeyMaterial`.
    public func encoded() throws -> Data {
        switch self {
        case .vaultSeed(let seed, let p256):
            guard seed.count == Self.mlkemSeedSize, !p256.isEmpty else { throw SecureEnclaveTagPQMaterialError.malformed }
            return Data(seed) + Data(p256)
        case .enclave(let mlkem, let p256):
            guard (1...Self.maxBlobSize).contains(mlkem.count),
                  (1...Self.maxBlobSize).contains(p256.count) else { throw SecureEnclaveTagPQMaterialError.malformed }
            let n = UInt32(mlkem.count)
            let length = Data([UInt8(truncatingIfNeeded: n >> 24), UInt8(truncatingIfNeeded: n >> 16),
                               UInt8(truncatingIfNeeded: n >> 8), UInt8(truncatingIfNeeded: n)])
            return Self.magic + length + Data(mlkem) + Data(p256)
        }
    }

    /// Read stored `privateKeyMaterial` in either layout.
    public static func decode(_ material: Data) throws -> SecureEnclaveTagPQMaterial {
        let b = [UInt8](material)
        if let enclave = decodeEnclave(b) { return enclave }
        // 5.0.1 layout: the same rule 5.0.1 applied (more than the seed).
        guard b.count > mlkemSeedSize else { throw SecureEnclaveTagPQMaterialError.malformed }
        return .vaultSeed(mlkemSeed: Data(b[0..<mlkemSeedSize]), p256Blob: Data(b[mlkemSeedSize...]))
    }

    private static func decodeEnclave(_ b: [UInt8]) -> SecureEnclaveTagPQMaterial? {
        let header = magic.count + lengthFieldSize
        guard b.count > header, Data(b[0..<magic.count]) == magic else { return nil }
        let i = magic.count
        let n = Int(b[i]) << 24 | Int(b[i + 1]) << 16 | Int(b[i + 2]) << 8 | Int(b[i + 3])
        guard (1...maxBlobSize).contains(n), header + n < b.count else { return nil }
        let p256Count = b.count - header - n
        guard p256Count <= maxBlobSize else { return nil }
        return .enclave(mlkemBlob: Data(b[header..<(header + n)]), p256Blob: Data(b[(header + n)...]))
    }
}

#if os(iOS) || os(macOS)
/// Making and rebuilding `age1tagpq1` hardware keys, for the app's vault.
public enum SecureEnclaveTagPQ {

    /// Whether a new key gets its ML-KEM half in the Secure Enclave: iOS 26 / macOS 26
    /// or later, built with the iOS 26 SDK, on a device with an Enclave.
    public static var mlkemInEnclaveAvailable: Bool {
        #if compiler(>=6.2)
        if #available(iOS 26, macOS 26, *) {
            return SecureEnclaveMLKEM.isAvailable
        }
        #endif
        return false
    }

    /// Make a new key with `protection` on every Enclave half. Returns the vault's
    /// `privateKeyMaterial` and the 1249-byte public key (ML-KEM ek || P-256 point).
    public static func generate(protection: SecureEnclaveKeyProtection) throws -> (privateKeyMaterial: Data, publicKey: Data) {
        try generate(protection: protection, mlkemInEnclave: mlkemInEnclaveAvailable)
    }

    /// Makes an Enclave ML-KEM key: (dataRepresentation, encapsulationKey).
    typealias EnclaveMLKEMMaker = (SecureEnclaveKeyProtection) throws -> (dataRepresentation: Data, encapsulationKey: Data)

    /// `mlkemInEnclave` false makes a 5.0.1-layout key (tests). `makeEnclaveMLKEM` replaces
    /// `SecureEnclaveMLKEM.generate` (tests). If the Enclave won't make the ML-KEM key
    /// (review fix 3), the key is still made, in the vault-seed layout with the P-256 key
    /// already made, so a quantum-safe hardware key can always be created; the identity
    /// page reads the stored layout and says where its ML-KEM half is.
    static func generate(protection: SecureEnclaveKeyProtection,
                         mlkemInEnclave: Bool,
                         makeEnclaveMLKEM: EnclaveMLKEMMaker? = nil) throws -> (privateKeyMaterial: Data, publicKey: Data) {
        let p256 = try SecureEnclaveKeyAgreement.generate(protection: protection)
        #if compiler(>=6.2)
        if #available(iOS 26, macOS 26, *), mlkemInEnclave {
            let make: EnclaveMLKEMMaker = makeEnclaveMLKEM ?? { try SecureEnclaveMLKEM.generate(protection: $0) }
            if let mlkem = try? make(protection) {
                let material = try SecureEnclaveTagPQMaterial.enclave(mlkemBlob: mlkem.dataRepresentation,
                                                                      p256Blob: p256.dataRepresentation).encoded()
                return (material, mlkem.encapsulationKey + p256.publicUncompressed)
            }
        }
        #endif
        let seed = MLKEM768.randomBytes(SecureEnclaveTagPQMaterial.mlkemSeedSize)
        let mlkem = try HybridKEMBackend.mlkemKey(seed: seed)   // CryptoKit on 26, own code before
        let material = try SecureEnclaveTagPQMaterial.vaultSeed(mlkemSeed: seed, p256Blob: p256.dataRepresentation).encoded()
        return (material, mlkem.encapsulationKey + p256.publicUncompressed)
    }

    /// Rebuild the identity from the vault. `authenticationContext` is a context the app
    /// has just evaluated. An Enclave-layout key gives both halves the same context (a
    /// new one when none is passed), so a key that wants Face ID asks once for the pair.
    public static func identity(privateKeyMaterial: Data,
                                publicKey: Data,
                                authenticationContext: LAContext?) throws -> TagIdentity {
        guard publicKey.count == HpkeP256.hybridPublicKeySize else { throw SecureEnclaveTagPQMaterialError.malformed }
        let p256Point = Data(publicKey.suffix(P256Curve.uncompressedSize))
        switch try SecureEnclaveTagPQMaterial.decode(privateKeyMaterial) {
        case .vaultSeed(let seed, let blob):
            let se = SecureEnclaveKeyAgreement(dataRepresentation: blob, authenticationContext: authenticationContext)
            return try TagIdentity.hybrid(mlkemSeed: seed, p256PublicKey: p256Point, p256: se)
        case .enclave(let mlkemBlob, let p256Blob):
            #if compiler(>=6.2)
            if #available(iOS 26, macOS 26, *) {
                let context = authenticationContext ?? LAContext()
                let mlkem = SecureEnclaveMLKEM(dataRepresentation: mlkemBlob,
                                               encapsulationKey: Data(publicKey.prefix(MLKEM768.encapsulationKeySize)),
                                               authenticationContext: context)
                let se = SecureEnclaveKeyAgreement(dataRepresentation: p256Blob, authenticationContext: context)
                return try TagIdentity.hybrid(mlkem: mlkem, p256PublicKey: p256Point, p256: se)
            }
            #endif
            // Below iOS 26 (a vault restored onto an older system): still an identity, so
            // the key isn't silently dropped from a decrypt and the user is told why
            // (review fix 1). Its ML-KEM half refuses with `requiresIOS26`.
            return try unavailableIdentity(mlkemEncapsulationKey: Data(publicKey.prefix(MLKEM768.encapsulationKeySize)),
                                           p256Blob: p256Blob, p256Point: p256Point,
                                           authenticationContext: authenticationContext)
        }
    }

    /// The identity for an Enclave-layout key where the Enclave ML-KEM key can't be used.
    static func unavailableIdentity(mlkemEncapsulationKey: Data, p256Blob: Data, p256Point: Data,
                                    authenticationContext: LAContext?) throws -> TagIdentity {
        let se = SecureEnclaveKeyAgreement(dataRepresentation: p256Blob, authenticationContext: authenticationContext)
        return try TagIdentity.hybrid(mlkem: UnavailableMLKEM(encapsulationKey: mlkemEncapsulationKey),
                                      p256PublicKey: p256Point, p256: se)
    }
}

/// The ML-KEM half of an Enclave-layout key on a system without Enclave ML-KEM (below
/// iOS 26). Not availability-gated. Decapsulating throws `requiresIOS26`; a `TagIdentity`
/// holding it doesn't claim stanzas in `matches`, so a YubiKey addressed by the same
/// file is still offered for a tap instead of being skipped for a key that can't open it.
struct UnavailableMLKEM: MLKEMDecapsulation {
    let encapsulationKey: Data
    func decapsulate(ciphertext: Data) throws -> Data {
        throw SecureEnclaveKeyError.requiresIOS26
    }
}
#endif
