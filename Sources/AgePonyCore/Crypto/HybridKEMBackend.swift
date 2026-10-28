//
//  HybridKEMBackend.swift
//  AgePonyCore
//
//  5.1.0 RC3 (E8): which code runs the post-quantum KEMs.
//
//    - iOS 26 / macOS 26 and later: Apple CryptoKit (X-Wing HPKE for `mlkem768x25519`,
//      ML-KEM-768 for the ML-KEM half of `mlkem768p256tag`). See CryptoKitPQ.swift.
//    - iOS 17 to 25 / macOS 14 to 15: AgePony's own code (MLKEM768.swift,
//      HpkeMlkem768X25519.swift), unchanged.
//
//  The choice is made behind the same public types (HybridIdentity, HybridRecipient,
//  TagIdentity, TagRecipient), so the app doesn't know which one ran. Every check age
//  requires stays in AgePony and runs before CryptoKit sees the bytes: stanza type and
//  argument count, canonical base64, enc and body sizes, the 16-byte file key, the
//  FIPS 203 modulus check on recipient keys, and the low-order X25519 refusal (the
//  RC3 spike showed CryptoKit opens five CCTV vectors age must reject).
//
//  Known-answer tests pass fixed encapsulation randomness, which CryptoKit can't take,
//  so any call with `testRandom` always runs the own code.
//
//  No fallback: where CryptoKit runs, it is the only ML-KEM / X-Wing code that runs. A
//  CryptoKit throw after AgePony's checks is mapped to the error the own code gives for
//  that kind of failure (`mapEncapsulationError`, `MLKEMDecapsulationRefused`), never
//  retried through the own code, so a real CryptoKit refusal isn't masked.
//
//  `forceOwnCode` is a test hook: on macOS 26 it lets the same tests run through both
//  backends. Internal, so only `@testable` tests can set it.
//

import Foundation
import os

enum HybridKEMBackend {

    private static let ownCodeOverride = OSAllocatedUnfairLock(initialState: false)

    /// Test hook: when true, the own code runs even where CryptoKit's post-quantum
    /// APIs are available. Never set by the app. Process-global: meant for XCTest, which
    /// runs a process's tests one at a time. Not safe under parallel Swift Testing (or
    /// any concurrent tests in one process): a test running alongside a `withOwnCode`
    /// block would pick up the forced backend.
    static var forceOwnCode: Bool {
        get { ownCodeOverride.withLock { $0 } }
        set { ownCodeOverride.withLock { $0 = newValue } }
    }

    /// Run `body` with the own code forced, then put the previous setting back.
    static func withOwnCode<T>(_ body: () throws -> T) rethrows -> T {
        let previous = forceOwnCode
        forceOwnCode = true
        defer { forceOwnCode = previous }
        return try body()
    }

    /// Whether new keys and operations go to CryptoKit right now.
    static var usesCryptoKit: Bool {
        #if (os(iOS) || os(macOS)) && compiler(>=6.2)
        if #available(iOS 26, macOS 26, *) {
            return !forceOwnCode
        }
        #endif
        return false
    }

    // MARK: - mlkem768x25519 (X-Wing)

    /// The private half of an `age1pq1` identity, from its 32-byte seed: CryptoKit's
    /// X-Wing key where available, the own `HpkeMlkem768X25519.PrivateKey` otherwise.
    /// If CryptoKit refuses the seed (the spike never saw it), the key is unusable:
    /// `HybridKEMError.invalidSeedLength`, the own code's "damaged key" error.
    static func xwingKey(seed: Data) throws -> any XWingDecryptionKey {
        #if (os(iOS) || os(macOS)) && compiler(>=6.2)
        if #available(iOS 26, macOS 26, *), !forceOwnCode {
            guard seed.count == HpkeMlkem768X25519.seedSize else { throw HybridKEMError.invalidSeedLength }
            do {
                return try CryptoKitXWingKey(seed: seed)
            } catch let e as HybridKEMError {
                throw e
            } catch {
                throw HybridKEMError.invalidSeedLength
            }
        }
        #endif
        return try HpkeMlkem768X25519.PrivateKey(seed: seed)
    }

    // MARK: - ML-KEM-768 (the tag recipients' post-quantum half)

    /// The ML-KEM half of an `age1tagpq1` identity from its 64-byte seed (d || z).
    static func mlkemKey(seed: Data) throws -> any MLKEMDecapsulation {
        guard seed.count == MLKEM768.seedSize else { throw MLKEMError.invalidSeedLength }
        #if (os(iOS) || os(macOS)) && compiler(>=6.2)
        if #available(iOS 26, macOS 26, *), !forceOwnCode {
            do {
                return try CryptoKitMLKEMKey(seed: seed)
            } catch let e as MLKEMError {
                throw e
            } catch {
                // CryptoKit refused a 64-byte seed: the own code's error for an unusable seed.
                throw MLKEMError.invalidSeedLength
            }
        }
        #endif
        return try MLKEM768.keyPairFromSeed(seed)
    }

    /// ML-KEM-768 encapsulation. With `message` (a known-answer test) or without
    /// CryptoKit, the own code. Otherwise AgePony's length and FIPS 203 modulus checks
    /// first, with the own errors, then CryptoKit only. A CryptoKit throw after the checks
    /// maps to `MLKEMError.malformedEncapsulationKey`, the own code's only failure for a
    /// key of the right length.
    static func mlkemEncapsulate(encapsulationKey ek: Data,
                                 message: Data?) throws -> (sharedSecret: Data, ciphertext: Data) {
        #if (os(iOS) || os(macOS)) && compiler(>=6.2)
        if #available(iOS 26, macOS 26, *), message == nil, !forceOwnCode {
            guard ek.count == MLKEM768.encapsulationKeySize else { throw MLKEMError.invalidEncapsulationKeyLength }
            guard MLKEM768.isValidEncapsulationKey(ek) else { throw MLKEMError.malformedEncapsulationKey }
            do {
                return try CryptoKitMLKEM.encapsulate(encapsulationKey: ek)
            } catch {
                throw mapEncapsulationError(error)
            }
        }
        #endif
        return try MLKEM768.encapsulate(encapsulationKey: ek, message: message)
    }

    /// A CryptoKit ML-KEM encapsulation failure after AgePony's checks passed, as the own
    /// code would report a recipient key it can't encrypt to.
    static func mapEncapsulationError(_ error: Error) -> Error {
        if error is MLKEMError { return error }
        return MLKEMError.malformedEncapsulationKey
    }
}

/// CryptoKit refused to decapsulate a well-sized ML-KEM ciphertext with a software key.
/// The own code never fails there (implicit rejection gives a secret that then fails the
/// AEAD), so `TagIdentity.unwrap` turns this into nil, "not for me", the same result.
/// Enclave keys don't use it: their errors (a cancelled prompt) still propagate.
struct MLKEMDecapsulationRefused: Error, Equatable {}

// MARK: - Decryption keys behind a protocol

/// The private half of an `age1pq1` identity, whichever backend holds it.
protocol XWingDecryptionKey {
    /// The 1216-byte hybrid public key.
    var publicKey: Data { get }
    /// Single-shot HPKE open of a 1120-byte `enc` and `ciphertext` under `info`.
    /// Throws on any failure; the caller turns that into "not for me".
    func open(enc: Data, info: Data, ciphertext: Data) throws -> Data
}

extension HpkeMlkem768X25519.PrivateKey: XWingDecryptionKey {
    func open(enc: Data, info: Data, ciphertext: Data) throws -> Data {
        try HpkeMlkem768X25519.open(priv: self, enc: enc, info: info, ciphertext: ciphertext)
    }
}

/// The ML-KEM-768 half of an `age1tagpq1` identity, wherever it lives: the own code
/// (`MLKEM768.KeyPair`), CryptoKit from a vault seed, or the Secure Enclave
/// (`SecureEnclaveMLKEM`, iOS 26). Mirrors `P256KeyAgreement`, which does the same for
/// the P-256 half.
public protocol MLKEMDecapsulation {
    /// The 1184-byte encapsulation key.
    var encapsulationKey: Data { get }
    /// FIPS 203 decapsulation of a 1088-byte ciphertext, returning the 32-byte shared
    /// secret. A ciphertext that doesn't re-encrypt gives the implicit-rejection secret,
    /// not an error; errors are for a key that can't be used (a cancelled prompt, say).
    func decapsulate(ciphertext: Data) throws -> Data
}

extension MLKEM768.KeyPair: MLKEMDecapsulation {
    public func decapsulate(ciphertext: Data) throws -> Data {
        try MLKEM768.decapsulate(decapsulationKey: decapsulationKey, ciphertext: ciphertext)
    }
}
