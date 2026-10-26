//
//  HardeningTests.swift
//  AgePonyCoreTests
//
//  Bounds and consistency checks from the Sep 2026 audit that aren't about the age
//  header itself: bcrypt_pbkdf limits (L-10), CBOR and RSA input that used to trap
//  (L-11), Field25519 subtraction and Ed25519 point validation (L-13), and private keys
//  whose halves don't belong together.
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

final class HardeningTests: XCTestCase {

    // MARK: L-10 bcrypt_pbkdf

    func test_bcryptRoundsAndSaltAreCapped() throws {
        XCTAssertThrowsError(try BcryptPBKDF.bcryptPBKDF(password: Data("pw".utf8), salt: Data(count: 16),
                                                         rounds: BcryptPBKDF.maxRounds + 1, keylen: 48))
        XCTAssertThrowsError(try BcryptPBKDF.bcryptPBKDF(password: Data("pw".utf8), salt: Data(count: 2000),
                                                         rounds: 16, keylen: 48))
        func kdfOpts(salt: Int, rounds: UInt32) -> Data {
            var w = SSHWireWriter()
            w.writeString(Data(count: salt))
            w.writeUInt32(rounds)
            return w.data
        }
        XCTAssertNoThrow(try OpenSSHEncryptedKey.parseKDFOpts(kdfOpts(salt: 16, rounds: 16)))
        XCTAssertThrowsError(try OpenSSHEncryptedKey.parseKDFOpts(kdfOpts(salt: 16, rounds: 4_000_000_000)))
        XCTAssertThrowsError(try OpenSSHEncryptedKey.parseKDFOpts(kdfOpts(salt: 16, rounds: 0)))
        XCTAssertThrowsError(try OpenSSHEncryptedKey.parseKDFOpts(kdfOpts(salt: 4096, rounds: 16)))
    }

    // MARK: L-11 CBOR

    func test_cborDeclaredSizes_neverTrapOrPreallocate() {
        // Byte string claiming 2^64 - 1 bytes.
        XCTAssertThrowsError(try CBORReader.decode(Data([0x5B] + [UInt8](repeating: 0xFF, count: 8)))) {
            XCTAssertEqual($0 as? CBORError, .truncated)
        }
        // Array and map claiming 2^63 entries.
        XCTAssertThrowsError(try CBORReader.decode(Data([0x9B, 0x80] + [UInt8](repeating: 0, count: 7))))
        XCTAssertThrowsError(try CBORReader.decode(Data([0xBB, 0x7F] + [UInt8](repeating: 0xFF, count: 7))))
        // Text claiming more than is there.
        XCTAssertThrowsError(try CBORReader.decode(Data([0x7A, 0x00, 0x01, 0x00, 0x00, 0x41])))
    }

    func test_cborNestingIsBounded() {
        let ok = Data([UInt8](repeating: 0x81, count: CBORReader.maxDepth) + [0x00])
        XCTAssertNoThrow(try CBORReader.decode(ok))
        let deep = Data([UInt8](repeating: 0x81, count: CBORReader.maxDepth + 1) + [0x00])
        XCTAssertThrowsError(try CBORReader.decode(deep)) { XCTAssertEqual($0 as? CBORError, .tooDeep) }
        let deepMap = Data([UInt8](repeating: 0xA1, count: 40).flatMap { [$0, 0x00] } + [0x00])
        XCTAssertThrowsError(try CBORReader.decode(deepMap))
    }

    // MARK: L-11 RSA private-key components

    func test_rsaPrimesAtOrBelowOne_areRefusedNotTrapped() {
        let n = Data(repeating: 0xC5, count: 256), e = Data([0x01, 0x00, 0x01]), d = Data(repeating: 0x11, count: 256)
        for (p, q) in [(Data([0x01]), Data([0x03])), (Data([0x00]), Data([0x03])), (Data([0x05]), Data([0x00, 0x01]))] {
            XCTAssertThrowsError(try RSAKey.makePrivate(n: n, e: e, d: d, p: p, q: q, iqmp: Data([0x01]))) {
                XCTAssertEqual(($0 as? RSAKeyError).map { "\($0)" }, "invalidKeyComponent")
            }
        }
    }

    // MARK: L-13 Field25519 and Ed25519 points

    func test_field25519_subtractionWithNonCanonicalOperands() {
        // b = p + 5 is a valid 256-bit limb value but not reduced; 0 - b must be -5 mod p.
        let p = Field25519.pLimbs
        var bLimbs = p
        bLimbs[0] &+= 5
        let b = Field25519(limbs: bLimbs)
        let expected = Field25519(limbs: [p[0] - 5] + Array(p.dropFirst()))
        XCTAssertEqual(Field25519.zero - b, expected)
        XCTAssertEqual((Field25519.zero - b).reduced().limbs, expected.limbs)
        // Near 2^256: two subtractions of p are needed to reduce.
        let top = Field25519(limbs: [UInt32](repeating: 0xFFFF_FFFF, count: 8))
        XCTAssertTrue(top.reduced().isCanonical)
        XCTAssertEqual(top - top, Field25519.zero)
    }

    func test_ed25519PublicKey_mustBeACurvePoint() throws {
        let real = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        XCTAssertTrue(Ed25519Conversion.isValidPublicKey(real))
        XCTAssertNoThrow(try Ed25519Conversion.publicKeyToX25519(edPublicKey: real))

        // y = p (non-canonical encoding of 0).
        var yIsP = Data(repeating: 0xFF, count: 32)
        yIsP[0] = 0xED; yIsP[31] = 0x7F
        XCTAssertFalse(Ed25519Conversion.isValidPublicKey(yIsP))

        // A y with no matching x (the old SSHKeySource fixture was one of these).
        let offCurve = Data(base64Encoded: "AAAAC3NzaC1lZDI1NTE5AAAAIPFx4q1cdQYPVPnoYsm0H/jX6vMOgtJ3I7DAuhwJxCt8")!.suffix(32)
        XCTAssertFalse(Ed25519Conversion.isValidPublicKey(Data(offCurve)))
        XCTAssertThrowsError(try Ed25519Conversion.publicKeyToX25519(edPublicKey: Data(offCurve))) {
            XCTAssertEqual($0 as? Ed25519ConversionError, .invalidPoint)
        }

        // x = 0 with the sign bit set is not a valid encoding (y = 1 is the identity).
        var negZero = Data(count: 32)
        negZero[0] = 1; negZero[31] = 0x80
        XCTAssertFalse(Ed25519Conversion.isValidPublicKey(negZero))
    }

    // MARK: Private-key consistency

    func test_ed25519PrivateKey_withForeignPublicKey_isRefused() throws {
        let a = Curve25519.Signing.PrivateKey(), b = Curve25519.Signing.PrivateKey()
        let good = try OpenSSHEd25519Export.privateKeyPEM(seed: a.rawRepresentation, publicKey: a.publicKey.rawRepresentation)
        XCTAssertNoThrow(try SSHKey.parseOpenSSHPrivateKey(good))
        let bad = try OpenSSHEd25519Export.privateKeyPEM(seed: a.rawRepresentation, publicKey: b.publicKey.rawRepresentation)
        XCTAssertThrowsError(try SSHKey.parseOpenSSHPrivateKey(bad)) {
            XCTAssertEqual($0 as? SSHKeyError, .inconsistentKey)
        }
    }
}
