//
//  PasswordKeyBlobTests.swift
//  AgePonyCoreTests
//
//  Round-trip and three-way-outcome tests for the app-owned password/PIN +
//  duress blob logic. The blob is device-local (never crosses machines), so
//  there is no cross-implementation golden vector to pin; correctness is a
//  wrap/unwrap round trip plus the wrong, duress, tamper, device-key and v1
//  migration branches. The scrypt KDF underneath is pinned to RFC 7914 vectors
//  in ScryptTests.
//
//  The statistical timing (no-tell) acceptance test runs on-device per the
//  4.0.0 plan's B4; here we only assert the logic.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class PasswordKeyBlobTests: XCTestCase {

    private func randomKey() -> Data {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    }

    private let device = SoftwareDeviceBinding(key: Data(repeating: 0x42, count: 32))

    private func realKey(_ o: PasswordKeyBlob.Outcome, file: StaticString = #filePath, line: UInt = #line) -> (Data, Bool)? {
        guard case let .real(vk, rewrap) = o else { XCTFail("expected .real, got \(o)", file: file, line: line); return nil }
        return (vk, rewrap)
    }

    func testRealPasswordRecoversExactVaultKey() throws {
        let vk = randomKey()
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: vk, binding: device)
        let duress = try PasswordKeyBlob.duressBlob(secret: "battery staple", binding: device)
        XCTAssertEqual(PasswordKeyBlob.version(of: real), 2)
        XCTAssertEqual(real[1], 16)
        let r = realKey(try PasswordKeyBlob.tryUnlock(secret: "correct horse", realBlob: real, duressBlob: duress, binding: device))
        XCTAssertEqual(r?.0, vk)
        XCTAssertEqual(r?.1, false)
    }

    func testDuressPasswordSignalsDuress_andItsMaterialSealsTheNewVault() throws {
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: randomKey(), binding: device)
        let duress = try PasswordKeyBlob.duressBlob(secret: "battery staple", binding: device)
        guard case let .duress(material) = try PasswordKeyBlob.tryUnlock(
            secret: "battery staple", realBlob: real, duressBlob: duress, binding: device) else {
            return XCTFail("expected .duress")
        }
        // The wipe rotates the device key; the decoy becomes the new real secret.
        let rotated = SoftwareDeviceBinding()
        let newVK = randomKey()
        let newReal = try material.wrapNewVaultKey(newVK, binding: rotated)
        XCTAssertThrowsError(try material.wrapNewVaultKey(newVK, binding: rotated)) {
            XCTAssertEqual($0 as? PasswordKeyBlob.BlobError, .duressMaterialUsed)
        }
        XCTAssertEqual(realKey(try PasswordKeyBlob.tryUnlock(secret: "battery staple", realBlob: newReal,
                                                             duressBlob: nil, binding: rotated))?.0, newVK)
        // The old blobs are dead under the rotated key.
        XCTAssertTrue(try PasswordKeyBlob.tryUnlock(secret: "correct horse", realBlob: real, duressBlob: nil, binding: rotated).isWrong)
    }

    func testWrongPassword() throws {
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: randomKey(), binding: device)
        let duress = try PasswordKeyBlob.duressBlob(secret: "battery staple", binding: device)
        XCTAssertTrue(try PasswordKeyBlob.tryUnlock(secret: "nope", realBlob: real, duressBlob: duress, binding: device).isWrong)
    }

    func testNoDuressConfigured() throws {
        let vk = randomKey()
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: vk, binding: device)
        XCTAssertEqual(realKey(try PasswordKeyBlob.tryUnlock(secret: "correct horse", realBlob: real, duressBlob: nil, binding: device))?.0, vk)
        XCTAssertTrue(try PasswordKeyBlob.tryUnlock(secret: "whatever", realBlob: real, duressBlob: nil, binding: device).isWrong)
    }

    func testPinBehavesLikePassword() throws {
        let vk = randomKey()
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "902317", vaultKey: vk, binding: device)
        XCTAssertEqual(realKey(try PasswordKeyBlob.tryUnlock(secret: "902317", realBlob: real, duressBlob: nil, binding: device))?.0, vk)
    }

    func testTamperedBlobReadsAsWrongNotCrash() throws {
        var real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: randomKey(), binding: device)
        real[real.index(before: real.endIndex)] ^= 0x01
        XCTAssertTrue(try PasswordKeyBlob.tryUnlock(secret: "correct horse", realBlob: real, duressBlob: nil, binding: device).isWrong)
    }

    func testTooShortBlobThrows() {
        XCTAssertThrowsError(try PasswordKeyBlob.tryUnlock(secret: "x", realBlob: Data([1, 15, 0, 0]), duressBlob: nil, binding: device)) {
            XCTAssertEqual($0 as? PasswordKeyBlob.BlobError, .tooShort)
        }
    }

    func testUnknownVersionThrows() throws {
        var real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: randomKey(), binding: device)
        real[real.startIndex] = 0x09
        XCTAssertThrowsError(try PasswordKeyBlob.tryUnlock(secret: "correct horse", realBlob: real, duressBlob: nil, binding: device)) {
            XCTAssertEqual($0 as? PasswordKeyBlob.BlobError, .unknownVersion(0x09))
        }
    }

    func testBlobIsExpectedSize() throws {
        // header(2) + salt(16) + nonce(12) + ct(32) + tag(16) = 78
        XCTAssertEqual(try PasswordKeyBlob.wrapVaultKey(secret: "p", vaultKey: randomKey(), binding: device).count, 78)
        XCTAssertEqual(try PasswordKeyBlob.duressBlob(secret: "p", binding: device).count, 78)
    }

    // MARK: - Device binding (audit M-2)

    func testV2BlobNeedsTheSameDeviceKey() throws {
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: randomKey(), binding: device)
        let elsewhere = SoftwareDeviceBinding(key: Data(repeating: 0x43, count: 32))
        XCTAssertTrue(try PasswordKeyBlob.tryUnlock(secret: "correct horse", realBlob: real, duressBlob: nil, binding: elsewhere).isWrong)
    }

    func testMissingDeviceKey_isReportedNotWrongForever() throws {
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: randomKey(), binding: device)
        let gone = SoftwareDeviceBinding()
        XCTAssertThrowsError(try PasswordKeyBlob.tryUnlock(secret: "correct horse", realBlob: real, duressBlob: nil, binding: gone)) {
            XCTAssertEqual($0 as? PasswordKeyBlob.BlobError, .deviceKeyMissing)
        }
    }

    func testDeviceKeyRecreatedByTheApp_isReportedOnce() throws {
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: randomKey(), binding: device)
        let fresh = SoftwareDeviceBinding(key: Data(repeating: 0x44, count: 32), justCreated: true)
        XCTAssertThrowsError(try PasswordKeyBlob.tryUnlock(secret: "correct horse", realBlob: real, duressBlob: nil, binding: fresh)) {
            XCTAssertEqual($0 as? PasswordKeyBlob.BlobError, .deviceKeyMissing)
        }
    }

    // MARK: - v1 migration

    func testV1BlobStillOpens_andAsksForRewrap() throws {
        let vk = randomKey()
        let v1 = try PasswordKeyBlob.legacyV1Blob(secret: "123456", plaintext: vk)
        XCTAssertEqual(PasswordKeyBlob.version(of: v1), 1)
        // Opens whatever the device key is, including one created just now.
        let r = realKey(try PasswordKeyBlob.tryUnlock(secret: "123456", realBlob: v1, duressBlob: nil, binding: SoftwareDeviceBinding()))
        XCTAssertEqual(r?.0, vk)
        XCTAssertEqual(r?.1, true)
        XCTAssertTrue(try PasswordKeyBlob.tryUnlock(secret: "654321", realBlob: v1, duressBlob: nil, binding: device).isWrong)

        let v2 = try PasswordKeyBlob.wrapVaultKey(secret: "123456", vaultKey: vk, binding: device)
        XCTAssertEqual(realKey(try PasswordKeyBlob.tryUnlock(secret: "123456", realBlob: v2, duressBlob: nil, binding: device))?.1, false)
    }

    func testV1DuressBlobStillSignalsDuress() throws {
        let real = try PasswordKeyBlob.wrapVaultKey(secret: "correct horse", vaultKey: randomKey(), binding: device)
        let oldDuress = try PasswordKeyBlob.legacyV1Blob(secret: "decoy pass", plaintext: randomKey())
        XCTAssertTrue(try PasswordKeyBlob.tryUnlock(secret: "decoy pass", realBlob: real, duressBlob: oldDuress, binding: device).isDuress)
    }

    // MARK: - Policy (audit M-1)

    func testSecretPolicy() {
        XCTAssertNotNil(PasswordKeyBlob.policyError(secret: "12345", isPIN: true))
        XCTAssertNotNil(PasswordKeyBlob.policyError(secret: "12345a", isPIN: true))
        XCTAssertNotNil(PasswordKeyBlob.policyError(secret: "１２３４５６", isPIN: true))
        XCTAssertNil(PasswordKeyBlob.policyError(secret: "123456", isPIN: true))
        XCTAssertNotNil(PasswordKeyBlob.policyError(secret: "short", isPIN: false))
        XCTAssertNil(PasswordKeyBlob.policyError(secret: "eightchr", isPIN: false))
    }
}
