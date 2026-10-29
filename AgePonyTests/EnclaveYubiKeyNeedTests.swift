//
//  EnclaveYubiKeyNeedTests.swift
//  AgePonyTests
//
//  5.1.1 (M-4): a Secure Enclave key that matches a file but can't decrypt must not
//  hide the YubiKey tap. `YubiKeyDecrypt.need` counts software keys only, and
//  `DecryptIdentities.enclaveOpens` tries the Enclave key for real before the tap.
//  The Enclave stand-ins here are tag identities over a P-256 key that either works
//  (a software key) or throws the way a destroyed Enclave key does.
//

import XCTest
import Foundation
import CryptoKit
import AgePonyCore
@testable import AgePony

/// A Secure Enclave key that still matches its stanzas by tag but can't run the ECDH.
private final class DeadEnclaveKey: P256KeyAgreement {
    var calls = 0
    func sharedX(peerUncompressed: Data) throws -> Data {
        calls += 1
        throw SecureEnclaveKeyError.invalidKeyData
    }
}

@MainActor
final class EnclaveYubiKeyNeedTests: XCTestCase {

    private let fileKey = Data((0..<16).map { UInt8($0) })

    private func yubiKey() throws -> (stored: StoredIdentity, recipient: P256Recipient) {
        let pub = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
        let stub = try YubiKeyStub(serial: 12_345_678, slot: 0x82, tag: YubiKeyStub.staticTag(compressedPublicKey: pub))
        let stored = StoredIdentity(name: "yubikey", type: .yubikey, publicKeyMaterial: pub,
                                    privateKeyMaterial: stub.bytes, pinPolicy: .notRequired)
        return (stored, try P256Recipient(compressedPublicKey: pub))
    }

    private func deadEnclave(_ key: DeadEnclaveKey = DeadEnclaveKey()) throws -> TagIdentity {
        try TagIdentity.classic(publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation, p256: key)
    }

    private func workingEnclave() throws -> TagIdentity {
        try TagIdentity.softwareClassic(scalar: P256.KeyAgreement.PrivateKey().rawRepresentation)
    }

    func testEnclaveMatchDoesNotHideTheYubiKey() throws {
        let yk = try yubiKey()
        let enclave = try deadEnclave()
        let stanzas = [try enclave.recipient.wrap(fileKey: fileKey), try yk.recipient.wrap(fileKey: fileKey)]

        // The tag match alone is what used to make the tap look unnecessary.
        XCTAssertTrue(try Age.anyOpens(stanzas: stanzas, identities: [enclave]))

        let need = try XCTUnwrap(YubiKeyDecrypt.need(stanzas: stanzas, identities: [yk.stored], others: [enclave]))
        XCTAssertEqual(need.identity.id, yk.stored.id)
        XCTAssertEqual(need.points.count, 1)
    }

    func testSoftwareKeyStillMakesTheTapUnnecessary() throws {
        let yk = try yubiKey()
        let enclave = try deadEnclave()
        let x = X25519Identity.generate()
        let stanzas = [
            try enclave.recipient.wrap(fileKey: fileKey),
            try yk.recipient.wrap(fileKey: fileKey),
            try X25519Recipient(ageRecipient: x.ageRecipient).wrap(fileKey: fileKey),
        ]
        XCTAssertNil(YubiKeyDecrypt.need(stanzas: stanzas, identities: [yk.stored], others: [x, enclave]))
    }

    func testNoTapWhenTheYubiKeyIsNotAddressed() throws {
        let yk = try yubiKey()
        let enclave = try deadEnclave()
        let stanzas = [try enclave.recipient.wrap(fileKey: fileKey)]
        XCTAssertNil(YubiKeyDecrypt.need(stanzas: stanzas, identities: [yk.stored], others: [enclave]))
    }

    func testDeadEnclaveKeyDoesNotOpen() throws {
        let yk = try yubiKey()
        let key = DeadEnclaveKey()
        let enclave = try deadEnclave(key)
        let stanzas = [try enclave.recipient.wrap(fileKey: fileKey), try yk.recipient.wrap(fileKey: fileKey)]
        XCTAssertTrue(DecryptIdentities.enclaveIsAddressed(stanzas: stanzas, identities: [enclave]))
        XCTAssertFalse(DecryptIdentities.enclaveOpens(stanzas: stanzas, identities: [enclave]))
        XCTAssertEqual(key.calls, 1)
    }

    func testWorkingEnclaveKeyOpens() throws {
        let yk = try yubiKey()
        let enclave = try workingEnclave()
        let stanzas = [try yk.recipient.wrap(fileKey: fileKey), try enclave.recipient.wrap(fileKey: fileKey)]
        XCTAssertTrue(DecryptIdentities.enclaveOpens(stanzas: stanzas, identities: [enclave]))
    }

    func testEnclaveNotAddressed() throws {
        let yk = try yubiKey()
        let enclave = try deadEnclave()
        let stanzas = [try yk.recipient.wrap(fileKey: fileKey)]
        XCTAssertFalse(DecryptIdentities.enclaveIsAddressed(stanzas: stanzas, identities: [enclave]))
        XCTAssertFalse(DecryptIdentities.enclaveOpens(stanzas: stanzas, identities: [enclave]))
    }

    func testFailedEnclaveKeyIsNotAskedAgain() throws {
        // A crafted header with many stanzas for one key: after the first error the
        // key isn't tried again (5.1.1, L-7 bound).
        let key = DeadEnclaveKey()
        let enclave = try deadEnclave(key)
        let stanzas = try (0..<10).map { _ in try enclave.recipient.wrap(fileKey: fileKey) }
        XCTAssertFalse(DecryptIdentities.enclaveOpens(stanzas: stanzas, identities: [enclave]))
        XCTAssertEqual(key.calls, 1)
    }
}
