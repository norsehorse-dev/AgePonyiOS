//
//  P256RecipientTests.swift
//  AgePonyCoreTests
//
//  piv-p256 (age-plugin-yubikey) recipient. AgePony only encrypts to these
//  (the YubiKey decrypts), so there is no real identity to round-trip against.
//  Two checks stand in for the YubiKey:
//    - a random-key test that unwraps the stanza by following the spec with a
//      software P-256 private key, exercising the whole
//      ECDH -> HKDF -> ChaCha20Poly1305 chain and the exact stanza shape;
//    - a known-answer vector (fixed recipient key, fixed ephemeral, fixed file
//      key) pinned by the Python reference in tools/pivp256_ref.py, so the
//      Swift stays byte-identical to Android P256.kt and age-plugin-yubikey.
//
//  Final interop is still confirmed on-device by decrypting an AgePony-produced
//  file with `age` + a real YubiKey (see AgePony_4.0.0_DeviceTests.md).
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class P256RecipientTests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            out.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return Data(out)
    }

    // MARK: structure

    func testWrapProducesPivP256Stanza() throws {
        let priv = P256.KeyAgreement.PrivateKey()
        let pub = priv.publicKey.compressedRepresentation
        let recipient = try P256Recipient(compressedPublicKey: pub)

        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let stanza = try recipient.wrap(fileKey: fileKey)

        XCTAssertEqual(stanza.type, "piv-p256")
        XCTAssertEqual(stanza.args.count, 2)

        // arg[0] is SHA-256(compressed recipient)[..<4]
        let expectedTag = Data(Array(SHA256.hash(data: pub)).prefix(4))
        XCTAssertEqual(try Stanza.base64Decode(stanza.args[0]), expectedTag)

        // arg[1] is the compressed ephemeral public key (33 bytes, 0x02/0x03)
        let epk = try Stanza.base64Decode(stanza.args[1])
        XCTAssertEqual(epk.count, 33)
        XCTAssertTrue(epk.first == 0x02 || epk.first == 0x03)

        // body = ChaCha20Poly1305(16-byte file key) + 16-byte tag
        XCTAssertEqual(stanza.body.count, 32)
    }

    // MARK: round trip against a stand-in private key

    func testRoundTripUnwrapWithStandInPrivateKey() throws {
        let recipientPriv = P256.KeyAgreement.PrivateKey()
        let pub = recipientPriv.publicKey.compressedRepresentation
        let recipient = try P256Recipient(compressedPublicKey: pub)

        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let stanza = try recipient.wrap(fileKey: fileKey)

        // Unwrap the way the YubiKey would, following the spec independently.
        let epkBytes = try Stanza.base64Decode(stanza.args[1])
        let epk = try P256.KeyAgreement.PublicKey(compressedRepresentation: epkBytes)
        let shared = try recipientPriv.sharedSecretFromKeyAgreement(with: epk)
        let salt = epkBytes + pub
        let wrapKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data("piv-p256".utf8), outputByteCount: 32)

        let ciphertext = stanza.body.prefix(16)
        let tag = stanza.body.suffix(16)
        let nonce = try ChaChaPoly.Nonce(data: Data(repeating: 0, count: 12))
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let recovered = try ChaChaPoly.open(box, using: wrapKey, authenticating: Data())

        XCTAssertEqual(recovered, fileKey)
    }

    // MARK: bech32

    func testBech32RoundTrips() throws {
        let priv = P256.KeyAgreement.PrivateKey()
        let pub = priv.publicKey.compressedRepresentation
        let recipient = try P256Recipient(compressedPublicKey: pub)
        let text = recipient.toBech32()
        XCTAssertTrue(text.hasPrefix("age1yubikey1"))
        let reparsed = try P256Recipient(ageRecipient: text)
        XCTAssertEqual(reparsed.compressedPublicKey, Data(pub))
    }

    // MARK: known-answer vector (tools/pivp256_ref.py)

    func testKnownAnswerVector() throws {
        let recipientPub = hex("02e184ae8152166cbf2ed1a6647627d0d3e6d2c806e79e383865e67ac14273ce8e")
        let ephemeralScalar = hex("0fedcba987654321fedcba9876543210fedcba9876543210fedcba9876543201")
        let fileKey = hex("000102030405060708090a0b0c0d0e0f")

        let expectedTag = hex("50a83f1b")
        let expectedEpk = hex("033ec11e450117e49bfd858d5b816f458e1abbc453806ac5afcc25ba72c2adf384")
        let expectedBody = hex("4040884f293e85aebc7c2ba2016af2641182a2afa6e49d0236055a0a59e42d4f")
        let expectedRecipientString =
            "age1yubikey1qtscft5p2gtxe0ew6xnxga386rf7d5kgqmneuwpcvhn84s2zw08gux62t87"

        let recipient = try P256Recipient(compressedPublicKey: recipientPub)
        let ephemeral = try P256.KeyAgreement.PrivateKey(rawRepresentation: ephemeralScalar)
        let stanza = try recipient.wrap(fileKey: fileKey, ephemeral: ephemeral)

        XCTAssertEqual(try Stanza.base64Decode(stanza.args[0]), expectedTag)
        XCTAssertEqual(try Stanza.base64Decode(stanza.args[1]), expectedEpk)
        XCTAssertEqual(stanza.body, expectedBody)
        XCTAssertEqual(recipient.toBech32(), expectedRecipientString)
        XCTAssertEqual(
            try P256Recipient(ageRecipient: expectedRecipientString).compressedPublicKey,
            recipientPub)
    }

    // MARK: rejection

    func testRejectsMalformedInput() {
        // Wrong length.
        XCTAssertThrowsError(try P256Recipient(compressedPublicKey: Data(repeating: 2, count: 32)))
        // Bad compression byte (valid length, leading 0x04 = uncompressed marker).
        var bad = Data([0x04]); bad.append(Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try P256Recipient(compressedPublicKey: bad))
        // Wrong HRP.
        XCTAssertThrowsError(try P256Recipient(ageRecipient: "age1qqqqqqqqqqqqqqqqqqqqqqqq"))
    }
}
