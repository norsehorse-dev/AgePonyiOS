import XCTest
import CryptoKit
@testable import AgePonyCore

final class PinProtocolV1Tests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return d
    }
    private func hx(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    // All vectors below were produced independently with Python
    // (`cryptography` + hashlib + hmac).

    private let platScalar = "1111111111111111111111111111111111111111111111111111111111111111"
    private let authX963   = "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"
    private let sharedSS   = "98f5bf15dbc72627acd9a8ab61ce21349ea3496d79136adf08ad381cc9c0fa25"

    /// SHA-256 of the ECDH x-coordinate, from a fixed platform scalar and the
    /// authenticator's public key. Confirms CryptoKit's P-256 shared secret is
    /// the raw x-coordinate (what CTAP expects).
    func testSharedSecret_matchesReference() throws {
        let priv = try P256.KeyAgreement.PrivateKey(rawRepresentation: hex(platScalar))
        let ss = try PinProtocolV1.sharedSecret(
            platformPrivate: priv, authenticatorPublicX963: hex(authX963))
        XCTAssertEqual(hx(ss), sharedSS)
    }

    /// pinHashEnc = AES-256-CBC( sharedSecret, iv0, LEFT(SHA256("1234"),16) ).
    func testPinHashEnc_matchesReference() throws {
        let enc = try PinProtocolV1.pinHashEnc(sharedSecret: hex(sharedSS), pin: "1234")
        XCTAssertEqual(hx(enc), "cd782dd78eb3517e6279ff687e577f00")
    }

    /// pinUvAuthParam = LEFT( HMAC-SHA256(pinToken, clientDataHash), 16 ).
    func testPinUvAuthParam_matchesReference() throws {
        let token = hex("808182838485868788898a8b8c8d8e8f")
        let cdh   = Data(SHA256.hash(data: Data("hello ssh".utf8)))
        XCTAssertEqual(hx(cdh),
                       "ad6dc9f902e07c202c9ff2ffc1a1388e698b2758ffc2727572e8e9963da265e4")
        let param = PinProtocolV1.pinUvAuthParam(pinToken: token, clientDataHash: cdh)
        XCTAssertEqual(hx(param), "9134c0018e48d8cd8258be570172b149")
        XCTAssertEqual(param.count, 16)
    }

    /// The authenticator encrypts the PIN token under the same shared secret;
    /// decrypting must recover it.
    func testPinTokenDecrypt_roundTrip() throws {
        let token = hex("808182838485868788898a8b8c8d8e8f")
        let tokenEnc = try PinProtocolV1.encrypt(sharedSecret: hex(sharedSS), plaintext: token)
        XCTAssertEqual(hx(tokenEnc), "468066941faf072e8407dc3b9d569e16")
        let back = try PinProtocolV1.decryptPinToken(
            sharedSecret: hex(sharedSS), pinTokenEnc: tokenEnc)
        XCTAssertEqual(back, token)
    }

    /// End-to-end shape: two fresh platform key pairs derive the *same* shared
    /// secret with a real authenticator key would; here we cross two platform
    /// keys to confirm ECDH symmetry through our wrapper.
    func testSharedSecret_isSymmetric() throws {
        let a = P256.KeyAgreement.PrivateKey()
        let b = P256.KeyAgreement.PrivateKey()
        let ssA = try PinProtocolV1.sharedSecret(
            platformPrivate: a, authenticatorPublicX963: b.publicKey.x963Representation)
        let ssB = try PinProtocolV1.sharedSecret(
            platformPrivate: b, authenticatorPublicX963: a.publicKey.x963Representation)
        XCTAssertEqual(ssA, ssB)
    }

    func testGeneratePlatformKeyPair_publicIsX963() {
        let (_, pub) = PinProtocolV1.generatePlatformKeyPair()
        XCTAssertEqual(pub.count, 65)        // 04 || X(32) || Y(32)
        XCTAssertEqual(pub.first, 0x04)
    }
}
