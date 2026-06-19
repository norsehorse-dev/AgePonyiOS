//
//  AuthenticatorDataTests.swift
//  AgePonyCoreTests
//
//  Vectors built with cbor2 + hashlib: a getAssertion authData (no attested
//  data) and a makeCredential authData (with attested credential data carrying
//  a COSE Ed25519 key), plus the two enclosing CTAP2 response objects, so the
//  whole decode path the NFC transport will use is exercised end to end.
//

import XCTest
@testable import AgePonyCore

final class AuthenticatorDataTests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var d = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i ..< j], radix: 16)!)
            i = j
        }
        return d
    }

    // SHA-256("ssh:")
    private let rpIdHash = "e30610e8a162115960fe1ec223e6529c9f4b6e80200dcb5e5c321c8af1e2b1bf"

    func testParseGetAssertionAuthData() throws {
        // rpIdHash || flags(0x01) || count(7)
        let auth = try AuthenticatorData(hex(rpIdHash + "0100000007"))
        XCTAssertEqual(auth.rpIdHash, hex(rpIdHash))
        XCTAssertEqual(auth.flags, 0x01)
        XCTAssertTrue(auth.userPresent)
        XCTAssertFalse(auth.hasAttestedCredentialData)
        XCTAssertEqual(auth.signCount, 7)
        XCTAssertNil(auth.attestedCredentialData)
    }

    func testParseMakeCredentialAuthData() throws {
        // flags 0x41 (UP|AT), count 0, zero aaguid, 16-byte credId a0..af, COSE Ed25519.
        let auth = try AuthenticatorData(hex(
            rpIdHash + "41" + "00000000" +
            "00000000000000000000000000000000" +     // aaguid
            "0010" +                                  // credIdLen = 16
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +      // credId
            "a4010103272006215820" +                  // COSE Ed25519
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        ))
        XCTAssertEqual(auth.flags, 0x41)
        XCTAssertTrue(auth.hasAttestedCredentialData)
        XCTAssertEqual(auth.signCount, 0)

        let acd = try XCTUnwrap(auth.attestedCredentialData)
        XCTAssertEqual(acd.aaguid, Data(repeating: 0, count: 16))
        XCTAssertEqual(acd.credentialId, hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
        guard case .ed25519(let raw) = acd.credentialPublicKey else {
            return XCTFail("expected ed25519 credential key")
        }
        XCTAssertEqual(raw, Data((0x40 ..< 0x60).map { UInt8($0) }))
    }

    func testTooShortRejected() {
        XCTAssertThrowsError(try AuthenticatorData(hex(rpIdHash + "01"))) { e in
            XCTAssertEqual(e as? AuthenticatorDataError, .tooShort)
        }
    }

    // MARK: End-to-end through the enclosing CTAP2 response objects

    func testParseFromMakeCredentialResponse() throws {
        // { 1: "none", 2: authData, 3: {} } — exactly a CTAP2 makeCredential reply.
        let resp = hex(
            "a301646e6f6e65025871" +
            rpIdHash + "41" + "00000000" +
            "00000000000000000000000000000000" + "0010" +
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
            "a4010103272006215820" +
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
            "03a0"
        )
        let cbor = try CBORReader.decode(resp)
        XCTAssertEqual(cbor.value(forIntKey: 1)?.textValue, "none")
        let authBytes = try XCTUnwrap(cbor.value(forIntKey: 2)?.bytesValue)
        let auth = try AuthenticatorData(authBytes)
        let acd = try XCTUnwrap(auth.attestedCredentialData)
        guard case .ed25519 = acd.credentialPublicKey else {
            return XCTFail("expected ed25519")
        }
        XCTAssertEqual(acd.credentialId, hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
    }

    func testParseFromGetAssertionResponse() throws {
        // { 1: {type,id}, 2: authData, 3: signature } — a CTAP2 getAssertion reply.
        let resp = hex(
            "a301a262696450a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
            "64747970656a7075626c69632d6b6579" +
            "025825" + rpIdHash + "0100000007" +
            "035840" +
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        )
        let cbor = try CBORReader.decode(resp)
        let credId = try XCTUnwrap(cbor.value(forIntKey: 1)?.value(forTextKey: "id")?.bytesValue)
        XCTAssertEqual(credId, hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))

        let authBytes = try XCTUnwrap(cbor.value(forIntKey: 2)?.bytesValue)
        let auth = try AuthenticatorData(authBytes)
        XCTAssertEqual(auth.signCount, 7)
        XCTAssertTrue(auth.userPresent)

        let sig = try XCTUnwrap(cbor.value(forIntKey: 3)?.bytesValue)
        XCTAssertEqual(sig.count, 64)
    }
}
