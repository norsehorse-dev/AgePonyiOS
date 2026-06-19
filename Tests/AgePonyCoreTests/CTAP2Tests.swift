//
//  CTAP2Tests.swift
//  AgePonyCoreTests
//
//  Request builders pinned to CBOR generated with cbor2; response parsers and
//  the DER->raw conversion pinned to vectors built with cbor2 / cryptography.
//

import XCTest
@testable import AgePonyCore

final class CTAP2Tests: XCTestCase {

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

    private let cdh = Data(repeating: 0x11, count: 32)
    private let credId = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    private let rpIdHash = "e30610e8a162115960fe1ec223e6529c9f4b6e80200dcb5e5c321c8af1e2b1bf"

    // MARK: Requests

    func testMakeCredentialRequest() {
        let golden = hex(
            "01" +   // command byte
            "a50158201111111111111111111111111111111111111111111111111111111111111111" +
            "02a1626964647373683a" +
            "03a26269644101646e616d65647373683a" +
            "0482a263616c672764747970656a7075626c69632d6b6579" +
            "a263616c672664747970656a7075626c69632d6b6579" +
            "07a162726bf4"
        )
        XCTAssertEqual(CTAP2.makeCredentialRequest(clientDataHash: cdh), golden)
    }

    func testGetAssertionRequest() {
        let golden = hex(
            "02" +   // command byte
            "a401647373683a" +
            "025820" + "1111111111111111111111111111111111111111111111111111111111111111" +
            "0381a262696450" + credId + "64747970656a7075626c69632d6b6579" +
            "05a1627570f5"
        )
        XCTAssertEqual(
            CTAP2.getAssertionRequest(clientDataHash: cdh, allowCredentialIds: [hex(credId)]),
            golden
        )
    }

    // MARK: Responses

    func testParseMakeCredentialResponse() throws {
        let resp = hex(
            "a301646e6f6e65025871" +
            rpIdHash + "41" + "00000000" +
            "00000000000000000000000000000000" + "0010" + credId +
            "a4010103272006215820" +
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
            "03a0"
        )
        let result = try CTAP2.parseMakeCredentialResponse(resp)
        XCTAssertEqual(result.credentialId, hex(credId))
        XCTAssertEqual(result.signCount, 0)
        guard case .ed25519(let raw) = result.publicKey else {
            return XCTFail("expected ed25519")
        }
        XCTAssertEqual(raw, Data((0x40 ..< 0x60).map { UInt8($0) }))
    }

    func testParseGetAssertionResponse() throws {
        let sig = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        let resp = hex(
            "a301a262696450" + credId + "64747970656a7075626c69632d6b6579" +
            "025825" + rpIdHash + "0100000007" +
            "035840" + sig
        )
        let result = try CTAP2.parseGetAssertionResponse(resp)
        XCTAssertEqual(result.credentialId, hex(credId))
        XCTAssertEqual(result.signature, hex(sig))
        XCTAssertEqual(result.authenticatorData.signCount, 7)
        XCTAssertTrue(result.authenticatorData.userPresent)
    }

    func testParseGetAssertionRejectsMissingSignature() {
        // authData present, signature (key 3) absent.
        let resp = hex("a1025825" + rpIdHash + "0100000007")
        XCTAssertThrowsError(try CTAP2.parseGetAssertionResponse(resp)) { e in
            XCTAssertEqual(e as? CTAP2Error, .missingSignature)
        }
    }

    // MARK: DER -> raw r||s

    func testDERtoRawSignature() throws {
        let der = hex(
            "30440220" +
            "1122334455667788990011223344556677889900112233445566778899001122" +
            "0220" +
            "33445566778899001122334455667788990011223344556677889900112233ab"
        )
        let raw = try CTAP2.rawP256Signature(fromDER: der)
        XCTAssertEqual(raw, hex(
            "1122334455667788990011223344556677889900112233445566778899001122" +
            "33445566778899001122334455667788990011223344556677889900112233ab"
        ))
    }

    func testDERtoRawSignatureWithPadding() throws {
        // r needs a DER sign byte (0x21 length); s has a leading-zero high byte.
        let der = hex(
            "3045022100" +
            "ab11223344556677889900112233445566778899001122334455667788990011" +
            "0220" +
            "00ffeeddccbbaa00112233445566778899001122334455667788990011223344"
        )
        let raw = try CTAP2.rawP256Signature(fromDER: der)
        XCTAssertEqual(raw, hex(
            "ab11223344556677889900112233445566778899001122334455667788990011" +
            "00ffeeddccbbaa00112233445566778899001122334455667788990011223344"
        ))
    }
}
