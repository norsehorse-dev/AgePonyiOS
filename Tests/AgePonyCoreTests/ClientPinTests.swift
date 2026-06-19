import XCTest
@testable import AgePonyCore

final class ClientPinTests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return d
    }
    private func hx(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private let platX963 = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794"
    private let authX963 = "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"
    private let pinHashEnc = "cd782dd78eb3517e6279ff687e577f00"
    private let tokenEnc   = "468066941faf072e8407dc3b9d569e16"

    // MARK: clientPin requests

    func testGetKeyAgreementRequest_matchesReference() {
        XCTAssertEqual(hx(CTAP2.getKeyAgreementRequest()), "06a201010202")
    }

    func testGetPinTokenRequest_matchesReference() throws {
        let platKey = try COSEKey.encodeEC2(x963: hex(platX963))
        let req = CTAP2.getPinTokenRequest(platformKeyAgreement: platKey, pinHashEnc: hex(pinHashEnc))
        XCTAssertEqual(hx(req),
            "06a40101020503a5010203381820012158200217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed225820194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e57940650cd782dd78eb3517e6279ff687e577f00")
    }

    // MARK: clientPin responses

    func testParseGetKeyAgreementResponse() throws {
        let resp = "a101a501020338182001215820d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf322582050185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285"
        let key = try CTAP2.parseGetKeyAgreementResponse(hex(resp))
        XCTAssertEqual(key, .p256(x963: hex(authX963)))
    }

    func testParseGetPinTokenResponse() throws {
        let resp = "a10250" + tokenEnc
        let token = try CTAP2.parseGetPinTokenResponse(hex(resp))
        XCTAssertEqual(hx(token), tokenEnc)
    }

    // MARK: pinUvAuthParam threaded onto mc / ga

    func testMakeCredentialWithPinParams_matchesReference() {
        let cdh = Data((0..<32).map { UInt8($0) })
        let param = Data((0..<16).map { UInt8($0) })
        let req = CTAP2.makeCredentialRequest(
            clientDataHash: cdh, pinUvAuthParam: param, pinUvAuthProtocol: 1)
        XCTAssertEqual(hx(req),
            "01a7015820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f02a1626964647373683a03a26269644101646e616d65647373683a0482a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b657907a162726bf40850000102030405060708090a0b0c0d0e0f0901")
    }

    func testGetAssertionWithPinParams_matchesReference() {
        let cdh = Data((0..<32).map { UInt8($0) })
        let param = Data((0..<16).map { UInt8($0) })
        let allow = Data((0..<8).map { UInt8($0) })
        let req = CTAP2.getAssertionRequest(
            clientDataHash: cdh, allowCredentialIds: [allow],
            pinUvAuthParam: param, pinUvAuthProtocol: 1)
        XCTAssertEqual(hx(req),
            "02a601647373683a025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0381a262696448000102030405060764747970656a7075626c69632d6b657905a1627570f50650000102030405060708090a0b0c0d0e0f0701")
    }

    /// Regression: with no PIN params the request is unchanged (5-entry map for
    /// makeCredential, 4-entry for getAssertion — i.e. keys 8/9 absent).
    func testRequestsUnchangedWithoutPinParams() {
        let cdh = Data((0..<32).map { UInt8($0) })
        let mc = CTAP2.makeCredentialRequest(clientDataHash: cdh)
        XCTAssertEqual(mc[mc.startIndex], 0x01)            // cmd
        XCTAssertEqual(mc[mc.index(after: mc.startIndex)], 0xA5)   // map(5), no 8/9
        let ga = CTAP2.getAssertionRequest(clientDataHash: cdh, allowCredentialIds: [Data([0x01])])
        XCTAssertEqual(ga[ga.startIndex], 0x02)
        XCTAssertEqual(ga[ga.index(after: ga.startIndex)], 0xA4)   // map(4), no 8/9
    }
}
