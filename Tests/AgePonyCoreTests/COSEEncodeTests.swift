import XCTest
@testable import AgePonyCore

final class COSEEncodeTests: XCTestCase {

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

    /// COSE_Key EC2 with alg -25, canonical CBOR — matches cbor2's output.
    func testEncodeEC2_matchesReference() throws {
        let cose = try COSEKey.encodeEC2(x963: hex(platX963))
        XCTAssertEqual(hx(cose.encoded()),
            "a5010203381820012158200217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed225820194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794")
    }

    /// Encoding then decoding recovers the same P-256 point.
    func testEncodeEC2_roundTrip() throws {
        let cose = try COSEKey.encodeEC2(x963: hex(platX963))
        let decoded = try COSEKey.decode(cose)
        XCTAssertEqual(decoded, .p256(x963: hex(platX963)))
    }

    func testEncodeEC2_rejectsBadInput() {
        XCTAssertThrowsError(try COSEKey.encodeEC2(x963: Data(repeating: 0x04, count: 33)))
        XCTAssertThrowsError(try COSEKey.encodeEC2(x963: Data([0x02]) + Data(repeating: 0, count: 64)))
    }
}
