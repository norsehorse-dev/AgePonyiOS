//
//  NFCResendPolicyTests.swift
//  AgePonyTests
//
//  5.1.1 (L-8): after a transient NFC error, only commands that are safe to run twice
//  are resent. A PIV VERIFY or a CTAP clientPIN request never is, so a wrong PIN can't
//  cost two tries; the user is asked to hold the key again instead.
//

import XCTest
import Foundation
import AgePonyCore
@testable import AgePony

@MainActor
final class NFCResendPolicyTests: XCTestCase {

    /// Records every APDU the PIV code builds and answers with a fixed status word.
    final class RecordingCard: PivCard {
        var sent: [Data] = []
        let reply: Data
        init(reply: Data) { self.reply = reply }
        func transmit(_ apdu: Data) throws -> Data {
            sent.append(apdu)
            return reply
        }
    }

    private func lastAPDU(reply: Data = Data([0x6D, 0x00]), _ run: (PivCard) throws -> Void) -> Data? {
        let card = RecordingCard(reply: reply)
        try? run(card)
        return card.sent.last
    }

    func testVerifyIsNeverResent() throws {
        let verify = try XCTUnwrap(lastAPDU(reply: Data([0x63, 0xC2])) { try Piv.verifyPIN($0, pin: "123456") })
        XCTAssertEqual(verify[verify.startIndex + 1], 0x20)
        XCTAssertFalse(NFCResendPolicy.mayResend(apdu: verify))
        // Whatever the CLA byte, VERIFY stays blocked.
        XCTAssertFalse(NFCResendPolicy.mayResend(apdu: Data([0x10, 0x20, 0x00, 0x80, 0x08]) + Data(repeating: 0x31, count: 8)))
    }

    func testIdempotentPivCommandsKeepTheirRetry() throws {
        let select = try XCTUnwrap(lastAPDU { try Piv.select($0) })
        let serial = try XCTUnwrap(lastAPDU { _ = try Piv.serial($0) })
        let getData = try XCTUnwrap(lastAPDU { _ = try Piv.readPublicKey($0, slot: 0x82) })
        let metadata = try XCTUnwrap(lastAPDU { _ = try Piv.pinPolicy($0, slot: 0x82) })
        let peer = P256SoftwareKey.generate().publicUncompressed
        let ecdh = try XCTUnwrap(lastAPDU(reply: Data([0x69, 0x82])) { _ = try Piv.ecdh($0, slot: 0x82, peerUncompressed: peer) })
        for (name, apdu) in [("SELECT", select), ("GET SERIAL", serial), ("GET DATA", getData),
                             ("GET METADATA", metadata), ("GENERAL AUTHENTICATE", ecdh)] {
            XCTAssertTrue(NFCResendPolicy.mayResend(apdu: apdu), name)
        }
    }

    func testUnknownOrShortCommandsAreNotResent() {
        XCTAssertFalse(NFCResendPolicy.mayResend(apdu: Data()))
        XCTAssertFalse(NFCResendPolicy.mayResend(apdu: Data([0x00, 0xA4, 0x04])))
        // CHANGE REFERENCE DATA and RESET RETRY COUNTER also touch PIN state.
        XCTAssertFalse(NFCResendPolicy.mayResend(apdu: Data([0x00, 0x24, 0x00, 0x80])))
        XCTAssertFalse(NFCResendPolicy.mayResend(apdu: Data([0x00, 0x2C, 0x00, 0x80])))
    }

    func testClientPINIsNeverResent() {
        XCTAssertFalse(NFCResendPolicy.mayResend(ctapRequest: CTAP2.getKeyAgreementRequest()))
        let getPinToken = CTAP2.getPinTokenRequest(platformKeyAgreement: .unsigned(0), pinHashEnc: Data(count: 16))
        XCTAssertEqual(getPinToken.first, CTAP2.cmdClientPin)
        XCTAssertFalse(NFCResendPolicy.mayResend(ctapRequest: getPinToken))
        XCTAssertFalse(NFCResendPolicy.mayResend(ctapRequest: Data()))
    }

    func testOtherCTAPRequestsKeepTheirRetry() {
        let hash = Data(count: 32)
        XCTAssertTrue(NFCResendPolicy.mayResend(ctapRequest: CTAP2.makeCredentialRequest(clientDataHash: hash)))
        XCTAssertTrue(NFCResendPolicy.mayResend(ctapRequest: CTAP2.getAssertionRequest(clientDataHash: hash, allowCredentialIds: [Data([1, 2, 3])])))
    }
}
