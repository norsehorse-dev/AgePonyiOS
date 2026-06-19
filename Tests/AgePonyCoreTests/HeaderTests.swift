//
//  HeaderTests.swift
//  AgePonyCoreTests
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class HeaderTests: XCTestCase {

    private func makeFileKey() -> Data {
        Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
    }

    private func makeStanza() -> Stanza {
        Stanza(
            type: "X25519",
            args: [Stanza.base64NoPad(Data((0..<32).map { _ in UInt8.random(in: 0...UInt8.max) }))],
            body: Data((0..<32).map { _ in UInt8.random(in: 0...UInt8.max) })
        )
    }

    // MARK: - Serialize / parse round-trip

    func testHeaderRoundTripSingleStanza() throws {
        let fileKey = makeFileKey()
        let stanza = makeStanza()
        let bytes = AgeHeader.serialize(stanzas: [stanza], fileKey: fileKey)
        let (parsed, payloadOffset) = try AgeHeader.parse(bytes: bytes)
        XCTAssertEqual(parsed.stanzas.count, 1)
        XCTAssertEqual(parsed.stanzas[0].type, stanza.type)
        XCTAssertEqual(parsed.stanzas[0].args, stanza.args)
        XCTAssertEqual(parsed.stanzas[0].body, stanza.body)
        XCTAssertEqual(payloadOffset, bytes.count, "payload should start at end of header bytes")
        try parsed.verifyMAC(fileKey: fileKey)
    }

    func testHeaderRoundTripMultipleStanzas() throws {
        let fileKey = makeFileKey()
        let stanzas = [makeStanza(), makeStanza(), makeStanza()]
        let bytes = AgeHeader.serialize(stanzas: stanzas, fileKey: fileKey)
        let (parsed, _) = try AgeHeader.parse(bytes: bytes)
        XCTAssertEqual(parsed.stanzas.count, 3)
        for i in 0..<3 {
            XCTAssertEqual(parsed.stanzas[i].type, stanzas[i].type)
            XCTAssertEqual(parsed.stanzas[i].args, stanzas[i].args)
            XCTAssertEqual(parsed.stanzas[i].body, stanzas[i].body)
        }
        try parsed.verifyMAC(fileKey: fileKey)
    }

    func testHeaderWithPayloadBytesAppended() throws {
        let fileKey = makeFileKey()
        let stanza = makeStanza()
        var bytes = AgeHeader.serialize(stanzas: [stanza], fileKey: fileKey)
        let payloadFake = Data((0..<100).map { _ in UInt8.random(in: 0...UInt8.max) })
        bytes.append(payloadFake)
        let (_, payloadOffset) = try AgeHeader.parse(bytes: bytes)
        XCTAssertEqual(bytes.suffix(from: payloadOffset), payloadFake)
    }

    // MARK: - MAC verification

    func testMACVerificationFailsWithWrongFileKey() throws {
        let real = makeFileKey()
        let wrong = makeFileKey()
        let stanza = makeStanza()
        let bytes = AgeHeader.serialize(stanzas: [stanza], fileKey: real)
        let (parsed, _) = try AgeHeader.parse(bytes: bytes)
        XCTAssertThrowsError(try parsed.verifyMAC(fileKey: wrong)) { error in
            XCTAssertEqual(error as? AgeHeaderError, .invalidMAC)
        }
    }

    func testMACVerificationFailsWhenStanzaTampered() throws {
        let fileKey = makeFileKey()
        let stanza = makeStanza()
        let bytes = AgeHeader.serialize(stanzas: [stanza], fileKey: fileKey)
        var parsed = try AgeHeader.parse(bytes: bytes).header

        // Mutate the stanza body and re-verify — the saved MAC should no longer match.
        var tamperedBody = Data(parsed.stanzas[0].body)
        tamperedBody[0] ^= 0x01
        let tamperedStanza = Stanza(type: parsed.stanzas[0].type, args: parsed.stanzas[0].args, body: tamperedBody)
        parsed = AgeHeader(stanzas: [tamperedStanza], mac: parsed.mac)
        XCTAssertThrowsError(try parsed.verifyMAC(fileKey: fileKey)) { error in
            XCTAssertEqual(error as? AgeHeaderError, .invalidMAC)
        }
    }

    // MARK: - Rejection of malformed input

    func testRejectsMissingVersionLine() {
        let bytes = Data("not a real header\n--- AAAA\n".utf8)
        XCTAssertThrowsError(try AgeHeader.parse(bytes: bytes))
    }

    func testRejectsUnsupportedVersion() {
        let mac = Stanza.base64NoPad(Data(repeating: 0, count: 32))
        let sample = "age-encryption.org/v99\n--- \(mac)\n"
        XCTAssertThrowsError(try AgeHeader.parse(bytes: Data(sample.utf8))) { error in
            // Either unsupportedVersion or noStanzas — both indicate clean rejection
            // of the future-versioned header.
            switch error as? AgeHeaderError {
            case .unsupportedVersion, .noStanzas:
                break
            default:
                XCTFail("expected an AgeHeaderError rejection, got \(error)")
            }
        }
    }

    func testRejectsHeaderWithNoStanzas() {
        let mac = Stanza.base64NoPad(Data(repeating: 0, count: 32))
        let sample = "age-encryption.org/v1\n--- \(mac)\n"
        XCTAssertThrowsError(try AgeHeader.parse(bytes: Data(sample.utf8))) { error in
            XCTAssertEqual(error as? AgeHeaderError, .noStanzas)
        }
    }

    func testRejectsMissingFooter() {
        let sample = "age-encryption.org/v1\n-> X25519 abc\nQUJD\n"
        XCTAssertThrowsError(try AgeHeader.parse(bytes: Data(sample.utf8)))
    }
}
