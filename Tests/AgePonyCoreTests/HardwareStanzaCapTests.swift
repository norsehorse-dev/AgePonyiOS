//
//  HardwareStanzaCapTests.swift
//  AgePonyCoreTests
//
//  A crafted header can address any number of stanzas to a hardware key, since the
//  tag comes from the public key. Each hardware identity is asked at most
//  `Age.maxStanzasPerHardwareIdentity` times per file, never again after it throws,
//  and one YubiKey tap runs at most that many ECDHs (5.1.1, L-7).
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

final class HardwareStanzaCapTests: XCTestCase {

    struct MockError: Error, Equatable {}

    /// A hardware identity that counts how often it is asked to open a stanza.
    final class MockHardware: HardwareIdentity {
        let type: String
        let throwsError: Bool
        let fileKey: Data?
        var unwrapCalls = 0

        init(type: String, throwsError: Bool = false, fileKey: Data? = nil) {
            self.type = type
            self.throwsError = throwsError
            self.fileKey = fileKey
        }

        func matches(stanza: Stanza) -> Bool { stanza.type == type }

        func unwrap(stanza: Stanza) throws -> Data? {
            guard stanza.type == type else { return nil }
            unwrapCalls += 1
            if throwsError { throw MockError() }
            return fileKey
        }
    }

    /// A P-256 key agreement that counts its ECDHs (each one an Enclave or card operation).
    final class CountingKeyAgreement: P256KeyAgreement {
        let inner = P256SoftwareKey.generate()
        var calls = 0
        func sharedX(peerUncompressed: Data) throws -> Data {
            calls += 1
            return try inner.sharedX(peerUncompressed: peerUncompressed)
        }
    }

    private func junk(_ s: Stanza) -> Stanza {
        var body = s.body
        body[body.index(before: body.endIndex)] ^= 0x01
        return Stanza(type: s.type, args: s.args, body: body)
    }

    private func randomFileKey() -> Data {
        Data((0..<Age.fileKeySize).map { _ in UInt8.random(in: 0...255) })
    }

    // MARK: - unwrapFileKey

    func test_hundredMatchingStanzas_atMostFourHardwareCalls() throws {
        let hw = MockHardware(type: "mock-hw")
        let stanzas = (0..<100).map { _ in Stanza(type: "mock-hw", args: [], body: Data()) }
        XCTAssertThrowsError(try Age.unwrapFileKey(stanzas: stanzas, identities: [hw])) {
            XCTAssertEqual($0 as? AgeError, .noMatchingIdentity)
        }
        XCTAssertEqual(hw.unwrapCalls, Age.maxStanzasPerHardwareIdentity)
        XCTAssertLessThanOrEqual(hw.unwrapCalls, 4)
    }

    func test_hundredMatchingTagStanzas_atMostFourECDHs() throws {
        let ka = CountingKeyAgreement()
        let id = try TagIdentity.classic(publicKey: ka.inner.publicUncompressed, p256: ka)
        let stanzas = try (0..<100).map { _ in junk(try id.recipient.wrap(fileKey: randomFileKey())) }
        XCTAssertTrue(stanzas.allSatisfy { id.matches(stanza: $0) })
        XCTAssertThrowsError(try Age.unwrapFileKey(stanzas: stanzas, identities: [id]))
        XCTAssertLessThanOrEqual(ka.calls, 4)
        XCTAssertGreaterThan(ka.calls, 0)
    }

    func test_validStanzaAmongJunk_stillOpens() throws {
        let ka = CountingKeyAgreement()
        let id = try TagIdentity.classic(publicKey: ka.inner.publicUncompressed, p256: ka)
        let fileKey = randomFileKey()
        let valid = try id.recipient.wrap(fileKey: fileKey)
        let stanzas = [junk(try id.recipient.wrap(fileKey: randomFileKey())), valid]
            + (try (0..<50).map { _ in junk(try id.recipient.wrap(fileKey: randomFileKey())) })
        XCTAssertEqual(try Age.unwrapFileKey(stanzas: stanzas, identities: [id]), fileKey)
        XCTAssertEqual(ka.calls, 2)
    }

    func test_identityThatThrows_isNotAskedAgain_andItsErrorSurfaces() throws {
        let hw = MockHardware(type: "mock-hw", throwsError: true)
        let stanzas = (0..<10).map { _ in Stanza(type: "mock-hw", args: [], body: Data()) }
        XCTAssertThrowsError(try Age.unwrapFileKey(stanzas: stanzas, identities: [hw])) {
            XCTAssertEqual($0 as? MockError, MockError())
        }
        XCTAssertEqual(hw.unwrapCalls, 1)
    }

    func test_throwingIdentity_doesNotStopOtherHardware() throws {
        let fileKey = randomFileKey()
        let failing = MockHardware(type: "a", throwsError: true)
        let working = MockHardware(type: "b", fileKey: fileKey)
        let stanzas = [
            Stanza(type: "a", args: [], body: Data()),
            Stanza(type: "a", args: [], body: Data()),
            Stanza(type: "b", args: [], body: Data()),
        ]
        XCTAssertEqual(try Age.unwrapFileKey(stanzas: stanzas, identities: [failing, working]), fileKey)
        XCTAssertEqual(failing.unwrapCalls, 1)
        XCTAssertEqual(working.unwrapCalls, 1)
    }

    func test_capIsPerIdentity() throws {
        let a = MockHardware(type: "a")
        let b = MockHardware(type: "b")
        let stanzas = (0..<20).map { Stanza(type: $0 % 2 == 0 ? "a" : "b", args: [], body: Data()) }
        XCTAssertThrowsError(try Age.unwrapFileKey(stanzas: stanzas, identities: [a, b]))
        XCTAssertEqual(a.unwrapCalls, 4)
        XCTAssertEqual(b.unwrapCalls, 4)
    }

    // MARK: - YubiKey

    private func yubiKey() throws -> (key: P256SoftwareKey, compressed: Data, stub: YubiKeyStub) {
        let key = P256SoftwareKey.generate()
        let compressed = try P256Curve.compressed(key.publicUncompressed)
        let stub = try YubiKeyStub(serial: 1, slot: 0x82, tag: YubiKeyStub.staticTag(compressedPublicKey: compressed))
        return (key, compressed, stub)
    }

    func test_peerPoints_returnsAtMostFour() throws {
        let (_, compressed, stub) = try yubiKey()
        let tag = try TagRecipient(publicKey: compressed)
        let piv = try P256Recipient(compressedPublicKey: compressed)
        let stanzas = try (0..<100).map { i in
            try (i % 2 == 0 ? tag.wrap(fileKey: randomFileKey()) : piv.wrap(fileKey: randomFileKey()))
        }
        let probe = try YubiKeyIdentity.probe(stub: stub, publicKey: compressed)
        XCTAssertTrue(stanzas.allSatisfy { probe.matches(stanza: $0) })
        let points = probe.peerPoints(in: stanzas)
        XCTAssertEqual(points.count, 4)
        XCTAssertEqual(Set(points).count, 4)
    }

    func test_peerPoints_matchWhatDecryptTries() throws {
        // The recorded ECDHs cover exactly the stanzas unwrapFileKey asks the key about,
        // so a valid stanza within the first four still opens and nothing throws Missing.
        let (key, compressed, stub) = try yubiKey()
        let tag = try TagRecipient(publicKey: compressed)
        let fileKey = randomFileKey()
        var stanzas = try (0..<3).map { _ in junk(try tag.wrap(fileKey: randomFileKey())) }
        stanzas.append(try tag.wrap(fileKey: fileKey))
        stanzas += try (0..<40).map { _ in junk(try tag.wrap(fileKey: randomFileKey())) }
        let points = try YubiKeyIdentity.probe(stub: stub, publicKey: compressed).peerPoints(in: stanzas)
        var results: [Data: Data] = [:]
        for p in points { results[p] = try key.sharedX(peerUncompressed: p) }
        let id = try YubiKeyIdentity(stub: stub, publicKey: compressed, keyAgreement: RecordedKeyAgreement(results: results))
        XCTAssertEqual(try Age.unwrapFileKey(stanzas: stanzas, identities: [id]), fileKey)
    }

    func test_sessionKeyAgreements_runAtMostFourECDHs() throws {
        /// Answers SELECT, declines GET SERIAL, and counts GENERAL AUTHENTICATE.
        final class CountingCard: PivCard {
            var ecdhCalls = 0
            func transmit(_ apdu: Data) throws -> Data {
                let ins = apdu[apdu.startIndex + 1]
                switch ins {
                case 0xA4: return Data([0x90, 0x00])
                case 0x87:
                    ecdhCalls += 1
                    return Data([0x7C, 0x22, 0x82, 0x20]) + Data(repeating: 0x11, count: 32) + Data([0x90, 0x00])
                default: return Data([0x6D, 0x00])
                }
            }
        }
        let (_, _, stub) = try yubiKey()
        let points = (0..<100).map { _ in P256SoftwareKey.generate().publicUncompressed }
        let card = CountingCard()
        let results = try PivSession.keyAgreements(card, stub: stub, points: points, pin: nil)
        XCTAssertEqual(card.ecdhCalls, 4)
        XCTAssertEqual(results.count, 4)
    }
}
