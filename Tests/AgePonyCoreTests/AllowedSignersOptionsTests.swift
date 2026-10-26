//
//  AllowedSignersOptionsTests.swift
//  AgePonyCoreTests
//
//  allowed_signers options are parsed and enforced the way `ssh-keygen -Y verify` does
//  (audit L-6), and security-key signatures need a touch unless the signer's entry says
//  `no-touch-required` (audit L-7). Ported from Android's AllowedSignersOptionsTests and
//  SSHSigPolicyTest.
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

final class AllowedSignersOptionsTests: XCTestCase {

    let key = "AAAAC3NzaC1lZDI1NTE5AAAAILr/NVvNaGxfkVp8Ni/Z3ubM8/k89JoVOg8oMJeid1tU"
    let utc = TimeZone(identifier: "UTC")!
    let now = ISO8601DateFormatter().date(from: "2026-06-01T12:00:00Z")!

    func date(_ s: String) -> Date { ISO8601DateFormatter().date(from: s)! }

    func entry(_ options: String?) -> AllowedSigner {
        AllowedSigners.parseLine("alice@example.com \(options.map { $0 + " " } ?? "")ssh-ed25519 \(key)")!
    }

    // MARK: Tokenizing

    func test_quotedValueMayHoldCommasAndSpaces() throws {
        let line = "alice@example.com namespaces=\"agepony, git\",valid-after=\"20240101\" ssh-ed25519 \(key) the comment"
        let s = try XCTUnwrap(AllowedSigners.parseLine(line))
        XCTAssertEqual(s.options, "namespaces=\"agepony, git\",valid-after=\"20240101\"")
        XCTAssertEqual(s.keyType, "ssh-ed25519")
        XCTAssertEqual(s.keyBase64, key)
        XCTAssertEqual(s.comment, "the comment")
        let o = s.parsedOptions(zone: utc)
        XCTAssertNil(o.error)
        XCTAssertEqual(o.namespaces, "agepony, git")
        XCTAssertEqual(o.validAfter, date("2024-01-01T00:00:00Z"))
        XCTAssertEqual(AllowedSigners.serialize([s]), line + "\n")
        XCTAssertEqual(AllowedSigners.parse(AllowedSigners.serialize([s])).first, s)
    }

    func test_escapedQuoteInsideAValue() {
        let o = AllowedSignerOptions.parse("namespaces=\"a\\\"b,c\"", zone: utc)
        XCTAssertNil(o.error)
        XCTAssertEqual(o.namespaces, "a\"b,c")
    }

    func test_unterminatedQuoteDropsTheLine() {
        XCTAssertNil(AllowedSigners.parseLine("alice namespaces=\"agepony ssh-ed25519 \(key)"))
    }

    func test_tabsSeparateFields() throws {
        let s = try XCTUnwrap(AllowedSigners.parseLine("alice@example.com\tcert-authority\tssh-ed25519\t\(key)"))
        XCTAssertEqual(s.options, "cert-authority")
        XCTAssertTrue(s.isCertAuthority)
    }

    func test_quotedPrincipalsRoundTrip() throws {
        let s = try XCTUnwrap(AllowedSigners.parseLine("\"alice smith,bob\" ssh-ed25519 \(key)"))
        XCTAssertEqual(s.principals, ["alice smith", "bob"])
        let text = AllowedSigners.serialize([s])
        XCTAssertEqual(text, "\"alice smith,bob\" ssh-ed25519 \(key)\n")
        XCTAssertEqual(AllowedSigners.parse(text).first, s)
    }

    // MARK: Dates

    func test_dateFormats() {
        let ny = TimeZone(identifier: "America/New_York")!
        func after(_ v: String, _ zone: TimeZone? = nil) -> Date? {
            AllowedSignerOptions.parse("valid-after=\"\(v)\"", zone: zone ?? utc).validAfter
        }
        XCTAssertEqual(after("20250304Z"), date("2025-03-04T00:00:00Z"))
        XCTAssertEqual(after("202503040506Z"), date("2025-03-04T05:06:00Z"))
        XCTAssertEqual(after("20250304050607Z"), date("2025-03-04T05:06:07Z"))
        XCTAssertEqual(after("20250304050607utc"), date("2025-03-04T05:06:07Z"))
        XCTAssertEqual(after("20250304", ny), date("2025-03-04T05:00:00Z")) // EST, before DST
        XCTAssertEqual(AllowedSignerOptions.parse("valid-after=20250304Z", zone: utc).validAfter, date("2025-03-04T00:00:00Z"))
    }

    func test_badDatesAreErrors() {
        for v in ["2025030", "202503041", "20251301", "20250230", "2025-03-04", "20250304T", "", "Z", "19700101Z"] {
            let o = AllowedSignerOptions.parse("valid-before=\"\(v)\"", zone: utc)
            XCTAssertNotNil(o.error, "should reject '\(v)'")
            XCTAssertFalse(o.permits(namespace: "agepony", at: now), "should not permit with '\(v)'")
        }
    }

    func test_validBeforeMustFollowValidAfter() {
        XCTAssertNotNil(AllowedSignerOptions.parse("valid-after=\"20250101Z\",valid-before=\"20250101Z\"", zone: utc).error)
        XCTAssertNotNil(AllowedSignerOptions.parse("valid-after=\"20250102Z\",valid-before=\"20250101Z\"", zone: utc).error)
        XCTAssertNil(AllowedSignerOptions.parse("valid-after=\"20250101Z\",valid-before=\"20250102Z\"", zone: utc).error)
    }

    func test_duplicateClausesAreErrors() {
        XCTAssertNotNil(AllowedSignerOptions.parse("namespaces=\"a\",namespaces=\"b\"", zone: utc).error)
        XCTAssertNotNil(AllowedSignerOptions.parse("valid-after=\"20250101Z\",valid-after=\"20250102Z\"", zone: utc).error)
        XCTAssertNotNil(AllowedSignerOptions.parse("cert-authority,,no-touch-required", zone: utc).error)
    }

    // MARK: permits()

    func test_noOptionsPermitsEverything() {
        let s = entry(nil)
        XCTAssertTrue(s.permits(namespace: "agepony", at: now, zone: utc))
        XCTAssertTrue(s.permits(namespace: "git", at: now, zone: utc))
        XCTAssertFalse(s.isCertAuthority)
        XCTAssertTrue(s.requiresTouch)
        XCTAssertFalse(s.requiresUserVerification)
        XCTAssertEqual(s.unknownOptions, [])
    }

    func test_namespacesRestrict() {
        let s = entry("namespaces=\"agepony\"")
        XCTAssertTrue(s.permits(namespace: "agepony", at: now, zone: utc))
        XCTAssertFalse(s.permits(namespace: "git", at: now, zone: utc))
        XCTAssertFalse(s.permits(namespace: "agepony-sig-v2", at: now, zone: utc))
        XCTAssertFalse(s.permits(namespace: "Agepony", at: now, zone: utc))
    }

    func test_namespacePatterns() {
        let s = entry("namespaces=\"agepony*,?it,file\"")
        XCTAssertTrue(s.permits(namespace: "agepony", at: now, zone: utc))
        XCTAssertTrue(s.permits(namespace: "agepony-bundle-v2", at: now, zone: utc))
        XCTAssertTrue(s.permits(namespace: "git", at: now, zone: utc))
        XCTAssertTrue(s.permits(namespace: "file", at: now, zone: utc))
        XCTAssertFalse(s.permits(namespace: "gitx", at: now, zone: utc))
        XCTAssertFalse(s.permits(namespace: "files", at: now, zone: utc))
        let neg = entry("namespaces=\"*,!git\"")
        XCTAssertTrue(neg.permits(namespace: "agepony", at: now, zone: utc))
        XCTAssertFalse(neg.permits(namespace: "git", at: now, zone: utc))
        XCTAssertEqual(AllowedSignerOptions.matchPatternList("abc", "a*c"), 1)
        XCTAssertEqual(AllowedSignerOptions.matchPatternList("ac", "a*c"), 1)
        XCTAssertEqual(AllowedSignerOptions.matchPatternList("abd", "a*c"), 0)
        XCTAssertEqual(AllowedSignerOptions.matchPatternList("abc", "a*,!a?c"), -1)
        XCTAssertEqual(AllowedSignerOptions.matchPatternList("git", "agepony, git"), 0)
    }

    func test_agePonyFamilyCoversTheV2Namespaces() {
        let s = entry("namespaces=\"agepony\"")
        XCTAssertTrue(s.permitsAgePony(namespace: "agepony", at: now, zone: utc))
        XCTAssertTrue(s.permitsAgePony(namespace: "agepony-sig-v2", at: now, zone: utc))
        XCTAssertTrue(s.permitsAgePony(namespace: "agepony-bundle-v2", at: now, zone: utc))
        XCTAssertFalse(s.permitsAgePony(namespace: "git", at: now, zone: utc))
        XCTAssertFalse(entry("namespaces=\"git\"").permitsAgePony(namespace: "agepony-sig-v2", at: now, zone: utc))
        XCTAssertFalse(entry("namespaces=\"agepony,!agepony-sig-v2\"").permitsAgePony(namespace: "agepony-sig-v2", at: now, zone: utc))
    }

    func test_certAuthorityPermitsNothing() {
        let s = entry("Cert-Authority")
        XCTAssertTrue(s.isCertAuthority)
        XCTAssertFalse(s.permits(namespace: "agepony", at: now, zone: utc))
        XCTAssertFalse(s.permitsAgePony(namespace: "agepony", at: now, zone: utc))
    }

    func test_unknownOptionsPermitNothing() {
        let s = entry("namespaces=\"agepony\",restrict,from=\"10.0.0.1\"")
        XCTAssertEqual(s.unknownOptions, ["restrict", "from=\"10.0.0.1\""])
        XCTAssertFalse(s.permits(namespace: "agepony", at: now, zone: utc))
        XCTAssertEqual(entry("cert-authority=\"x\"").unknownOptions, ["cert-authority=\"x\""])
        XCTAssertEqual(entry("namespaces").unknownOptions, ["namespaces"])
    }

    func test_validityWindow() {
        let s = entry("valid-after=\"20260101Z\",valid-before=\"20261231235959Z\"")
        XCTAssertTrue(s.permits(namespace: "agepony", at: now, zone: utc))
        XCTAssertFalse(s.permits(namespace: "agepony", at: date("2025-12-31T23:59:59Z"), zone: utc))
        XCTAssertTrue(s.permits(namespace: "agepony", at: date("2026-01-01T00:00:00Z"), zone: utc))
        XCTAssertTrue(s.permits(namespace: "agepony", at: date("2026-12-31T23:59:59Z"), zone: utc))
        XCTAssertFalse(s.permits(namespace: "agepony", at: date("2027-01-01T00:00:00Z"), zone: utc))
        XCTAssertFalse(entry("valid-before=\"20200101\"").permits(namespace: "agepony", at: now, zone: utc))
        XCTAssertFalse(entry("valid-after=\"20300101\"").permits(namespace: "agepony", at: now, zone: utc))
    }

    func test_localTimeUsesTheSuppliedZone() {
        let s = entry("valid-after=\"20260601\"")
        let tokyo = TimeZone(identifier: "Asia/Tokyo")!
        XCTAssertTrue(s.permits(namespace: "agepony", at: date("2026-05-31T15:00:00Z"), zone: tokyo))
        XCTAssertFalse(s.permits(namespace: "agepony", at: date("2026-05-31T14:59:59Z"), zone: tokyo))
    }

    // MARK: Security-key touch (L-7)

    func skSignature(flags: UInt8, namespace: String = "agepony", message: Data) throws -> (String, Data) {
        let key = Curve25519.Signing.PrivateKey()
        let app = Data("ssh:".utf8)
        let signed = SSHSig.signedData(messageHash: SSHSigHash.sha512.digest(message), namespace: namespace, hash: .sha512)
        let authMsg = SSHSig.skAuthenticatorMessage(application: app, flags: flags, counter: 7, signedData: signed)
        let raw = try key.signature(for: authMsg)
        let armored = try SSHSigner.assembleSkEd25519(publicKey: key.publicKey.rawRepresentation, application: app,
                                                      rawSig: raw, flags: flags, counter: 7, namespace: namespace)
        return (armored, SSHSig.skEd25519PublicKeyWire(rawPublicKey: key.publicKey.rawRepresentation, application: app))
    }

    func test_skSignatureWithoutTouch_needsNoTouchRequired() throws {
        let msg = Data("touch me".utf8)
        let (untouched, wire) = try skSignature(flags: 0x00, message: msg)
        XCTAssertThrowsError(try SSHSigVerifier.verify(message: msg, armoredSignature: untouched)) {
            XCTAssertEqual($0 as? SSHSigError, .userPresenceRequired)
        }
        let v = try SSHSigVerifier.verify(message: msg, armoredSignature: untouched, allowNoTouch: true)
        XCTAssertEqual(v.userPresent, false)

        let b64 = wire.base64EncodedString()
        let strict = AllowedSigners.parseLine("me sk-ssh-ed25519@openssh.com \(b64)")!
        let relaxed = AllowedSigners.parseLine("me no-touch-required sk-ssh-ed25519@openssh.com \(b64)")!
        XCTAssertFalse(strict.accepts(v, at: now, zone: utc))
        XCTAssertTrue(relaxed.accepts(v, at: now, zone: utc))
        XCTAssertThrowsError(try SSHSigVerifier.verify(message: msg, armoredSignature: untouched, principal: "me", allowedSigners: [strict]))
        XCTAssertNoThrow(try SSHSigVerifier.verify(message: msg, armoredSignature: untouched, principal: "me", allowedSigners: [relaxed]))

        let (touched, _) = try skSignature(flags: 0x01, message: msg)
        let t = try SSHSigVerifier.verify(message: msg, armoredSignature: touched)
        XCTAssertEqual(t.userPresent, true)
        XCTAssertEqual(t.userVerified, false)
        let uvRequired = AllowedSigners.parseLine("me verify-required sk-ssh-ed25519@openssh.com \(b64)")!
        XCTAssertFalse(uvRequired.accepts(t, at: now, zone: utc))
        let (verified, _) = try skSignature(flags: 0x05, message: msg)
        XCTAssertTrue(uvRequired.accepts(try SSHSigVerifier.verify(message: msg, armoredSignature: verified), at: now, zone: utc))
    }

    func test_oversizedSignatureIsRefused() {
        let huge = SSHSig.armorBegin + "\n" + String(repeating: "A", count: 20_000) + "\n" + SSHSig.armorEnd
        XCTAssertThrowsError(try SSHSigVerifier.verify(message: Data(), armoredSignature: huge))
    }
}
