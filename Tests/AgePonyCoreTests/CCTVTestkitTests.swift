//
//  CCTVTestkitTests.swift
//  AgePonyCoreTests
//
//  Runs the C2SP CCTV age test vectors (github.com/C2SP/CCTV, `age/testdata`) through
//  AgePony's real decrypt path: AgeArmor.decode for armored files, then the streaming
//  Age.decryptStream, hashing every plaintext byte it releases.
//
//  Source and updating: the vectors live in `Testkit/` (copied as is, commit recorded in
//  `Testkit/SOURCE.md`, format in `Testkit/CCTV-README.md`) and ship with the test target
//  as `resources: [.copy("Testkit")]`. To update, replace the vector files, record the new
//  commit in SOURCE.md, then set `expectedVectorCount` (and `expectedSkipped` if a vector
//  uses a header key this runner doesn't know) to match the new set.
//
//  Error mapping (`category(for:)`). CCTV has six expected results; AgePony's errors map
//  onto them as follows. Rows marked "alias" are places where AgePony can't tell two CCTV
//  results apart or files the failure at a different stage than Go age does.
//
//    AgeArmorError (any)                          -> armor failure
//    AgeError.headerError(.invalidMAC)            -> HMAC failure
//    AgeError.headerError(any other)              -> header failure
//    AgeError.payloadError(.missingNoncePrefix)   -> header failure   (alias: AgePony reads
//                                                    the 16-byte nonce in the payload stage;
//                                                    CCTV counts a missing/short nonce as a
//                                                    header failure)
//    AgeError.payloadError(any other)             -> payload failure
//    AgeError.noMatchingIdentity / .wrongPassphrase -> no match
//    AgeError.scryptNotAlone                      -> header failure
//    AgeError.invalidFileKeyLength / .truncatedFile -> header failure
//    ScryptStanzaError.invalidWorkFactor          -> header failure   (work factor above
//                                                    ScryptIdentity.maxWorkFactor, refused
//                                                    before any KDF work)
//    anything else                                -> "unexpected error" (never matches)
//
//  Alias "no match" for "header failure": AgeIdentity.unwrap returns nil both for "not
//  for me" and for a stanza of its own type that it can't use (wrong argument count,
//  non-canonical or wrong-length share/salt, malformed work factor, low-order share,
//  wrapped key that isn't 16+16 bytes; audits L-5 and L-14). Go age fails the header for
//  those. So `no match` is accepted for an expected `header failure` only when the header
//  itself parsed and at least one stanza has a type one of the vector's identities
//  handles (X25519, mlkem768x25519, scrypt). Every vector passing through this alias is
//  printed to the test log.
//
//  `knownDivergences` lists vectors AgePony deliberately handles differently, each with
//  the exact outcome AgePony is expected to give instead and why. An entry only waives
//  that specific outcome, and the test fails if a listed vector starts passing, so the
//  list can't go stale.
//

import XCTest
import CryptoKit
import Foundation
@testable import AgePonyCore

// Not final: CCTVTestkitOwnCodeTests (CryptoKitBackendTests.swift) runs the vectors again
// with the own code forced, so on macOS 26 both backends are covered (5.1.0 RC3).
class CCTVTestkitTests: XCTestCase {

    /// The post-quantum backend this class's tests must run on: CryptoKit on macOS 26 /
    /// iOS 26, own code before; the OwnCode subclasses override it (RC3 review fix 5).
    class var expectsCryptoKit: Bool { CryptoKitBackendTests.cryptoKitExpected }

    override func invokeTest() {
        XCTAssertEqual(HybridKEMBackend.usesCryptoKit, type(of: self).expectsCryptoKit,
                       "post-quantum backend for \(type(of: self))")
        super.invokeTest()
    }

    // MARK: - Expectations for the vendored set

    /// Vectors at CCTV commit 50a8ecf (see Testkit/SOURCE.md).
    private static let expectedVectorCount = 147

    /// Vectors this runner is expected to skip for using an unknown header key. None today.
    private static let expectedSkipped: Set<String> = []

    /// Files in Testkit/ that aren't vectors.
    private static let nonVectorFiles: Set<String> = ["CCTV-README.md", "SOURCE.md", "RUNNER-NOTES.md"]

    // MARK: - Categories

    enum Category: String, Sendable {
        case success = "success"
        case noMatch = "no match"
        case hmacFailure = "HMAC failure"
        case headerFailure = "header failure"
        case payloadFailure = "payload failure"
        case armorFailure = "armor failure"
        /// Not a CCTV category: an error the mapping doesn't know, or a runner problem.
        case unexpected = "unexpected error"
    }

    // MARK: - Known divergences

    struct KnownDivergence: Sendable {
        /// The category AgePony gives instead of the expected one.
        let actual: Category
        /// True when the category matches and only the released-plaintext hash differs.
        let hashOnly: Bool
        let reason: String
    }

    private static let armorWhitespace = """
        AgeArmor.decode trims every byte <= 0x20 (spaces, tabs, CR) from both ends of each \
        armor line, on purpose, so armor pasted from mail or chat still opens. Go age \
        rejects this input. The decoded bytes are the same either way.
        """

    private static let armorBlankBeforeEnd = """
        AgePony accepts one blank line between a full 64-column final line and END, as age \
        1.1.1 does, so armor from older age versions still opens (StrictFormatTests \
        test_armorWithAFullFinalLine). Newer age and CCTV reject it. Two blank lines are \
        still refused.
        """

    private static let streamReadAhead = """
        AgePayload.decryptStream reads one chunk ahead and only opens a chunk once it knows \
        whether it is the last one, so it never releases a chunk it then has to reject. Go \
        age opens the chunk first (retrying it as final) and fails afterwards, so it releases \
        one more chunk before the error. Same category; AgePony releases a shorter prefix.
        """

    private static let knownDivergences: [String: KnownDivergence] = [
        "armor_cr_line_start": KnownDivergence(actual: .success, hashOnly: false, reason: armorWhitespace),
        "armor_double_crlf": KnownDivergence(actual: .success, hashOnly: false, reason: armorWhitespace),
        "armor_whitespace_eol": KnownDivergence(actual: .success, hashOnly: false, reason: armorWhitespace),
        "armor_whitespace_last_line": KnownDivergence(actual: .success, hashOnly: false, reason: armorWhitespace),
        "armor_whitespace_line_start": KnownDivergence(actual: .success, hashOnly: false, reason: armorWhitespace),
        "armor_empty_last_line": KnownDivergence(actual: .success, hashOnly: false, reason: armorBlankBeforeEnd),

        "armor_garbage_encoded": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
        "stream_no_final_full": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
        "stream_no_final_two_chunks_full": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
        "stream_short_second_chunk": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
        "stream_trailing_garbage_long": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
        "stream_trailing_garbage_short": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
        "stream_two_final_chunks": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
        "stream_two_final_chunks_full": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
        "stream_two_final_chunks_second": KnownDivergence(actual: .payloadFailure, hashOnly: true, reason: streamReadAhead),
    ]

    // MARK: - Vector model

    struct Vector {
        let name: String
        let expect: Category
        let payloadHash: String?
        let identities: [String]
        let passphrases: [String]
        let armored: Bool
        let compressed: Bool
        let body: Data
    }

    enum ParsedFile {
        case vector(Vector)
        case skipped(String)
    }

    struct Outcome {
        let category: Category
        let detail: String
        let releasedHash: String
        /// Stanza types in the header, when AgePony could parse it (used by the alias).
        let stanzaTypes: Set<String>?
        /// Stanza types the vector's identities handle.
        let handledTypes: Set<String>
    }

    enum RunnerError: Error, CustomStringConvertible {
        case badZlib(String)
        case badIdentity(String)

        var description: String {
            switch self {
            case .badZlib(let s): return "runner: zlib: \(s)"
            case .badIdentity(let s): return "runner: identity: \(s)"
            }
        }
    }

    // MARK: - The test

    func testCCTVVectors() throws {
        print("CCTV: post-quantum backend \(HybridKEMBackend.usesCryptoKit ? "CryptoKit" : "own code") "
              + "(\(String(describing: type(of: self))))")
        let root = try XCTUnwrap(
            Bundle.module.url(forResource: "Testkit", withExtension: nil),
            "Testkit folder missing from the test bundle (check resources in Package.swift)"
        )
        let files = try FileManager.default
            .contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
            .filter { !$0.lastPathComponent.hasPrefix(".") }
            .filter { !Self.nonVectorFiles.contains($0.lastPathComponent) }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        var processed = 0
        var skipped: [String] = []
        var failures: [String] = []
        var aliased: [String] = []
        var waived: [String] = []
        var seen: Set<String> = []

        for url in files {
            let name = url.lastPathComponent
            seen.insert(name)
            let raw = try Data(contentsOf: url)
            let vector: Vector
            switch Self.parse(name: name, raw: raw) {
            case .skipped(let why):
                skipped.append("\(name) (\(why))")
                continue
            case .vector(let v):
                vector = v
            }
            processed += 1

            let outcome = Self.run(vector)
            let divergence = Self.knownDivergences[name]

            // Compare category, then the released-plaintext hash where CCTV gives one.
            var categoryOK = outcome.category == vector.expect
            var usedAlias = false
            if !categoryOK, vector.expect == .headerFailure, outcome.category == .noMatch,
               let types = outcome.stanzaTypes, !types.isDisjoint(with: outcome.handledTypes) {
                categoryOK = true
                usedAlias = true
            }
            var hashOK = true
            if categoryOK, outcome.category == vector.expect,
               vector.expect == .success || vector.expect == .payloadFailure {
                hashOK = outcome.releasedHash == vector.payloadHash?.lowercased()
            }
            let passes = categoryOK && hashOK

            if passes {
                if usedAlias { aliased.append("\(name): \(outcome.detail)") }
                if divergence != nil {
                    failures.append("\(name): listed in knownDivergences but now passes; remove the entry")
                }
                continue
            }

            let summary: String
            if !categoryOK {
                summary = "expected \(vector.expect.rawValue), got \(outcome.category.rawValue) (\(outcome.detail))"
            } else {
                let wanted = vector.payloadHash ?? "(none)"
                summary = "\(outcome.category.rawValue) as expected, but released plaintext SHA-256 "
                    + "\(outcome.releasedHash) != payload \(wanted)"
            }

            if let d = divergence {
                let covered = d.hashOnly
                    ? (categoryOK && !hashOK && outcome.category == d.actual)
                    : (!categoryOK && outcome.category == d.actual)
                if covered {
                    waived.append("\(name): \(summary)")
                    continue
                }
                let expectedText = d.hashOnly ? d.actual.rawValue + ", hash only" : d.actual.rawValue
                failures.append("\(name): \(summary) [knownDivergences expects \(expectedText), "
                    + "so this is a different failure]")
            } else {
                failures.append("\(name): \(summary)")
            }
        }

        for name in Self.knownDivergences.keys.sorted() where !seen.contains(name) {
            failures.append("\(name): listed in knownDivergences but no such vector in Testkit/")
        }

        if !aliased.isEmpty {
            print("CCTV: \(aliased.count) vector(s) passed via the no match -> header failure alias:\n  "
                + aliased.joined(separator: "\n  "))
        }
        if !waived.isEmpty {
            print("CCTV: \(waived.count) vector(s) waived by knownDivergences:\n  "
                + waived.joined(separator: "\n  "))
        }

        XCTAssertEqual(processed + skipped.count, Self.expectedVectorCount,
                       "vector files found in Testkit/ (\(processed) run, \(skipped.count) skipped)")
        let unexpectedSkips = skipped.filter { entry in
            !Self.expectedSkipped.contains(where: { entry.hasPrefix($0 + " ") })
        }
        XCTAssertTrue(unexpectedSkips.isEmpty,
                      "skipped vectors (unknown header keys):\n  " + unexpectedSkips.joined(separator: "\n  "))
        XCTAssertTrue(failures.isEmpty,
                      "CCTV testkit: \(failures.count) of \(processed) vectors don't match:\n  "
                      + failures.joined(separator: "\n  "))
    }

    // MARK: - Vector file parsing

    /// Header of `key: value` lines, a blank line, then the age file.
    static func parse(name: String, raw: Data) -> ParsedFile {
        let separator = Data([0x0A, 0x0A])
        guard let sep = raw.range(of: separator) else { return .skipped("no blank line after header") }
        let headerText = String(decoding: raw[raw.startIndex..<sep.lowerBound], as: UTF8.self)
        let body = Data(raw[sep.upperBound...])

        var expect: Category?
        var payload: String?
        var identities: [String] = []
        var passphrases: [String] = []
        var armored = false
        var compressed = false

        for line in headerText.split(separator: "\n", omittingEmptySubsequences: false) {
            guard let colon = line.range(of: ": ") else { return .skipped("header line without ': '") }
            let key = String(line[line.startIndex..<colon.lowerBound])
            let value = String(line[colon.upperBound...])
            switch key {
            case "expect":
                guard let c = Category(rawValue: value), c != .unexpected else {
                    return .skipped("unknown expect value \(value)")
                }
                expect = c
            case "payload": payload = value
            case "identity": identities.append(value)
            case "passphrase": passphrases.append(value)
            case "armored":
                guard value == "yes" else { return .skipped("armored: \(value)") }
                armored = true
            case "compressed":
                guard value == "zlib" else { return .skipped("compressed: \(value)") }
                compressed = true
            case "file key", "comment":
                break
            default:
                return .skipped("unknown key \(key)")
            }
        }
        guard let expect else { return .skipped("no expect key") }
        return .vector(Vector(name: name, expect: expect, payloadHash: payload,
                              identities: identities, passphrases: passphrases,
                              armored: armored, compressed: compressed, body: body))
    }

    // MARK: - Running one vector

    static func run(_ v: Vector) -> Outcome {
        // Identities: X25519, hybrid, then one scrypt identity per passphrase, all tried.
        var identities: [AgeIdentity] = []
        var handled: Set<String> = []
        do {
            for s in v.identities {
                if s.uppercased().hasPrefix("AGE-SECRET-KEY-PQ-1") {
                    identities.append(try HybridIdentity(ageIdentity: s))
                    handled.insert("mlkem768x25519")
                } else {
                    identities.append(try X25519Identity(ageIdentity: s))
                    handled.insert("X25519")
                }
            }
        } catch {
            let message = RunnerError.badIdentity(String(describing: error)).description
            return Outcome(category: .unexpected, detail: message,
                           releasedHash: hex(Data()), stanzaTypes: nil, handledTypes: handled)
        }
        for p in v.passphrases {
            // Default cap, as the app's FileEncryptor builds it.
            identities.append(ScryptIdentity(passphrase: p))
            handled.insert("scrypt")
        }

        var file = v.body
        if v.compressed {
            do {
                file = try inflateZlib(file)
            } catch {
                return Outcome(category: .unexpected, detail: "\(error)",
                               releasedHash: hex(Data()), stanzaTypes: nil, handledTypes: handled)
            }
        }

        var released = Data()
        var category = Category.success
        var detail = "decrypted to EOF"
        do {
            if v.armored {
                file = try AgeArmor.decode(String(decoding: file, as: UTF8.self))
            }
            let input = InputStream(data: file)
            let output = OutputStream.toMemory()
            output.open()
            defer { input.close() }
            do {
                try Age.decryptStream(ciphertext: input, identities: identities, into: output)
            } catch {
                released = memoryData(output)
                output.close()
                throw error
            }
            released = memoryData(output)
            output.close()
        } catch {
            (category, detail) = Self.category(for: error)
        }

        var stanzaTypes: Set<String>?
        if category == .noMatch, let header = try? Age.parseHeader(ciphertext: file) {
            stanzaTypes = Set(header.stanzas.map(\.type))
        }
        return Outcome(category: category, detail: detail, releasedHash: hex(released),
                       stanzaTypes: stanzaTypes, handledTypes: handled)
    }

    /// The one place AgePony errors become CCTV categories. See the table at the top.
    static func category(for error: Error) -> (Category, String) {
        switch error {
        case let e as AgeArmorError:
            return (.armorFailure, "AgeArmorError.\(e)")
        case let e as AgeError:
            switch e {
            case .headerError(.invalidMAC):
                return (.hmacFailure, "AgeError.\(e)")
            case .headerError:
                return (.headerFailure, "AgeError.\(e)")
            case .payloadError(.missingNoncePrefix):
                return (.headerFailure, "AgeError.\(e) (alias: nonce counts as header)")
            case .payloadError(.streamReadFailed), .payloadError(.streamWriteFailed):
                return (.unexpected, "AgeError.\(e) (runner stream problem)")
            case .payloadError:
                return (.payloadFailure, "AgeError.\(e)")
            case .noMatchingIdentity, .wrongPassphrase:
                return (.noMatch, "AgeError.\(e)")
            case .scryptNotAlone, .invalidFileKeyLength, .truncatedFile:
                return (.headerFailure, "AgeError.\(e)")
            default:
                return (.unexpected, "AgeError.\(e)")
            }
        case let e as ScryptStanzaError where e == .invalidWorkFactor:
            return (.headerFailure, "ScryptStanzaError.\(e)")
        default:
            return (.unexpected, "\(type(of: error)).\(error)")
        }
    }

    // MARK: - Helpers

    static func memoryData(_ stream: OutputStream) -> Data {
        stream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
    }

    static func hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Inflate a zlib stream (RFC 1950). Apple's `.zlib` algorithm is raw DEFLATE
    /// (RFC 1951), so the 2-byte zlib header and 4-byte Adler-32 trailer are stripped
    /// here and the trailer is checked against the output.
    static func inflateZlib(_ data: Data) throws -> Data {
        let bytes = [UInt8](data)
        guard bytes.count >= 6 else { throw RunnerError.badZlib("too short") }
        let cmf = bytes[0], flg = bytes[1]
        guard cmf & 0x0F == 8, (UInt16(cmf) << 8 | UInt16(flg)) % 31 == 0, flg & 0x20 == 0 else {
            throw RunnerError.badZlib("unsupported header \(cmf) \(flg)")
        }
        let deflate = Data(bytes[2..<(bytes.count - 4)])
        let out: Data
        do {
            out = try (deflate as NSData).decompressed(using: .zlib) as Data
        } catch {
            throw RunnerError.badZlib("\(error)")
        }
        let t = bytes[(bytes.count - 4)...]
        let expected = t.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard adler32(out) == expected else { throw RunnerError.badZlib("Adler-32 mismatch") }
        return out
    }

    static func adler32(_ data: Data) -> UInt32 {
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> UInt32 in
            var a: UInt32 = 1
            var b: UInt32 = 0
            var i = 0
            let n = raw.count
            while i < n {
                // 5552 is the largest block that can't overflow UInt32 before the modulo.
                let end = min(i + 5552, n)
                while i < end {
                    a &+= UInt32(raw[i])
                    b &+= a
                    i += 1
                }
                a %= 65521
                b %= 65521
            }
            return b << 16 | a
        }
    }
}
