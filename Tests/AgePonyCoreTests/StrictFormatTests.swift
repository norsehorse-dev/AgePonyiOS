//
//  StrictFormatTests.swift
//  AgePonyCoreTests
//
//  Hand-built negative vectors in the style of the C2SP age CCTV testkit (audit L-1,
//  L-2, L-3, L-5, L-14 and the empty-final-chunk finding), ported from Android's
//  StrictFormatTests. Every malformed file must be refused by both the whole-buffer and
//  the streaming decrypt. When the reference `age` binary is installed, each vector is
//  also fed to it, to prove AgePony is never stricter than Go age, and every positive
//  control is checked to open there too.
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

/// The reference Go `age` binary, when installed. Calls return nil when it isn't.
enum GoAge {
    static let path: String? = ["/opt/homebrew/bin/age", "/usr/local/bin/age", "/usr/bin/age"]
        .first { FileManager.default.isExecutableFile(atPath: $0) }

    /// Plaintext from Go age, or nil if Go refused the file (or isn't installed).
    static func decrypt(_ ct: Data, identity: String) -> Data? {
        guard let path else { return nil }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("agepony-go-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = dir.appendingPathComponent("key"), input = dir.appendingPathComponent("in"), output = dir.appendingPathComponent("out")
        try? Data((identity + "\n").utf8).write(to: key)
        try? ct.write(to: input)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = ["-d", "-i", key.path, "-o", output.path, input.path]
        p.standardOutput = Pipe(); p.standardError = Pipe()
        guard (try? p.run()) != nil else { return nil }
        p.waitUntilExit()
        return p.terminationStatus == 0 ? (try? Data(contentsOf: output)) : nil
    }
}

final class StrictFormatTests: XCTestCase {

    let id = X25519Identity.generate()
    lazy var recipient = try! X25519Recipient(ageRecipient: id.ageRecipient)
    let plaintext = Data("strict parsing".utf8)

    func fileKey() -> Data { Data((0..<16).map { _ in UInt8.random(in: 0...255) }) }

    /// Header text up to and including "---", with a correct MAC, then `payload`.
    func craft(_ key: Data, _ headerNoMAC: String, payload: Data? = nil, macLine: ((String) -> String)? = nil) throws -> Data {
        let macInput = Data(headerNoMAC.utf8)
        let macKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: key), salt: Data(), info: Data("header".utf8), outputByteCount: 32)
        let mac = Stanza.base64NoPad(Data(HMAC<SHA256>.authenticationCode(for: macInput, using: macKey)))
        var out = macInput
        out.append(Data((" " + (macLine?(mac) ?? mac) + "\n").utf8))
        out.append(try payload ?? AgePayload.encrypt(plaintext: plaintext, fileKey: key))
        return out
    }

    func v1(_ parts: String...) -> String { "age-encryption.org/v1\n" + parts.joined() }

    /// A stanza in wire form with its trailing newline.
    func wire(_ s: Stanza) -> String { s.serialize() + "\n" }

    func decryptWhole(_ ct: Data, _ ids: [AgeIdentity]? = nil) throws -> Data {
        try Age.decrypt(ciphertext: ct, identities: ids ?? [id])
    }

    func decryptStreamed(_ ct: Data, _ ids: [AgeIdentity]? = nil) throws -> Data {
        let out = OutputStream.toMemory()
        out.open()
        try Age.decryptStream(ciphertext: InputStream(data: ct), identities: ids ?? [id], into: out)
        return out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
    }

    func rejects(_ ct: Data, _ what: String, goToo: Bool = true, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try decryptWhole(ct), "whole-buffer accepted: \(what)", file: file, line: line)
        XCTAssertThrowsError(try decryptStreamed(ct), "streaming accepted: \(what)", file: file, line: line)
        if goToo, GoAge.path != nil {
            XCTAssertNil(GoAge.decrypt(ct, identity: id.ageIdentityString), "Go age accepted: \(what)", file: file, line: line)
        }
    }

    func opens(_ ct: Data, _ expected: Data? = nil, file: StaticString = #filePath, line: UInt = #line) {
        let want = expected ?? plaintext
        XCTAssertEqual(try decryptWhole(ct), want, file: file, line: line)
        XCTAssertEqual(try decryptStreamed(ct), want, file: file, line: line)
        if GoAge.path != nil {
            XCTAssertEqual(GoAge.decrypt(ct, identity: id.ageIdentityString), want, "Go age output differs", file: file, line: line)
        }
    }

    /// Same top bits, different unused low bits.
    func flipTrailingBits(_ b64: String) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        let last = alphabet.firstIndex(of: b64.last!)!
        return String(b64.dropLast()) + String(alphabet[last ^ 1])
    }

    // MARK: - Positive controls

    func test_craftedCanonicalHeaderOpens() throws {
        let key = fileKey()
        opens(try craft(key, v1(wire(try recipient.wrap(fileKey: key)), "---")))
    }

    func test_serializerOutput_isAcceptedHereAndByGo() throws {
        // Unknown stanzas of every body-length shape ride along with the real recipient.
        // Go re-serializes the header to check the MAC, so Go opening these proves the
        // byte format matches.
        for n in [0, 1, 2, 3, 47, 48, 49, 95, 96, 97, 150] {
            let key = fileKey()
            let body = Data((0..<n).map { _ in UInt8.random(in: 0...255) })
            let grease = Stanza(type: "grease-test", args: ["a", "b~!"], body: body)
            let ct = try craft(key, v1(wire(try recipient.wrap(fileKey: key)), wire(grease), "---"))
            let parsed = try Age.parseHeader(ciphertext: ct)
            XCTAssertEqual(parsed.stanzas.count, 2)
            XCTAssertEqual(parsed.stanzas[1].body, body, "body of \(n) bytes")
            opens(ct)
        }
    }

    // MARK: - L-1: header and stanza encoding

    func test_rejectsNonCanonicalMACTrailingBits() throws {
        let ct = try Age.encrypt(plaintext: plaintext, to: [recipient])
        var s = Array(ct)
        let marker = Array("\n--- ".utf8)
        let at = (0...(s.count - marker.count)).first { Array(s[$0..<($0 + marker.count)]) == marker }! + 5
        let mac = String(decoding: s[at..<(at + 43)], as: UTF8.self)
        s.replaceSubrange(at..<(at + 43), with: Array(flipTrailingBits(mac).utf8))
        rejects(Data(s), "MAC with non-zero trailing bits")
    }

    func test_rejectsPaddedMACAndMACLineJunk() throws {
        let key = fileKey()
        let h = v1(wire(try recipient.wrap(fileKey: key)), "---")
        rejects(try craft(key, h, macLine: { $0 + "=" }), "padded MAC")
        rejects(try craft(key, h, macLine: { $0 + " " }), "MAC with trailing space")
        rejects(try craft(key, h, macLine: { $0 + "\r" }), "MAC with CR")
        rejects(try craft(key, h, macLine: { String($0.dropLast()) }), "short MAC")
        rejects(try craft(key, h, macLine: { " " + $0 }), "MAC after two spaces")
    }

    func test_rejectsNonCanonicalBodyEncodings() throws {
        let key = fileKey()
        let st = try recipient.wrap(fileKey: key)
        let b64 = Stanza.base64NoPad(st.body)
        let arg = st.args[0]
        rejects(try craft(key, v1("-> X25519 \(arg)\n", flipTrailingBits(b64), "\n---")), "body trailing bits")
        rejects(try craft(key, v1("-> X25519 \(arg)\n", b64 + "=", "\n---")), "padded body")
        // A non-canonical argument parses (arguments are opaque to the header grammar) but
        // the X25519 identity refuses it, as Go's does.
        rejects(try craft(key, v1("-> X25519 \(flipTrailingBits(arg))\n", b64, "\n---")), "arg trailing bits")
    }

    func test_rejectsBadBodyLineLengths() throws {
        let key = fileKey()
        let real = wire(try recipient.wrap(fileKey: key))
        let b64 = Stanza.base64NoPad(Data((0..<60).map { _ in UInt8.random(in: 0...255) })) // 80 chars
        let p64 = String(b64.prefix(64)), r64 = String(b64.dropFirst(64))
        opens(try craft(key, v1(real, "-> grease\n", p64, "\n", r64, "\n---")))
        rejects(try craft(key, v1(real, "-> grease\n", String(b64.prefix(60)), "\n", String(b64.dropFirst(60)), "\n---")), "60-column wrap")
        rejects(try craft(key, v1(real, "-> grease\n", b64, "\n---")), "80-column line")

        let full = Stanza.base64NoPad(Data((0..<48).map { _ in UInt8.random(in: 0...255) }))
        opens(try craft(key, v1(real, "-> grease\n", full, "\n\n---")))
        rejects(try craft(key, v1(real, "-> grease\n", full, "\n---")), "full line without terminator")
        rejects(try craft(key, v1("-> grease\n", full, "\n", real, "---")), "full line straight into next stanza")
        opens(try craft(key, v1(real, "-> grease\n\n---")))
        rejects(try craft(key, v1(real, "-> grease\n---")), "no body line at all")
    }

    func test_rejectsStrayLinesAndBadStanzaLines() throws {
        let key = fileKey()
        let st = try recipient.wrap(fileKey: key)
        let real = wire(st)
        let bodyLine = Stanza.base64NoPad(st.body)
        let arg = st.args[0]
        rejects(try craft(key, v1(real, "\n---")), "blank line before MAC")
        rejects(try craft(key, v1("\n", real, "---")), "blank line after version")
        rejects(try craft(key, v1("-> X25519  \(arg)\n\(bodyLine)\n---")), "double space")
        rejects(try craft(key, v1("-> X25519 \(arg) \n\(bodyLine)\n---")), "trailing space")
        rejects(try craft(key, v1(real, "-> grease a\tb\n\n---")), "tab in argument")
        rejects(try craft(key, v1(real, "-> grease café\n\n---")), "non-ASCII argument")
        rejects(try craft(key, v1(real, "-> grease \u{7f}\n\n---")), "DEL in argument")
        rejects(try craft(key, v1(real, "->\n\n---")), "stanza with no type")
        rejects(try craft(key, "age-encryption.org/v1\r\n\(real)---"), "CRLF version line")
        rejects(try craft(key, v1(real.replacingOccurrences(of: "\n", with: "\r\n"), "---")), "CRLF stanza")
        rejects(try craft(key, "age-encryption.org/v2\n\(real)---"), "wrong version")
    }

    // MARK: - L-2: scrypt must be alone

    final class Watching: AgeIdentity {
        var sawScrypt = false
        func unwrap(stanza: Stanza) throws -> Data? {
            if stanza.type == "scrypt" { sawScrypt = true }
            return nil
        }
    }

    func test_rejectsScryptMixedWithAnotherStanza_beforeAnyKDF() throws {
        let key = fileKey()
        // The second scrypt stanza claims work factor 22: running the KDF on it is the attack.
        let cheap = try ScryptRecipient(passphrase: "pw", workFactor: 10).wrap(fileKey: key)
        let costly = Stanza(type: "scrypt", args: [cheap.args[0], "22"], body: cheap.body)
        let watching = Watching()
        for header in [v1(wire(try recipient.wrap(fileKey: key)), wire(costly), "---"),
                       v1(wire(cheap), wire(costly), "---"),
                       v1(wire(costly), wire(try recipient.wrap(fileKey: key)), "---")] {
            let ct = try craft(key, header)
            let ids: [AgeIdentity] = [watching, ScryptIdentity(passphrase: "pw")]
            XCTAssertThrowsError(try decryptWhole(ct, ids)) { XCTAssertEqual($0 as? AgeError, .scryptNotAlone) }
            XCTAssertThrowsError(try decryptStreamed(ct, ids)) { XCTAssertEqual($0 as? AgeError, .scryptNotAlone) }
            XCTAssertThrowsError(try Age.canDecryptStream(ciphertext: InputStream(data: ct), identities: ids))
            XCTAssertThrowsError(try Age.decryptAndRecoverSignature(ciphertext: ct, identities: ids))
            XCTAssertFalse(watching.sawScrypt, "an identity was shown a stanza of a mixed scrypt header")
        }
        // Go age puts this check in the scrypt identity, so an X25519 key still opens a
        // mixed file (no KDF runs). AgePony matches that.
        opens(try craft(key, v1(wire(try recipient.wrap(fileKey: key)), wire(costly), "---")))
        let alone = try Age.encrypt(plaintext: plaintext, to: [ScryptRecipient(passphrase: "pw", workFactor: 10)])
        XCTAssertEqual(try Age.decrypt(ciphertext: alone, passphrase: "pw"), plaintext)
    }

    // MARK: - L-5: wrapped file-key sizes

    func test_rejectsWrongWrappedBodySizes() throws {
        let key = fileKey()
        let st = try recipient.wrap(fileKey: key)
        for body in [st.body + Data([0]), st.body.prefix(31), Data()] {
            let bad = Stanza(type: st.type, args: st.args, body: Data(body))
            XCTAssertNil(try id.unwrap(stanza: bad))
            rejects(try craft(key, v1(wire(bad), "---")), "X25519 body of \(body.count) bytes")
        }
        let sc = try ScryptRecipient(passphrase: "pw", workFactor: 10).wrap(fileKey: key)
        XCTAssertNil(try ScryptIdentity(passphrase: "pw").unwrap(stanza: Stanza(type: sc.type, args: sc.args, body: sc.body + Data([0]))))
    }

    struct Odd: AgeIdentity {
        func unwrap(stanza: Stanza) throws -> Data? { Data(count: 15) }
    }

    func test_rejectsAnUnwrappedFileKeyThatIsNot16Bytes() throws {
        let key = fileKey()
        let ct = try craft(key, v1(wire(Stanza(type: "custom", args: ["x"], body: Data(count: 4))), "---"))
        XCTAssertThrowsError(try decryptWhole(ct, [Odd()])) { XCTAssertEqual($0 as? AgeError, .invalidFileKeyLength(15)) }
        XCTAssertThrowsError(try decryptStreamed(ct, [Odd()])) { XCTAssertEqual($0 as? AgeError, .invalidFileKeyLength(15)) }
    }

    // MARK: - Low-order X25519 (L-14)

    func test_lowOrderEphemeralShare_isNotForUs() throws {
        let key = fileKey()
        let st = try recipient.wrap(fileKey: key)
        var one = Data(count: 32); one[0] = 1
        for u in [Data(count: 32), one] {
            let bad = Stanza(type: "X25519", args: [Stanza.base64NoPad(u)], body: st.body)
            XCTAssertNil(try id.unwrap(stanza: bad))
            rejects(try craft(key, v1(wire(bad), "---")), "low-order share", goToo: false)
        }
    }

    func test_refusesToEncryptToALowOrderRecipient() throws {
        XCTAssertThrowsError(try X25519Recipient(publicKey: Data(count: 32)).wrap(fileKey: fileKey())) {
            XCTAssertEqual($0 as? X25519Error, .lowOrderPublicKey)
        }
    }

    // MARK: - L-3: header size cap

    func test_headerCap() throws {
        let big = Data(repeating: UInt8(ascii: "A"), count: AgeHeaderConstants.maxHeaderSize + 10)
        XCTAssertThrowsError(try AgeHeader.parse(bytes: big))
        XCTAssertThrowsError(try Age.parseHeaderStream(ciphertext: InputStream(data: big)))

        var endless = Data("age-encryption.org/v1\n".utf8)
        while endless.count < AgeHeaderConstants.maxHeaderSize + 100 { endless.append(Data("-> grease\nAAAA\n".utf8)) }
        XCTAssertThrowsError(try decryptStreamed(endless))
    }

    func test_headerJustUnderTheCap_stillOpens() throws {
        let key = fileKey()
        let real = wire(try recipient.wrap(fileKey: key))
        var filler = ""
        while filler.utf8.count + 11 < 900 * 1024 { filler += "-> grease\n\n" }
        opens(try craft(key, v1(real, filler, "---")))
    }

    // MARK: - STREAM payload

    func chunk(_ key: SymmetricKey, _ counter: UInt64, last: Bool, _ pt: Data) throws -> Data {
        let box = try ChaChaPoly.seal(pt, using: key, nonce: try AgePayload.chunkNonce(counter: counter, last: last))
        return box.ciphertext + box.tag
    }

    func test_rejectsAnEmptyFinalChunkAfterAFullOne() throws {
        let key = fileKey()
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let pk = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: key), salt: nonce, info: Data("payload".utf8), outputByteCount: 32)
        let full = Data((0..<AgePayload.chunkSize).map { _ in UInt8.random(in: 0...255) })
        let payload = nonce + (try chunk(pk, 0, last: false, full)) + (try chunk(pk, 1, last: true, Data()))
        XCTAssertThrowsError(try AgePayload.decrypt(bytes: payload, fileKey: key)) {
            XCTAssertEqual($0 as? AgePayloadError, .emptyFinalChunk)
        }
        rejects(try craft(key, v1(wire(try recipient.wrap(fileKey: key)), "---"), payload: payload), "empty final chunk")
        let canonical = nonce + (try chunk(pk, 0, last: true, full))
        opens(try craft(key, v1(wire(try recipient.wrap(fileKey: key)), "---"), payload: canonical), full)
    }

    func test_exactChunkMultiples_neverEmitAnEmptyFinalChunk() throws {
        for n in [AgePayload.chunkSize, 2 * AgePayload.chunkSize] {
            let pt = Data((0..<n).map { _ in UInt8.random(in: 0...255) })
            let file = try Age.encrypt(plaintext: pt, to: [recipient])
            opens(file, pt)
            let sink = OutputStream.toMemory()
            sink.open()
            try Age.encryptStream(plaintext: InputStream(data: pt), to: [recipient], into: sink)
            opens(sink.property(forKey: .dataWrittenToMemoryStreamKey) as! Data, pt)
        }
    }

    func test_rejectsTrailingDataAndTruncation() throws {
        let pt = Data((0..<(2 * AgePayload.chunkSize)).map { _ in UInt8.random(in: 0...255) })
        let ct = try Age.encrypt(plaintext: pt, to: [recipient])
        rejects(ct + Data([0]), "one trailing byte")
        rejects(ct + Data(count: 16), "trailing tag-sized block")
        let (_, start) = try AgeHeader.parse(bytes: ct)
        rejects(ct.prefix(start + 16 + AgePayload.chunkSize + 16), "truncated at the first chunk boundary")
        rejects(ct.prefix(start + 16), "nonce only")
        rejects(ct.prefix(ct.count - 1), "last byte missing")
    }

    // MARK: - Armor (Go's line rules, bounded line reads)

    func armorRejects(_ text: String, _ what: String, goToo: Bool = true, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try AgeArmor.decode(text), "decode accepted: \(what)", file: file, line: line)
        XCTAssertThrowsError(try AgeArmor.decodeStream(armored: InputStream(data: Data(text.utf8)), into: { let o = OutputStream.toMemory(); o.open(); return o }()),
                             "stream accepted: \(what)", file: file, line: line)
        if goToo, GoAge.path != nil {
            XCTAssertNil(GoAge.decrypt(Data(text.utf8), identity: id.ageIdentityString), "Go age accepted: \(what)", file: file, line: line)
        }
    }

    func armorOpens(_ text: String, _ expected: Data, goToo: Bool = true, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(try Age.decrypt(ciphertext: try AgeArmor.decode(text), identities: [id]), expected, file: file, line: line)
        let out = OutputStream.toMemory()
        out.open()
        XCTAssertNoThrow(try Age.decryptStream(ciphertext: ArmorDecodingSource(InputStream(data: Data(text.utf8))), identities: [id], into: out),
                         file: file, line: line)
        XCTAssertEqual(out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data, expected, file: file, line: line)
        if goToo, GoAge.path != nil {
            XCTAssertEqual(GoAge.decrypt(Data(text.utf8), identity: id.ageIdentityString), expected, file: file, line: line)
        }
    }

    func armoredLines(_ ct: Data) -> [String] {
        Array(AgeArmor.encode(ct).split(separator: "\n").map(String.init).dropFirst().dropLast())
    }

    func join(_ body: [String]) -> String { AgeArmor.beginMarker + "\n" + body.joined(separator: "\n") + "\n" + AgeArmor.endMarker + "\n" }

    func chunked(_ s: String, _ n: Int) -> [String] {
        let c = Array(s)
        return stride(from: 0, to: c.count, by: n).map { String(c[$0..<min($0 + n, c.count)]) }
    }

    func test_armorFollowsGoLineRules() throws {
        let ct = try Age.encrypt(plaintext: Data((0..<300).map { _ in UInt8.random(in: 0...255) }), to: [recipient])
        let pt = try Age.decrypt(ciphertext: ct, identities: [id])
        let lines = armoredLines(ct)

        armorOpens(join(lines), pt)
        armorOpens(join(lines).replacingOccurrences(of: "\n", with: "\r\n"), pt)
        // age 1.1.1 refuses blank lines before BEGIN (newer age accepts them); AgePony
        // may be more lenient than Go, never stricter.
        armorOpens("\n \n" + join(lines) + "\n\n", pt, goToo: false)
        armorOpens(join(lines).replacingOccurrences(of: "\n", with: " \t\n"), pt, goToo: false)

        let flat = lines.joined()
        armorRejects(join(chunked(flat, 76)), "76-column lines")
        armorRejects(join(chunked(flat, 60)), "60-column lines")
        armorRejects(join(Array(lines.prefix(2)) + [""] + Array(lines.dropFirst(2))), "blank line inside the body")
        let last = lines.last!
        let unpadded = String(last.reversed().drop(while: { $0 == "=" }).reversed())
        if unpadded != last { armorRejects(join(Array(lines.dropLast()) + [unpadded]), "missing padding") }
        armorRejects(join(Array(lines.dropLast()) + [last + "=="]), "extra padding")
        armorRejects(join(lines) + "junk\n", "junk after END")
        armorRejects(join(lines).replacingOccurrences(of: AgeArmor.endMarker, with: "-----END AGE ENCRYPTED FILE"), "bad END")
        armorRejects(AgeArmor.beginMarker + "\n" + lines.joined(separator: "\n") + "\n", "missing END")
    }

    func test_armorWithAFullFinalLine() throws {
        let pt = Data((0..<40).map { _ in UInt8.random(in: 0...255) })
        let ct = try Age.encrypt(plaintext: pt, to: [recipient])
        XCTAssertEqual(ct.count % 48, 0)
        let lines = armoredLines(ct)
        XCTAssertTrue(lines.allSatisfy { $0.count == 64 })
        armorOpens(AgeArmor.encode(ct), pt)
        // age 1.1.1 accepts one blank line between a full final line and END; newer age
        // refuses it. AgePony accepts it: more lenient than Go is fine, stricter isn't.
        armorOpens(AgeArmor.beginMarker + "\n" + lines.joined(separator: "\n") + "\n\n" + AgeArmor.endMarker + "\n", pt, goToo: false)
        armorRejects(AgeArmor.beginMarker + "\n" + lines.joined(separator: "\n") + "\n\n\n" + AgeArmor.endMarker + "\n", "two blank lines before END")
    }

    func test_armorRejectsNonCanonicalFinalGroup() throws {
        var ct: Data
        repeat { ct = try Age.encrypt(plaintext: Data(count: Int.random(in: 1...64)), to: [recipient]) } while ct.count % 3 == 0
        var lines = armoredLines(ct)
        let last = lines.removeLast()
        let data = String(last.reversed().drop(while: { $0 == "=" }).reversed())
        let bad = flipTrailingBits(data) + String(last.dropFirst(data.count))
        armorRejects(join(lines + [bad]), "non-zero trailing bits in armor")
    }

    func test_armorLineReads_areBounded() {
        let text = AgeArmor.beginMarker + "\n" + String(repeating: "A", count: 100_000)
        XCTAssertThrowsError(try AgeArmor.decodeStream(armored: InputStream(data: Data(text.utf8)), into: { let o = OutputStream.toMemory(); o.open(); return o }())) {
            XCTAssertEqual($0 as? AgeArmorError, .lineTooLong)
        }
    }
}
