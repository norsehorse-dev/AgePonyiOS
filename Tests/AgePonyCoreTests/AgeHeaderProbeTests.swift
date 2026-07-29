//
//  AgeHeaderProbeTests.swift
//  AgePonyCoreTests
//
//  The header-only probe answers "what is this encrypted to, and can I open it?"
//  without decrypting. Two things matter: it must be correct, and it must stop at the
//  header — a probe that quietly read the whole payload would defeat its own purpose
//  on a large file.
//

import XCTest
@testable import AgePonyCore

final class AgeHeaderProbeTests: XCTestCase {

    private func stream(_ data: Data) -> InputStream {
        let s = InputStream(data: data)
        s.open()
        return s
    }

    // MARK: - Recipient types are visible without decrypting

    func testParseHeaderRevealsRecipientCount() throws {
        let a = X25519Identity.generate()
        let b = X25519Identity.generate()
        let ciphertext = try Age.encrypt(
            plaintext: Data("hello".utf8),
            to: [try X25519Recipient(publicKey: a.publicKey),
                 try X25519Recipient(publicKey: b.publicKey)]
        )

        let header = try Age.parseHeader(ciphertext: ciphertext)
        XCTAssertEqual(header.stanzas.count, 2)
        XCTAssertTrue(header.stanzas.allSatisfy { $0.type == "X25519" })
    }

    func testParseHeaderIdentifiesPassphraseFile() throws {
        let ciphertext = try Age.encrypt(
            plaintext: Data("hello".utf8),
            passphrase: "correct horse",
            workFactor: 10
        )
        let header = try Age.parseHeader(ciphertext: ciphertext)
        XCTAssertEqual(header.stanzas.count, 1)
        XCTAssertEqual(header.stanzas[0].type, "scrypt")
        // The work factor is the second stanza argument, and is what lets a reader warn
        // about the memory a decrypt will cost before attempting it.
        XCTAssertEqual(header.stanzas[0].args.count, 2)
        XCTAssertEqual(header.stanzas[0].args[1], "10")
    }

    func testParseHeaderIdentifiesPostQuantumFile() throws {
        let identity = try HybridIdentity.generate()
        let ciphertext = try Age.encrypt(
            plaintext: Data("hello".utf8),
            to: [try identity.recipient()]
        )
        let header = try Age.parseHeader(ciphertext: ciphertext)
        XCTAssertEqual(header.stanzas.count, 1)
        XCTAssertEqual(header.stanzas[0].type, "mlkem768x25519")
    }

    // MARK: - canDecrypt

    func testCanDecryptTrueForOwnKey() throws {
        let identity = X25519Identity.generate()
        let ciphertext = try Age.encrypt(
            plaintext: Data("hello".utf8),
            to: [try X25519Recipient(publicKey: identity.publicKey)]
        )
        XCTAssertTrue(try Age.canDecrypt(ciphertext: ciphertext, identities: [identity]))
        XCTAssertTrue(try Age.canDecryptStream(ciphertext: stream(ciphertext), identities: [identity]))
    }

    func testCanDecryptFalseForStranger() throws {
        let mine = X25519Identity.generate()
        let theirs = X25519Identity.generate()
        let ciphertext = try Age.encrypt(
            plaintext: Data("hello".utf8),
            to: [try X25519Recipient(publicKey: theirs.publicKey)]
        )
        XCTAssertFalse(try Age.canDecrypt(ciphertext: ciphertext, identities: [mine]))
        XCTAssertFalse(try Age.canDecryptStream(ciphertext: stream(ciphertext), identities: [mine]))
    }

    func testCanDecryptFalseForNoIdentities() throws {
        let identity = X25519Identity.generate()
        let ciphertext = try Age.encrypt(
            plaintext: Data("hello".utf8),
            to: [try X25519Recipient(publicKey: identity.publicKey)]
        )
        XCTAssertFalse(try Age.canDecrypt(ciphertext: ciphertext, identities: []))
    }

    func testCanDecryptFindsOneMatchAmongMany() throws {
        let mine = X25519Identity.generate()
        let theirs = X25519Identity.generate()
        let ciphertext = try Age.encrypt(
            plaintext: Data("hello".utf8),
            to: [try X25519Recipient(publicKey: theirs.publicKey),
                 try X25519Recipient(publicKey: mine.publicKey)]
        )
        XCTAssertTrue(try Age.canDecryptStream(
            ciphertext: stream(ciphertext),
            identities: [X25519Identity.generate(), mine]
        ))
    }

    // MARK: - The probe stops at the header

    /// The header sits at the front and is bounded, so probing a large file must read
    /// only a small prefix. This is the property that makes the inspector instant on a
    /// file of any size; if it regressed, nothing would break except performance, which
    /// is exactly the kind of regression that goes unnoticed.
    func testProbeReadsOnlyTheHeaderOfALargeFile() throws {
        let identity = X25519Identity.generate()
        let ciphertext = try Age.encrypt(
            plaintext: Data(repeating: 0x11, count: 2_000_000),
            to: [try X25519Recipient(publicKey: identity.publicKey)]
        )
        XCTAssertGreaterThan(ciphertext.count, 1_000_000)

        let source = stream(ciphertext)
        _ = try Age.parseHeaderStream(ciphertext: source)

        // Whatever is left must still be the payload: draining it should yield close to
        // the full file, i.e. the probe consumed only a header-sized prefix.
        var remaining = 0
        var buf = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = source.read(&buf, maxLength: buf.count)
            if n <= 0 { break }
            remaining += n
        }
        let consumed = ciphertext.count - remaining
        XCTAssertLessThan(consumed, 4096, "probe consumed \(consumed) bytes; it should stop at the header")
    }

    /// After probing, the stream is positioned exactly at the first payload byte — which
    /// is what lets a caller probe and then continue straight into a streaming decrypt.
    func testStreamIsPositionedForPayloadAfterProbe() throws {
        let identity = X25519Identity.generate()
        let plaintext = Data(repeating: 0x7E, count: 200_000)
        let ciphertext = try Age.encrypt(
            plaintext: plaintext,
            to: [try X25519Recipient(publicKey: identity.publicKey)]
        )

        let source = stream(ciphertext)
        let header = try Age.parseHeaderStream(ciphertext: source)
        XCTAssertEqual(header.stanzas.count, 1)

        // Recover the file key from the header, then decrypt the payload the probe left.
        var fileKey: Data?
        for stanza in header.stanzas {
            if let key = try identity.unwrap(stanza: stanza) { fileKey = key; break }
        }
        let key = try XCTUnwrap(fileKey)

        let out = OutputStream.toMemory()
        out.open()
        try AgePayload.decryptStream(source: source, fileKey: key, into: out)
        out.close()
        let recovered = out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()

        XCTAssertEqual(recovered, plaintext)
    }

    // MARK: - Non-age input

    func testProbeRejectsNonAgeInput() {
        XCTAssertThrowsError(try Age.parseHeader(ciphertext: Data("not an age file at all".utf8)))
        XCTAssertThrowsError(
            try Age.parseHeaderStream(ciphertext: stream(Data(repeating: 0xAB, count: 4096)))
        )
    }
}
