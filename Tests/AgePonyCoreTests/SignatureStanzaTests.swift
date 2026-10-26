//
//  SignatureStanzaTests.swift
//  AgePonyCoreTests
//
//  The `agepony.com/sig` stanza (v1 read, v2 read/write) and signed bundle v2.
//  Vectors are from the Android repo's docs/SIGNATURE_FORMATS_v2.md, so a pass here
//  means the message layout matches Android byte for byte.
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

final class SignatureStanzaTests: XCTestCase {

    // MARK: - Helpers

    private struct Signer {
        let key = Curve25519.Signing.PrivateKey()
        var publicKey: Data { key.publicKey.rawRepresentation }

        func sign(messageHash: Data, namespace: String) throws -> String {
            try SSHSigner.signEd25519(
                messageHash: messageHash,
                seed: key.rawRepresentation,
                publicKey: publicKey,
                namespace: namespace,
                hash: .sha512
            )
        }
        func sign(message: Data, namespace: String) throws -> String {
            try sign(messageHash: SSHSigHash.sha512.digest(message), namespace: namespace)
        }
    }

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private func signedFile(_ plaintext: Data, to recipients: [AgeRecipient], signer: Signer) throws -> Data {
        let enc = try SignedEncryption.prepare(to: recipients)
        let hash = enc.messageHash(plaintextSHA512: Data(SHA512.hash(data: plaintext)))
        let sig = try signer.sign(messageHash: hash, namespace: SignatureStanza.namespaceV2)
        return try enc.encrypt(plaintext: plaintext, signatureArmored: sig)
    }

    /// Rebuild `file` with a different header, keeping the payload and file key.
    private func rewrap(_ file: Data, identity: AgeIdentity, stanzas: (Data, [Stanza]) throws -> [Stanza]) throws -> Data {
        let (header, offset) = try AgeHeader.parse(bytes: file)
        var fileKey: Data?
        for s in header.stanzas { if let k = try identity.unwrap(stanza: s) { fileKey = k; break } }
        let key = try XCTUnwrap(fileKey)
        var out = AgeHeader.serialize(stanzas: try stanzas(key, header.stanzas), fileKey: key)
        out.append(file.suffix(from: file.startIndex + offset))
        return out
    }

    // MARK: - Spec vectors

    func test_v2Message_matchesSpecVector() {
        let stanzas = [
            Stanza(type: "X25519", args: ["AAAA"], body: Data((0..<32).map { UInt8($0) })),
            Stanza(type: "agepony.com/sig", args: ["v2"], body: Data(repeating: 0, count: 40)),
            Stanza(type: "mlkem768x25519", args: [], body: Data([0x7f, 0x7f, 0x7f])),
        ]
        let m = SignatureStanza.v2Message(plaintextSHA512: Data(repeating: 0x11, count: 64), headerStanzas: stanzas)
        XCTAssertEqual(hex(Data(SHA256.hash(data: m))),
                       "8c7f506293ca9e956acaa380e6ee07f3d613e56e8b181158dbc98a97ed65524f")
    }

    func test_bundleV2Message_matchesSpecVector() {
        let manifest = Data("agepony-signed/2\nname=report.pdf\n".utf8)
        XCTAssertEqual(manifest.count, 33)
        XCTAssertEqual(SignedBundle.manifestV2(originalName: "report.pdf"), manifest)
        let m = SignedBundle.v2Message(manifest: manifest, payloadSHA512: Data(repeating: 0x22, count: 64))
        XCTAssertEqual(hex(Data(SHA256.hash(data: m))),
                       "f1e944ee38ee10dac9cbf6601f0dd110e826244d8dc01aa0662104433386d0b7")
    }

    // MARK: - Stanza v2

    func test_v2_roundTrip_verifies() throws {
        let id = X25519Identity.generate()
        let signer = Signer()
        let plaintext = Data("signed for one recipient\n".utf8)
        let file = try signedFile(plaintext, to: [try X25519Recipient(ageRecipient: id.ageRecipient)], signer: signer)

        let header = try Age.parseHeader(ciphertext: file)
        XCTAssertEqual(header.stanzas.last?.type, "agepony.com/sig")
        XCTAssertEqual(header.stanzas.last?.args, ["v2"])

        let result = try Age.decryptAndRecoverSignature(ciphertext: file, identities: [id])
        XCTAssertEqual(result.plaintext, plaintext)
        let opened = try XCTUnwrap(result.signature.opened)
        XCTAssertEqual(opened.version, 2)
        XCTAssertTrue(opened.coversRecipients)
        XCTAssertEqual(opened.namespace, "agepony-sig-v2")
        let v = try opened.verify(plaintext: plaintext)
        XCTAssertEqual(v.publicKeyWire, SSHSig.ed25519PublicKeyWire(signer.publicKey))
    }

    func test_v2_multipleRecipients_eachVerifies() throws {
        let a = X25519Identity.generate(), b = X25519Identity.generate()
        let plaintext = Data(repeating: 0x5a, count: 200_000)
        let file = try signedFile(plaintext, to: [
            try X25519Recipient(ageRecipient: a.ageRecipient),
            try X25519Recipient(ageRecipient: b.ageRecipient),
        ], signer: Signer())
        for id in [a, b] {
            let r = try Age.decryptAndRecoverSignature(ciphertext: file, identities: [id])
            XCTAssertNoThrow(try XCTUnwrap(r.signature.opened).verify(plaintext: r.plaintext))
        }
    }

    func test_v2_reAddressedFile_failsVerification() throws {
        let original = X25519Identity.generate()
        let attacker = X25519Identity.generate()
        let plaintext = Data("only for the original recipient".utf8)
        let file = try signedFile(plaintext, to: [try X25519Recipient(ageRecipient: original.ageRecipient)], signer: Signer())

        // The original recipient forwards the file to someone else, keeping the sig stanza.
        let forwarded = try rewrap(file, identity: original) { key, stanzas in
            [try X25519Recipient(ageRecipient: attacker.ageRecipient).wrap(fileKey: key)]
                + stanzas.filter { $0.type == SignatureStanza.type }
        }
        let r = try Age.decryptAndRecoverSignature(ciphertext: forwarded, identities: [attacker])
        XCTAssertEqual(r.plaintext, plaintext)
        let opened = try XCTUnwrap(r.signature.opened)
        XCTAssertThrowsError(try opened.verify(plaintext: r.plaintext)) {
            XCTAssertEqual($0 as? SSHSigError, .signatureInvalid)
        }
    }

    func test_v2_relabelledAsV1_isUnreadable() throws {
        let id = X25519Identity.generate()
        let file = try signedFile(Data("x".utf8), to: [try X25519Recipient(ageRecipient: id.ageRecipient)], signer: Signer())
        let relabelled = try rewrap(file, identity: id) { _, stanzas in
            stanzas.map { $0.type == SignatureStanza.type ? Stanza(type: $0.type, args: ["v1"], body: $0.body) : $0 }
        }
        let r = try Age.decryptAndRecoverSignature(ciphertext: relabelled, identities: [id])
        guard case .unreadable = r.signature else { return XCTFail("expected unreadable, got \(r.signature)") }
    }

    func test_signedEncryption_rejectsWrongNamespaceOrMessage() throws {
        let id = X25519Identity.generate()
        let plaintext = Data("p".utf8)
        let enc = try SignedEncryption.prepare(to: [try X25519Recipient(ageRecipient: id.ageRecipient)])
        let signer = Signer()
        let v1Style = try signer.sign(message: plaintext, namespace: "agepony")
        XCTAssertThrowsError(try enc.encrypt(plaintext: plaintext, signatureArmored: v1Style))
        let wrongNS = try signer.sign(messageHash: enc.messageHash(plaintextSHA512: Data(SHA512.hash(data: plaintext))), namespace: "agepony")
        XCTAssertThrowsError(try enc.encrypt(plaintext: plaintext, signatureArmored: wrongNS))
    }

    func test_signedEncryption_refusesPassphrase() {
        XCTAssertThrowsError(try SignedEncryption.prepare(to: [ScryptRecipient(passphrase: "pw", workFactor: 10)]))
    }

    func test_v2_streaming_roundTrip() throws {
        let id = X25519Identity.generate()
        let plaintext = Data((0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        let sha = Data(SHA512.hash(data: plaintext))
        let enc = try SignedEncryption.prepare(to: [try X25519Recipient(ageRecipient: id.ageRecipient)])
        let sig = try Signer().sign(messageHash: enc.messageHash(plaintextSHA512: sha), namespace: SignatureStanza.namespaceV2)

        let sink = OutputStream.toMemory()
        sink.open()
        try enc.encryptStream(plaintext: InputStream(data: plaintext), plaintextSHA512: sha, signatureArmored: sig, into: sink)
        let file = try XCTUnwrap(sink.property(forKey: .dataWrittenToMemoryStreamKey) as? Data)

        let out = OutputStream.toMemory()
        out.open()
        let opening = try Age.decryptStream(ciphertext: InputStream(data: file), identities: [id], into: out)
        let got = try XCTUnwrap(out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data)
        XCTAssertEqual(got, plaintext)
        let opened = try XCTUnwrap(opening.opened)
        XCTAssertNoThrow(try opened.verify(plaintextHash: { $0.digest(got) }))
    }

    func test_v2_streaming_detectsChangedPlaintext() throws {
        let id = X25519Identity.generate()
        let plaintext = Data("original".utf8)
        let sha = Data(SHA512.hash(data: plaintext))
        let enc = try SignedEncryption.prepare(to: [try X25519Recipient(ageRecipient: id.ageRecipient)])
        let sig = try Signer().sign(messageHash: enc.messageHash(plaintextSHA512: sha), namespace: SignatureStanza.namespaceV2)
        let sink = OutputStream.toMemory()
        sink.open()
        XCTAssertThrowsError(try enc.encryptStream(plaintext: InputStream(data: Data("changed!".utf8)), plaintextSHA512: sha,
                                                   signatureArmored: sig, into: sink)) {
            XCTAssertEqual($0 as? SignedEncryptionError, .plaintextChanged)
        }
    }

    // MARK: - Stanza v1 (read only)

    func test_v1_stanza_stillVerifies() throws {
        let id = X25519Identity.generate()
        let plaintext = Data("made by 5.0.0".utf8)
        let signer = Signer()
        let sig = try signer.sign(message: plaintext, namespace: "agepony")
        let recipient = try X25519Recipient(ageRecipient: id.ageRecipient)
        let fileKey = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let stanzas = [try recipient.wrap(fileKey: fileKey), try SignatureStanza.buildV1(fileKey: fileKey, signatureArmored: sig)]
        var file = AgeHeader.serialize(stanzas: stanzas, fileKey: fileKey)
        file.append(try AgePayload.encrypt(plaintext: plaintext, fileKey: fileKey))

        let r = try Age.decryptAndRecoverSignature(ciphertext: file, identities: [id])
        let opened = try XCTUnwrap(r.signature.opened)
        XCTAssertEqual(opened.version, 1)
        XCTAssertFalse(opened.coversRecipients)
        XCTAssertEqual(opened.namespace, "agepony")
        XCTAssertNoThrow(try opened.verify(plaintext: r.plaintext))
        XCTAssertNoThrow(try opened.verify(plaintextHash: { $0.digest(r.plaintext) }))
    }

    // MARK: - Three-way result

    func test_unsignedFile_isAbsent() throws {
        let id = X25519Identity.generate()
        let file = try Age.encrypt(plaintext: Data("u".utf8), to: [try X25519Recipient(ageRecipient: id.ageRecipient)])
        let r = try Age.decryptAndRecoverSignature(ciphertext: file, identities: [id])
        XCTAssertEqual(r.signature, .absent)
    }

    func test_malformedStanzas_areUnreadable() throws {
        let fileKey = Data(repeating: 9, count: 16)
        let good = try SignatureStanza.buildV2(fileKey: fileKey, signatureArmored: "sig")
        let other = Stanza(type: "X25519", args: ["a"], body: Data(count: 32))
        let cases: [[Stanza]] = [
            [other, good, good],
            [other, Stanza(type: SignatureStanza.type, args: [], body: good.body)],
            [other, Stanza(type: SignatureStanza.type, args: ["v3"], body: good.body)],
            [other, Stanza(type: SignatureStanza.type, args: ["v2", "x"], body: good.body)],
            [other, Stanza(type: SignatureStanza.type, args: ["v2"], body: Data(count: 27))],
            [other, Stanza(type: SignatureStanza.type, args: ["v2"], body: Data(count: 60))],
        ]
        for stanzas in cases {
            guard case .unreadable = SignatureStanza.openHeader(fileKey: fileKey, stanzas: stanzas) else {
                return XCTFail("expected unreadable for \(stanzas.map(\.args))")
            }
        }
        XCTAssertNotNil(SignatureStanza.openHeader(fileKey: fileKey, stanzas: [other, good]).opened)
    }

    // MARK: - Signed bundle v2

    func test_bundleV2_roundTrip_and_tamper() throws {
        let signer = Signer()
        let payload = Data("bundle payload".utf8)
        let hash = SignedBundle.v2MessageHash(originalName: "report.pdf", payloadSHA512: Data(SHA512.hash(data: payload)))
        let sig = try signer.sign(messageHash: hash, namespace: SignedBundle.namespaceV2)
        let tar = try SignedBundle.buildV2(originalName: "report.pdf", payload: payload, signatureArmored: sig)

        let parsed = try XCTUnwrap(SignedBundle.parse(tar))
        XCTAssertEqual(parsed.version, 2)
        XCTAssertTrue(parsed.nameCovered)
        XCTAssertEqual(parsed.name, "report.pdf")
        XCTAssertNoThrow(try parsed.verify())

        let renamed = SignedBundle.Parsed(name: "invoice.pdf", payload: payload, signatureArmored: sig, version: 2,
                                          manifest: SignedBundle.manifestV2(originalName: "invoice.pdf"))
        XCTAssertThrowsError(try renamed.verify())

        let downgraded = SignedBundle.Parsed(name: "report.pdf", payload: payload, signatureArmored: sig, version: 1,
                                             manifest: Data("agepony-signed/1\nname=report.pdf\n".utf8))
        XCTAssertThrowsError(try downgraded.verify()) {
            XCTAssertEqual($0 as? SSHSigError, .namespaceMismatch(expected: "agepony", found: "agepony-bundle-v2"))
        }
    }

    func test_bundleV1_stillParsesAsV1() throws {
        let payload = Data("old".utf8)
        let sig = try Signer().sign(message: payload, namespace: "agepony")
        let parsed = try XCTUnwrap(SignedBundle.parse(try SignedBundle.build(originalName: "a.txt", payload: payload, signatureArmored: sig)))
        XCTAssertEqual(parsed.version, 1)
        XCTAssertFalse(parsed.nameCovered)
        XCTAssertNoThrow(try parsed.verify())
    }

    func test_bundleV2_streamingBuildAndUnwrap() throws {
        let signer = Signer()
        let payload = Data((0..<150_000).map { UInt8(truncatingIfNeeded: $0) })
        let hash = SignedBundle.v2MessageHash(originalName: "big.bin", payloadSHA512: Data(SHA512.hash(data: payload)))
        let sig = try signer.sign(messageHash: hash, namespace: SignedBundle.namespaceV2)

        let built = try SignedBundle.buildV2(originalName: "big.bin", payload: payload, signatureArmored: sig)
        let source = try SignedBundle.bundleSourceV2(originalName: "big.bin", payloadSize: Int64(payload.count),
                                                     payload: InputStream(data: payload), signatureArmored: sig)
        source.open()
        var pulled = Data()
        var buf = [UInt8](repeating: 0, count: 8192)
        while true {
            let n = source.read(&buf, maxLength: buf.count)
            if n <= 0 { break }
            pulled.append(buf, count: n)
        }
        XCTAssertEqual(pulled, built)
        XCTAssertEqual(SignedBundle.sizeOfV2(originalName: "big.bin", payloadSize: Int64(payload.count), signatureArmored: sig),
                       Int64(built.count))

        let out = OutputStream.toMemory()
        out.open()
        let sink = SignedBundleUnwrappingSink(payloadOut: out)
        sink.open()
        _ = built.withUnsafeBytes { sink.write($0.bindMemory(to: UInt8.self).baseAddress!, maxLength: built.count) }
        try sink.finish()
        let result = try XCTUnwrap(try sink.result())
        XCTAssertEqual(result.version, 2)
        XCTAssertNoThrow(try result.verify())
        XCTAssertEqual(out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data, payload)
    }

    // MARK: - Plain age reads it

    func test_referenceAge_decryptsV2SignedFileToBareBytes() throws {
        let candidates = ["/opt/homebrew/bin/age", "/usr/local/bin/age", "/usr/bin/age"]
        guard let agePath = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw XCTSkip("age CLI not installed; install with: brew install age")
        }
        let id = X25519Identity.generate()
        let plaintext = Data("plain age ignores the signature stanza\n".utf8)
        let file = try signedFile(plaintext, to: [try X25519Recipient(ageRecipient: id.ageRecipient)], signer: Signer())

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("agepony-sig-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keyURL = dir.appendingPathComponent("key.txt"), inURL = dir.appendingPathComponent("in.age")
        try Data((id.ageIdentityString + "\n").utf8).write(to: keyURL)
        try file.write(to: inURL)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: agePath)
        proc.arguments = ["-d", "-i", keyURL.path, inURL.path]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        try proc.run()
        let out = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        XCTAssertEqual(proc.terminationStatus, 0)
        XCTAssertEqual(out, plaintext)
    }
}
