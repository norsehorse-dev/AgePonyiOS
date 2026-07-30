//
//  SignedBundleTests.swift
//  AgePonyCoreTests
//
//  The signed bundle is the sign-then-encrypt container: payload plus its detached
//  SSHSIG, tarred together and then age-encrypted as a unit, so the signature never
//  appears outside the ciphertext.
//
//  Two properties matter most here, and both are load-bearing for cross-platform
//  interop with the Android build:
//
//   1. The streaming and buffered builders produce identical bytes.
//   2. `UnwrappingSink` correctly distinguishes a bundle from an ordinary file
//      mid-stream, because the decrypt path cannot know which it has until the first
//      block arrives — and getting that wrong either corrupts plain files or silently
//      skips verification.
//

import XCTest
import CryptoKit
@testable import AgePonyCore

final class SignedBundleTests: XCTestCase {

    private let armoredSignature = """
    -----BEGIN SSH SIGNATURE-----
    U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgabcdefghijklmnopqrstuvwx
    -----END SSH SIGNATURE-----
    """

    private func pattern(_ n: Int, seed: UInt8 = 0) -> Data {
        Data((0..<n).map { UInt8((($0 &* 41) &+ Int(seed) &* 13 &+ 3) % 251) })
    }

    private func memoryOutput() -> OutputStream {
        let s = OutputStream.toMemory()
        s.open()
        return s
    }

    private func contents(_ s: OutputStream) -> Data {
        s.close()
        return s.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
    }

    private func drain(_ s: InputStream) throws -> Data {
        s.open()
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = s.read(&buf, maxLength: buf.count)
            if n < 0 { throw s.streamError ?? SignedBundleError.damaged("read failed") }
            if n == 0 { break }
            out.append(contentsOf: buf[0..<n])
        }
        return out
    }

    private var sizes: [Int] { [0, 1, 511, 512, 513, 5000, 70_000] }

    // MARK: - Buffered round trip

    func testBuildParseRoundTrip() throws {
        for n in sizes {
            let payload = pattern(n, seed: 1)
            let bundle = try SignedBundle.build(
                originalName: "report.pdf",
                payload: payload,
                signatureArmored: armoredSignature
            )
            let parsed = try XCTUnwrap(SignedBundle.parse(bundle), "failed to parse at \(n) bytes")
            XCTAssertEqual(parsed.name, "report.pdf")
            XCTAssertEqual(parsed.payload, payload)
            XCTAssertEqual(parsed.signatureArmored, armoredSignature)
        }
    }

    func testEntryOrderAndNames() throws {
        let bundle = try SignedBundle.build(
            originalName: "x", payload: pattern(100), signatureArmored: armoredSignature
        )
        let entries = try TarArchive.extract(bundle)
        XCTAssertEqual(entries.map(\.name), [".agepony-signed", "payload", "payload.sig"])
        XCTAssertTrue(
            String(decoding: entries[0].data, as: UTF8.self).hasPrefix("agepony-signed/1\n")
        )
    }

    // MARK: - Not-a-bundle detection

    func testParseReturnsNilForPlainData() {
        XCTAssertNil(SignedBundle.parse(Data("just some bytes, not a tar".utf8)))
        XCTAssertNil(SignedBundle.parse(Data()))
        XCTAssertNil(SignedBundle.parse(pattern(10_000)))
    }

    /// An ordinary multi-file bundle is a valid tar whose first entry is not the marker.
    /// It must not be mistaken for a signed bundle.
    func testParseReturnsNilForOrdinaryMultiFileArchive() throws {
        let archive = try TarArchive.create([
            TarArchive.Entry(name: "a.txt", data: pattern(100)),
            TarArchive.Entry(name: "b.txt", data: pattern(200)),
        ])
        XCTAssertNil(SignedBundle.parse(archive))
    }

    func testLooksLikeBundle() throws {
        let bundle = try SignedBundle.build(
            originalName: "x", payload: pattern(5000), signatureArmored: armoredSignature
        )
        XCTAssertTrue(SignedBundle.looksLikeBundle(bundle))

        let ordinary = try TarArchive.create([TarArchive.Entry(name: "a", data: pattern(100))])
        XCTAssertFalse(SignedBundle.looksLikeBundle(ordinary))
        XCTAssertFalse(SignedBundle.looksLikeBundle(pattern(10_000)))
    }

    // MARK: - Streaming build is byte-identical

    func testBuildStreamMatchesBuild() throws {
        for n in sizes {
            let payload = pattern(n, seed: 2)
            let buffered = try SignedBundle.build(
                originalName: "doc.txt", payload: payload, signatureArmored: armoredSignature
            )

            let out = memoryOutput()
            try SignedBundle.buildStream(
                into: out,
                originalName: "doc.txt",
                payloadSize: Int64(payload.count),
                payload: InputStream(data: payload),
                signatureArmored: armoredSignature
            )
            XCTAssertEqual(contents(out), buffered, "buildStream differs at \(n) bytes")
        }
    }

    func testBundleSourceMatchesBuild() throws {
        for n in sizes {
            let payload = pattern(n, seed: 3)
            let buffered = try SignedBundle.build(
                originalName: "doc.txt", payload: payload, signatureArmored: armoredSignature
            )
            let source = try SignedBundle.bundleSource(
                originalName: "doc.txt",
                payloadSize: Int64(payload.count),
                payload: InputStream(data: payload),
                signatureArmored: armoredSignature
            )
            XCTAssertEqual(try drain(source), buffered, "bundleSource differs at \(n) bytes")
        }
    }

    func testSizeOfMatchesActualBundle() throws {
        for n in sizes {
            let payload = pattern(n, seed: 4)
            let predicted = SignedBundle.sizeOf(
                originalName: "doc.txt",
                payloadSize: Int64(payload.count),
                signatureArmored: armoredSignature
            )
            let actual = try SignedBundle.build(
                originalName: "doc.txt", payload: payload, signatureArmored: armoredSignature
            )
            XCTAssertEqual(predicted, Int64(actual.count), "sizeOf disagreed at \(n) bytes")
        }
    }

    // MARK: - Name handling

    func testNameIsSanitized() throws {
        let bundle = try SignedBundle.build(
            originalName: "bad\nname\rhere",
            payload: pattern(10),
            signatureArmored: armoredSignature
        )
        // A newline in the manifest would forge a second manifest line, so it is replaced.
        let parsed = try XCTUnwrap(SignedBundle.parse(bundle))
        XCTAssertEqual(parsed.name, "bad_name_here")
    }

    func testBlankNameFallsBackToFile() throws {
        let bundle = try SignedBundle.build(
            originalName: "   ", payload: pattern(10), signatureArmored: armoredSignature
        )
        XCTAssertEqual(try XCTUnwrap(SignedBundle.parse(bundle)).name, "file")
    }

    // MARK: - UnwrappingSink

    private func unwrap(_ plaintext: Data, chunk: Int = 4096)
        throws -> (payload: Data, result: SignedBundle.StreamParsed?)
    {
        let payloadOut = memoryOutput()
        let sink = SignedBundleUnwrappingSink(payloadOut: payloadOut)
        sink.open()
        var offset = 0
        while offset < plaintext.count {
            let take = min(chunk, plaintext.count - offset)
            try AgePayload.writeAll(Data(plaintext[offset..<(offset + take)]), to: sink)
            offset += take
        }
        try sink.finish()
        return (contents(payloadOut), try sink.result())
    }

    func testUnwrappingSinkStripsBundle() throws {
        for n in sizes {
            let payload = pattern(n, seed: 5)
            let bundle = try SignedBundle.build(
                originalName: "secret.txt", payload: payload, signatureArmored: armoredSignature
            )
            let (out, result) = try unwrap(bundle)
            XCTAssertEqual(out, payload, "payload wrong at \(n) bytes")

            let parsed = try XCTUnwrap(result, "not recognized as a bundle at \(n) bytes")
            XCTAssertEqual(parsed.name, "secret.txt")
            XCTAssertEqual(parsed.signatureArmored, armoredSignature)
            XCTAssertEqual(parsed.payloadSize, Int64(n))
        }
    }

    /// The hashes are computed while the payload streams past, because the signature
    /// entry — which says which algorithm was used — arrives only after the payload
    /// is already gone.
    func testUnwrappingSinkHashesPayload() throws {
        let payload = pattern(50_000, seed: 6)
        let bundle = try SignedBundle.build(
            originalName: "f", payload: payload, signatureArmored: armoredSignature
        )
        let (_, result) = try unwrap(bundle)
        let parsed = try XCTUnwrap(result)

        XCTAssertEqual(parsed.hash(.sha512), SSHSigHash.sha512.digest(payload))
        XCTAssertEqual(parsed.hash(.sha256), SSHSigHash.sha256.digest(payload))
    }

    /// Plain data must pass through untouched, with a nil result — this is what makes it
    /// safe for the decrypt path to route *every* decrypted output through the sink.
    func testUnwrappingSinkPassesThroughPlainData() throws {
        for n in [0, 1, 100, 511, 512, 513, 100_000] {
            let plain = pattern(n, seed: 7)
            let (out, result) = try unwrap(plain)
            XCTAssertEqual(out, plain, "plain data altered at \(n) bytes")
            XCTAssertNil(result, "plain data misread as a bundle at \(n) bytes")
        }
    }

    func testUnwrappingSinkPassesThroughOrdinaryArchive() throws {
        let archive = try TarArchive.create([
            TarArchive.Entry(name: "a.txt", data: pattern(1000)),
            TarArchive.Entry(name: "b.txt", data: pattern(2000)),
        ])
        let (out, result) = try unwrap(archive)
        XCTAssertEqual(out, archive, "an ordinary multi-file bundle must pass through intact")
        XCTAssertNil(result)
    }

    /// The sink is fed by a chunked stream, so its behaviour must not depend on where
    /// chunk boundaries happen to fall relative to tar's 512-byte blocks.
    func testUnwrappingSinkIndependentOfChunkBoundaries() throws {
        let payload = pattern(9000, seed: 8)
        let bundle = try SignedBundle.build(
            originalName: "chunked", payload: payload, signatureArmored: armoredSignature
        )
        for chunk in [1, 7, 511, 512, 513, 1024, 65536] {
            let (out, result) = try unwrap(bundle, chunk: chunk)
            XCTAssertEqual(out, payload, "wrong payload at write chunk \(chunk)")
            XCTAssertEqual(try XCTUnwrap(result).name, "chunked", "lost metadata at chunk \(chunk)")
        }
    }

    func testUnwrappingSinkReportsDamage() throws {
        let payload = pattern(5000, seed: 9)
        var bundle = try SignedBundle.build(
            originalName: "f", payload: payload, signatureArmored: armoredSignature
        )
        // Truncate mid-payload: the marker was seen, so this is damage, not a plain file.
        bundle = Data(bundle.prefix(2000))

        let payloadOut = memoryOutput()
        let sink = SignedBundleUnwrappingSink(payloadOut: payloadOut)
        sink.open()
        try AgePayload.writeAll(bundle, to: sink)
        try sink.finish()

        XCTAssertThrowsError(try sink.result()) { error in
            guard case SignedBundleError.damaged = error else {
                return XCTFail("expected .damaged, got \(error)")
            }
        }
    }

    // MARK: - End to end through age

    /// The whole point: sign-then-encrypt yields one file, and the signature is inside
    /// the ciphertext rather than beside it.
    func testSignThenEncryptRoundTripThroughAge() throws {
        let identity = X25519Identity.generate()
        let payload = pattern(300_000, seed: 10)

        // Encrypt the bundle without ever building it in memory.
        let source = try SignedBundle.bundleSource(
            originalName: "contract.pdf",
            payloadSize: Int64(payload.count),
            payload: InputStream(data: payload),
            signatureArmored: armoredSignature
        )
        let encrypted = memoryOutput()
        try Age.encryptStream(
            plaintext: source,
            to: [try X25519Recipient(publicKey: identity.publicKey)],
            into: encrypted
        )
        let ciphertext = contents(encrypted)

        // The signature must not be visible in the ciphertext.
        XCTAssertNil(
            ciphertext.range(of: Data("BEGIN SSH SIGNATURE".utf8)),
            "the signature leaked outside the ciphertext"
        )

        // Decrypt straight through the unwrapping sink.
        let payloadOut = memoryOutput()
        let sink = SignedBundleUnwrappingSink(payloadOut: payloadOut)
        sink.open()
        try Age.decryptStream(
            ciphertext: InputStream(data: ciphertext),
            identities: [identity],
            into: sink
        )
        try sink.finish()

        let parsed = try XCTUnwrap(try sink.result())
        XCTAssertEqual(parsed.name, "contract.pdf")
        XCTAssertEqual(parsed.signatureArmored, armoredSignature)
        XCTAssertEqual(contents(payloadOut), payload)
        XCTAssertEqual(parsed.hash(.sha512), SSHSigHash.sha512.digest(payload))
    }

    /// An ordinary encrypted file, decrypted through the same sink, must come out
    /// unchanged with no verdict — the decrypt path uses one code path for both.
    func testOrdinaryFileThroughDecryptSinkIsUnchanged() throws {
        let identity = X25519Identity.generate()
        let plaintext = pattern(120_000, seed: 11)
        let ciphertext = try Age.encrypt(
            plaintext: plaintext,
            to: [try X25519Recipient(publicKey: identity.publicKey)]
        )

        let payloadOut = memoryOutput()
        let sink = SignedBundleUnwrappingSink(payloadOut: payloadOut)
        sink.open()
        try Age.decryptStream(
            ciphertext: InputStream(data: ciphertext),
            identities: [identity],
            into: sink
        )
        try sink.finish()

        XCTAssertNil(try sink.result())
        XCTAssertEqual(contents(payloadOut), plaintext)
    }
}

// MARK: - Streaming SSHSIG hash

final class SSHSigHashStreamTests: XCTestCase {

    private func pattern(_ n: Int) -> Data {
        Data((0..<n).map { UInt8(($0 &* 53 &+ 17) % 251) })
    }

    func testStreamingHashMatchesBuffered() throws {
        for n in [0, 1, 63, 64, 65, 1024, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 300_000] {
            let data = pattern(n)
            for algorithm in [SSHSigHash.sha256, .sha512] {
                XCTAssertEqual(
                    try algorithm.digest(streaming: InputStream(data: data)),
                    algorithm.digest(data),
                    "\(algorithm) differs at \(n) bytes"
                )
            }
        }
    }
}

// MARK: - Names from an untrusted manifest

/// A bundle's manifest is attacker-controlled, and the decrypt path writes a file
/// using the name it finds there. These are the shapes that must not survive.
final class SignedBundleSafeNameTests: XCTestCase {

    func testKeepsAnOrdinaryName() {
        XCTAssertEqual(SignedBundle.safeFileName("report.pdf"), "report.pdf")
        XCTAssertEqual(SignedBundle.safeFileName("a b — c.tar.gz"), "a b — c.tar.gz")
    }

    func testStripsPathTraversal() {
        XCTAssertEqual(SignedBundle.safeFileName("../../etc/passwd"), "passwd")
        XCTAssertEqual(SignedBundle.safeFileName("/etc/passwd"), "passwd")
        XCTAssertEqual(SignedBundle.safeFileName("a/b/c/report.pdf"), "report.pdf")
    }

    func testRefusesNamesThatAreOnlyTraversal() {
        for name in ["..", ".", "../..", "/", "", "   ", "a/.."] {
            XCTAssertEqual(SignedBundle.safeFileName(name), "file", "for \(name.debugDescription)")
        }
    }

    func testUsesTheGivenFallback() {
        XCTAssertEqual(SignedBundle.safeFileName("..", fallback: "payload.bin"), "payload.bin")
    }

    /// The manifest allows 4 KiB; filesystems allow far less.
    func testCapsLength() {
        let long = String(repeating: "x", count: 3000)
        XCTAssertEqual(SignedBundle.safeFileName(long).count, 200)
    }

    func testDropsEmbeddedNulAndSurroundingSpace() {
        XCTAssertEqual(SignedBundle.safeFileName("  report.pdf  "), "report.pdf")
        XCTAssertEqual(SignedBundle.safeFileName("re\0port.pdf"), "report.pdf")
    }
}

// MARK: - The whole sign-then-encrypt round trip

/// What 3.0 actually promises: one encrypted file goes out, and what comes back is
/// the original payload plus a signature that verifies — with the payload never
/// held whole at either end.
final class SignedBundleThroughAgeTests: XCTestCase {

    func testBundleSurvivesEncryptionAndVerifiesFromStreamedDigests() throws {
        let payload = Data((0..<250_000).map { UInt8(($0 &* 31 &+ 11) % 251) })

        let seed = Data((0..<32).map { UInt8($0 &+ 3) })
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let pub = key.publicKey.rawRepresentation

        // Sign the payload from a streamed digest -- as the app does, never
        // holding the plaintext.
        let digest = try SSHSigHash.sha512.digest(streaming: InputStream(data: payload))
        let armored = try SSHSigner.signEd25519(
            messageHash: digest,
            privateMaterial: seed + pub
        )

        // Encrypt the bundle without ever building it.
        let identity = X25519Identity.generate()
        let recipient = try X25519Recipient(publicKey: identity.publicKey)
        let bundle = try SignedBundle.bundleSource(
            originalName: "quarterly report.pdf",
            payloadSize: Int64(payload.count),
            payload: InputStream(data: payload),
            signatureArmored: armored
        )
        let ciphertextOut = OutputStream.toMemory()
        ciphertextOut.open()
        try Age.encryptStream(plaintext: bundle, to: [recipient], into: ciphertextOut)
        ciphertextOut.close()
        let ciphertext = ciphertextOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()

        // The declared size has to match what was actually produced, or the tar
        // header would be a lie and the whole thing would fail to parse.
        XCTAssertEqual(
            SignedBundle.sizeOf(
                originalName: "quarterly report.pdf",
                payloadSize: Int64(payload.count),
                signatureArmored: armored
            ),
            Int64(try SignedBundle.build(
                originalName: "quarterly report.pdf",
                payload: payload,
                signatureArmored: armored
            ).count)
        )

        // Decrypt straight into the unwrapping sink, the way the app does.
        let plaintextOut = OutputStream.toMemory()
        plaintextOut.open()
        let sink = SignedBundleUnwrappingSink(payloadOut: plaintextOut)
        sink.open()
        try Age.decryptStream(
            ciphertext: InputStream(data: ciphertext),
            identities: [identity],
            into: sink
        )
        try sink.finish()
        plaintextOut.close()

        let parsed = try XCTUnwrap(try sink.result())
        XCTAssertEqual(parsed.name, "quarterly report.pdf")
        XCTAssertEqual(parsed.payloadSize, Int64(payload.count))

        let recovered = plaintextOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
        XCTAssertEqual(recovered, payload)

        // Verified from the digests alone. Nothing re-reads the payload.
        let v = try SSHSigVerifier.verify(
            armoredSignature: parsed.signatureArmored,
            messageHash: { parsed.hash($0) }
        )
        XCTAssertEqual(v.publicKeyWire, SSHSig.ed25519PublicKeyWire(pub))
    }

    /// A plain file is not a bundle, and must come through untouched with no verdict.
    func testOrdinaryPlaintextPassesThroughUnchanged() throws {
        let identity = X25519Identity.generate()
        let recipient = try X25519Recipient(publicKey: identity.publicKey)

        for size in [0, 1, 511, 512, 513, 200_000] {
            let plaintext = Data((0..<size).map { UInt8($0 % 251) })
            let ciphertext = try Age.encrypt(plaintext: plaintext, to: [recipient])

            let out = OutputStream.toMemory()
            out.open()
            let sink = SignedBundleUnwrappingSink(payloadOut: out)
            sink.open()
            try Age.decryptStream(
                ciphertext: InputStream(data: ciphertext),
                identities: [identity],
                into: sink
            )
            try sink.finish()
            out.close()

            XCTAssertNil(try sink.result(), "at \(size) bytes")
            let recovered = out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
            XCTAssertEqual(recovered, plaintext, "at \(size) bytes")
        }
    }
}
