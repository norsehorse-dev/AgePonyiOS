//
//  AgeArmorStreamTests.swift
//  AgePonyCoreTests
//
//  The streaming armor path must be byte-identical to the buffered one. That is the
//  whole contract — a file armored by the streaming sink has to be indistinguishable
//  from one armored in memory, or the two paths diverge silently and only some files
//  round-trip.
//

import XCTest
@testable import AgePonyCore

final class AgeArmorStreamTests: XCTestCase {

    // MARK: - Helpers

    private func armorStreamed(_ binary: Data) throws -> String {
        let input = InputStream(data: binary)
        let output = OutputStream.toMemory()
        try AgeArmor.encodeStream(binary: input, into: output)
        output.close()
        let data = output.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    private func dearmorStreamed(_ text: String) throws -> Data {
        let input = InputStream(data: Data(text.utf8))
        let output = OutputStream.toMemory()
        try AgeArmor.decodeStream(armored: input, into: output)
        output.close()
        return output.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
    }

    /// Sizes chosen around the 48-byte group boundary, the 64-char line width, and the
    /// 48 KiB read chunk — every place the streaming path can lose or duplicate bytes.
    private var interestingSizes: [Int] {
        [0, 1, 2, 3, 47, 48, 49, 95, 96, 97,
         143, 144, 145, 1023, 1024,
         48 * 1024 - 1, 48 * 1024, 48 * 1024 + 1,
         100_000]
    }

    private func pattern(_ n: Int) -> Data {
        Data((0..<n).map { UInt8(($0 &* 31 &+ 7) % 251) })
    }

    // MARK: - Byte identity with the buffered path

    func testStreamedEncodeMatchesBufferedEncode() throws {
        for n in interestingSizes {
            let binary = pattern(n)
            XCTAssertEqual(
                try armorStreamed(binary),
                AgeArmor.encode(binary),
                "streamed armor differs from buffered at \(n) bytes"
            )
        }
    }

    func testStreamedDecodeMatchesBufferedDecode() throws {
        for n in interestingSizes {
            let armored = AgeArmor.encode(pattern(n))
            XCTAssertEqual(
                try dearmorStreamed(armored),
                try AgeArmor.decode(armored),
                "streamed dearmor differs from buffered at \(n) bytes"
            )
        }
    }

    func testStreamRoundTripsAcrossSizes() throws {
        for n in interestingSizes {
            let binary = pattern(n)
            XCTAssertEqual(try dearmorStreamed(try armorStreamed(binary)), binary, "at \(n) bytes")
        }
    }

    func testStreamedDecodeAcceptsBufferedEncodeAndViceVersa() throws {
        let binary = pattern(5000)
        XCTAssertEqual(try dearmorStreamed(AgeArmor.encode(binary)), binary)
        XCTAssertEqual(try AgeArmor.decode(try armorStreamed(binary)), binary)
    }

    // MARK: - Write chunking must not change the output
    //
    // The sink holds a partial 48-byte group between writes. If that carry is wrong,
    // output depends on how the caller happened to chunk its writes — which is exactly
    // the bug this guards.

    func testOutputIndependentOfWriteChunking() throws {
        let binary = pattern(10_000)
        let expected = AgeArmor.encode(binary)

        for chunk in [1, 7, 47, 48, 49, 64, 100, 4096] {
            let output = OutputStream.toMemory()
            let sink = try AgeArmor.EncodingSink(output)
            var offset = 0
            while offset < binary.count {
                let take = min(chunk, binary.count - offset)
                try sink.write(Data(binary[offset..<(offset + take)]))
                offset += take
            }
            try sink.finish()
            output.close()
            let text = String(
                decoding: output.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data(),
                as: UTF8.self
            )
            XCTAssertEqual(text, expected, "write chunk size \(chunk) changed the output")
        }
    }

    func testFinishIsIdempotent() throws {
        let output = OutputStream.toMemory()
        let sink = try AgeArmor.EncodingSink(output)
        try sink.write(Data("hello".utf8))
        try sink.finish()
        try sink.finish()
        output.close()
        let text = String(
            decoding: output.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data(),
            as: UTF8.self
        )
        XCTAssertEqual(text, AgeArmor.encode(Data("hello".utf8)))
    }

    // MARK: - Leniency, matching the buffered decoder

    func testStreamedDecodeAcceptsCRLF() throws {
        let binary = pattern(500)
        let crlf = AgeArmor.encode(binary).replacingOccurrences(of: "\n", with: "\r\n")
        XCTAssertEqual(try dearmorStreamed(crlf), binary)
    }

    func testStreamedDecodeAcceptsSurroundingBlankLines() throws {
        let binary = pattern(500)
        let padded = "\n\n  \n" + AgeArmor.encode(binary) + "\n   \n\n"
        XCTAssertEqual(try dearmorStreamed(padded), binary)
    }

    // MARK: - Rejection

    func testStreamedDecodeRejectsMissingBegin() {
        let body = AgeArmor.encode(pattern(100))
            .replacingOccurrences(of: AgeArmor.beginMarker + "\n", with: "")
        XCTAssertThrowsError(try dearmorStreamed(body))
    }

    func testStreamedDecodeRejectsMissingEnd() {
        let body = AgeArmor.encode(pattern(100))
            .replacingOccurrences(of: AgeArmor.endMarker + "\n", with: "")
        XCTAssertThrowsError(try dearmorStreamed(body))
    }

    func testStreamedDecodeRejectsContentAfterEnd() {
        let body = AgeArmor.encode(pattern(100)) + "trailing junk\n"
        XCTAssertThrowsError(try dearmorStreamed(body))
    }

    // MARK: - Substituting for a real stream

    /// The decoding source exists so an armored file can be handed straight to
    /// `Age.decryptStream` without being decoded whole first.
    func testDecodingSourceFeedsAgeDecryptStream() throws {
        let identity = X25519Identity.generate()
        let plaintext = Data(repeating: 0x5A, count: 150_000)

        let ciphertext = try Age.encrypt(
            plaintext: plaintext,
            to: [try X25519Recipient(publicKey: identity.publicKey)]
        )
        let armored = AgeArmor.encode(ciphertext)

        let source = ArmorDecodingSource(InputStream(data: Data(armored.utf8)))
        let out = OutputStream.toMemory()
        try Age.decryptStream(ciphertext: source, identities: [identity], into: out)
        out.close()
        let recovered = out.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()

        XCTAssertEqual(recovered, plaintext)
    }

    // MARK: - Sniffing

    func testLooksArmoredFromPrefixOnly() {
        let armored = AgeArmor.encode(pattern(100_000))
        let prefix = Data(Data(armored.utf8).prefix(AgeArmor.sniffLength))
        XCTAssertTrue(AgeArmor.looksArmored(prefix: prefix))

        XCTAssertFalse(AgeArmor.looksArmored(prefix: Data("age-encryption.org/v1\n".utf8)))
        XCTAssertFalse(AgeArmor.looksArmored(prefix: Data(repeating: 0xFF, count: 64)))
    }
}
