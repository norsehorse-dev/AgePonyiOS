//
//  TarArchiveStreamTests.swift
//  AgePonyCoreTests
//
//  The streaming tar paths must produce byte-identical archives to the buffered
//  `create`. That is the contract: a multi-file bundle written by the streaming writer,
//  or read out of the pull-shaped source, has to be indistinguishable from one built in
//  memory — otherwise the two paths drift and only some bundles interoperate, including
//  across to the Android build.
//

import XCTest
@testable import AgePonyCore

final class TarArchiveStreamTests: XCTestCase {

    // MARK: - Helpers

    private func pattern(_ n: Int, seed: UInt8 = 0) -> Data {
        Data((0..<n).map { UInt8((($0 &* 37) &+ Int(seed) &* 11 &+ 5) % 251) })
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
            if n < 0 { throw s.streamError ?? TarArchiveError.truncated }
            if n == 0 { break }
            out.append(contentsOf: buf[0..<n])
        }
        return out
    }

    /// Sizes around the 512-byte block boundary and the 64 KiB copy buffer.
    private var interestingSizes: [Int] {
        [0, 1, 511, 512, 513, 1023, 1024, 1025,
         64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 200_000]
    }

    // MARK: - Byte identity: push writer vs create

    func testStreamingWriteMatchesCreate() throws {
        for n in interestingSizes {
            let entries = [
                TarArchive.Entry(name: "a.txt", data: pattern(n, seed: 1)),
                TarArchive.Entry(name: "b.bin", data: pattern(300, seed: 2)),
            ]
            let buffered = try TarArchive.create(entries)

            let out = memoryOutput()
            for e in entries {
                try TarArchive.writeEntry(to: out, name: e.name, data: e.data)
            }
            try TarArchive.finish(to: out)

            XCTAssertEqual(contents(out), buffered, "streamed archive differs at payload size \(n)")
        }
    }

    func testStreamingWriteFromInputStreamMatchesCreate() throws {
        for n in interestingSizes {
            let payload = pattern(n, seed: 3)
            let entries = [TarArchive.Entry(name: "payload", data: payload)]
            let buffered = try TarArchive.create(entries)

            let out = memoryOutput()
            try TarArchive.writeEntry(
                to: out,
                name: "payload",
                size: Int64(payload.count),
                from: InputStream(data: payload)
            )
            try TarArchive.finish(to: out)

            XCTAssertEqual(contents(out), buffered, "streamed-from-stream archive differs at \(n)")
        }
    }

    // MARK: - Byte identity: pull source vs create

    func testSourceMatchesCreate() throws {
        for n in interestingSizes {
            let a = pattern(n, seed: 4)
            let b = pattern(777, seed: 5)
            let buffered = try TarArchive.create([
                TarArchive.Entry(name: "one", data: a),
                TarArchive.Entry(name: "two", data: b),
            ])

            let source = try TarArchive.source([
                TarArchive.StreamEntry(name: "one", size: Int64(a.count)) { InputStream(data: a) },
                TarArchive.StreamEntry(name: "two", size: Int64(b.count)) { InputStream(data: b) },
            ])

            XCTAssertEqual(try drain(source), buffered, "source archive differs at payload size \(n)")
        }
    }

    func testSourceOfNoEntriesIsJustEndBlocks() throws {
        let source = try TarArchive.source([])
        XCTAssertEqual(try drain(source), try TarArchive.create([]))
    }

    /// Output must not depend on how the consumer happens to chunk its reads.
    func testSourceOutputIndependentOfReadSize() throws {
        let payload = pattern(5000, seed: 6)
        let expected = try TarArchive.create([TarArchive.Entry(name: "p", data: payload)])

        for readSize in [1, 7, 512, 513, 4096] {
            let source = try TarArchive.source([
                TarArchive.StreamEntry(name: "p", size: Int64(payload.count)) {
                    InputStream(data: payload)
                }
            ])
            source.open()
            var out = Data()
            var buf = [UInt8](repeating: 0, count: readSize)
            while true {
                let n = source.read(&buf, maxLength: readSize)
                if n <= 0 { break }
                out.append(contentsOf: buf[0..<n])
            }
            XCTAssertEqual(out, expected, "read size \(readSize) changed the output")
        }
    }

    // MARK: - sizeOf

    func testSizeOfMatchesActualLength() throws {
        for n in interestingSizes {
            let entries = [
                TarArchive.StreamEntry(name: "a", size: Int64(n)) { InputStream(data: self.pattern(n)) },
                TarArchive.StreamEntry(name: "b", size: 100) { InputStream(data: self.pattern(100)) },
            ]
            let predicted = TarArchive.sizeOf(entries)
            let actual = try drain(try TarArchive.source(entries))
            XCTAssertEqual(Int64(actual.count), predicted, "sizeOf disagreed at payload size \(n)")
        }
    }

    // MARK: - Streaming read

    func testForEachEntryRoundTrips() throws {
        let entries = [
            TarArchive.Entry(name: "first.txt", data: pattern(1000, seed: 7)),
            TarArchive.Entry(name: "second.bin", data: pattern(0, seed: 8)),
            TarArchive.Entry(name: "third", data: pattern(70_000, seed: 9)),
        ]
        let archive = try TarArchive.create(entries)

        var seen: [(String, Int64, Data)] = []
        try TarArchive.forEachEntry(from: InputStream(data: archive)) { name, size, reader in
            seen.append((name, size, try reader.readAll()))
        }

        XCTAssertEqual(seen.count, entries.count)
        for (i, e) in entries.enumerated() {
            XCTAssertEqual(seen[i].0, e.name)
            XCTAssertEqual(seen[i].1, Int64(e.data.count))
            XCTAssertEqual(seen[i].2, e.data)
        }
    }

    /// A handler that reads only part of an entry must not desynchronize the archive —
    /// the reader drains the remainder before the next header.
    func testForEachEntryToleratesPartiallyReadEntries() throws {
        let entries = [
            TarArchive.Entry(name: "big", data: pattern(50_000, seed: 10)),
            TarArchive.Entry(name: "after", data: pattern(123, seed: 11)),
        ]
        let archive = try TarArchive.create(entries)

        var names: [String] = []
        var afterData = Data()
        try TarArchive.forEachEntry(from: InputStream(data: archive)) { name, _, reader in
            names.append(name)
            if name == "big" {
                _ = try reader.read(maxLength: 10)     // deliberately leave the rest unread
            } else {
                afterData = try reader.readAll()
            }
        }

        XCTAssertEqual(names, ["big", "after"])
        XCTAssertEqual(afterData, entries[1].data)
    }

    func testForEachEntryMatchesExtract() throws {
        let entries = (0..<5).map {
            TarArchive.Entry(name: "f\($0)", data: pattern(($0 + 1) * 700, seed: UInt8($0)))
        }
        let archive = try TarArchive.create(entries)

        var streamed: [TarArchive.Entry] = []
        try TarArchive.forEachEntry(from: InputStream(data: archive)) { name, _, reader in
            streamed.append(TarArchive.Entry(name: name, data: try reader.readAll()))
        }
        XCTAssertEqual(streamed, try TarArchive.extract(archive))
    }

    func testForEachEntryRejectsBadChecksum() throws {
        var archive = [UInt8](try TarArchive.create([
            TarArchive.Entry(name: "x", data: pattern(100))
        ]))
        archive[0] ^= 0xFF     // corrupt the name, invalidating the checksum

        XCTAssertThrowsError(
            try TarArchive.forEachEntry(from: InputStream(data: Data(archive))) { _, _, _ in }
        )
    }

    // MARK: - Declared size must match reality
    //
    // USTAR writes the size into the header before the data, so a stream that disagrees
    // with its declared size would silently produce a corrupt archive. Both directions
    // are caught.

    func testWriteEntryRejectsShortStream() {
        let out = memoryOutput()
        XCTAssertThrowsError(
            try TarArchive.writeEntry(
                to: out, name: "p", size: 1000, from: InputStream(data: pattern(500))
            )
        ) { error in
            guard case TarArchiveError.entryEndedEarly(let name, let written, let declared) = error else {
                return XCTFail("expected entryEndedEarly, got \(error)")
            }
            XCTAssertEqual(name, "p")
            XCTAssertEqual(written, 500)
            XCTAssertEqual(declared, 1000)
        }
    }

    func testWriteEntryRejectsLongStreamWhenStrict() {
        let out = memoryOutput()
        XCTAssertThrowsError(
            try TarArchive.writeEntry(
                to: out, name: "p", size: 100, from: InputStream(data: pattern(500))
            )
        ) { error in
            guard case TarArchiveError.entryLongerThanDeclared = error else {
                return XCTFail("expected entryLongerThanDeclared, got \(error)")
            }
        }
    }

    /// Non-strict is for a stream carrying further entries, where reading one byte past
    /// would consume the next entry's first byte.
    func testWriteEntryNonStrictLeavesStreamPositioned() throws {
        let combined = pattern(100, seed: 12) + pattern(50, seed: 13)
        let input = InputStream(data: combined)
        input.open()

        let out = memoryOutput()
        try TarArchive.writeEntry(to: out, name: "a", size: 100, from: input, strict: false)

        let rest = try AgePayload.readFully(input, maxLength: 50)
        XCTAssertEqual(rest, pattern(50, seed: 13))
    }

    func testRejectsNameTooLong() {
        let out = memoryOutput()
        let long = String(repeating: "x", count: 101)
        XCTAssertThrowsError(try TarArchive.writeEntry(to: out, name: long, data: Data()))
        XCTAssertThrowsError(
            try TarArchive.source([
                TarArchive.StreamEntry(name: long, size: 0) { InputStream(data: Data()) }
            ])
        )
    }

    func testRejectsNegativeAndOversizeEntries() {
        let out = memoryOutput()
        XCTAssertThrowsError(
            try TarArchive.writeEntry(to: out, name: "n", size: -1, from: InputStream(data: Data()))
        )
        XCTAssertThrowsError(
            try TarArchive.writeEntry(
                to: out, name: "n", size: TarArchive.maxEntrySize + 1, from: InputStream(data: Data())
            )
        )
    }

    // MARK: - Large sizes in the header
    //
    // The buffered header formats its octal size with String(format: "%011o"), whose %o
    // conversion takes a C unsigned int. The streaming header formats octal by hand so
    // entries at or above 4 GiB — still inside USTAR's range, and the whole reason this
    // streaming work exists — get a correct size field.

    func testHeaderEncodesSizesBeyond32Bits() throws {
        let size: Int64 = 5_000_000_000
        let header = try TarArchive.streamHeader(name: "huge", size: size)
        let field = String(decoding: [UInt8](header)[124..<135], as: UTF8.self)
        XCTAssertEqual(field, String(format: "%011llo", size))
        XCTAssertEqual(Int64(field, radix: 8), size)

        // And it still parses back to the same value.
        let parsed = try TarArchive.parseStreamHeader(header)
        XCTAssertEqual(parsed?.size, size)
        XCTAssertEqual(parsed?.name, "huge")
    }

    func testStreamHeaderMatchesBufferedHeaderForOrdinarySizes() throws {
        // The two header builders must agree byte for byte, or archives written by the
        // streaming and buffered paths would differ.
        for n in [0, 1, 511, 512, 1000, 100_000] {
            let buffered = try TarArchive.create([
                TarArchive.Entry(name: "e", data: Data(count: n))
            ])
            let streamed = try TarArchive.streamHeader(name: "e", size: Int64(n))
            XCTAssertEqual(Data(buffered.prefix(512)), streamed, "headers differ at size \(n)")
        }
    }

    // MARK: - Substituting for a real stream

    /// The pull-shaped source exists so a multi-file bundle can be encrypted without
    /// being built anywhere first.
    func testSourceFeedsAgeEncryptStream() throws {
        let identity = X25519Identity.generate()
        let a = pattern(120_000, seed: 20)
        let b = pattern(3_000, seed: 21)

        let source = try TarArchive.source([
            TarArchive.StreamEntry(name: "a.bin", size: Int64(a.count)) { InputStream(data: a) },
            TarArchive.StreamEntry(name: "b.bin", size: Int64(b.count)) { InputStream(data: b) },
        ])

        let encrypted = memoryOutput()
        try Age.encryptStream(
            plaintext: source,
            to: [try X25519Recipient(publicKey: identity.publicKey)],
            into: encrypted
        )
        let ciphertext = contents(encrypted)

        let recovered = try Age.decrypt(ciphertext: ciphertext, identities: [identity])
        let entries = try TarArchive.extract(recovered)

        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries[0].name, "a.bin")
        XCTAssertEqual(entries[0].data, a)
        XCTAssertEqual(entries[1].name, "b.bin")
        XCTAssertEqual(entries[1].data, b)
    }

    /// Entries are opened lazily, so a hundred-file archive never has a hundred files
    /// open at once.
    func testSourceOpensEntriesLazily() throws {
        var opened: [String] = []
        let entries = (0..<4).map { i in
            TarArchive.StreamEntry(name: "e\(i)", size: 600) {
                opened.append("e\(i)")
                return InputStream(data: self.pattern(600, seed: UInt8(i)))
            }
        }
        let source = try TarArchive.source(entries)
        XCTAssertEqual(opened, [], "no entry should be opened before reading starts")

        source.open()
        var buf = [UInt8](repeating: 0, count: 600)
        _ = source.read(&buf, maxLength: 600)
        XCTAssertLessThanOrEqual(opened.count, 1, "reading the first header opened later entries")

        _ = try drain(source)
        XCTAssertEqual(opened, ["e0", "e1", "e2", "e3"])
    }
}
