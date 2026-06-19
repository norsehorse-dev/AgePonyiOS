import XCTest
import CryptoKit
@testable import AgePonyCore

final class TarArchiveTests: XCTestCase {

    private func sha256Hex(_ d: Data) -> String {
        SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
    }

    private let entries: [TarArchive.Entry] = [
        TarArchive.Entry(name: "a.txt", data: Data("hello\n".utf8)),
        TarArchive.Entry(name: "b.bin", data: Data((0..<8).map { UInt8($0) })),
    ]

    /// Byte-for-byte match with Python tarfile (USTAR_FORMAT), compact form:
    /// mtime 0, mode 0644, uid/gid 0, empty uname/gname, two-zero-block trailer.
    func testCreate_matchesPythonReference() throws {
        let tar = try TarArchive.create(entries)
        XCTAssertEqual(tar.count, 3072)
        XCTAssertEqual(sha256Hex(tar),
                       "114a63e3d94be5ba8d9e1addaa4e68a72fb4a1bf7d4dc41ee78cc4fc4f3df2fe")
    }

    func testRoundTrip() throws {
        let tar = try TarArchive.create(entries)
        let back = try TarArchive.extract(tar)
        XCTAssertEqual(back, entries)
    }

    func testRoundTrip_emptyAndOddSizes() throws {
        let e = [
            TarArchive.Entry(name: "empty", data: Data()),
            TarArchive.Entry(name: "one", data: Data([0x41])),
            TarArchive.Entry(name: "block", data: Data(repeating: 0x42, count: 512)),
            TarArchive.Entry(name: "over", data: Data(repeating: 0x43, count: 513)),
        ]
        XCTAssertEqual(try TarArchive.extract(try TarArchive.create(e)), e)
    }

    func testStructure_magicAndType() throws {
        let tar = [UInt8](try TarArchive.create(entries))
        XCTAssertEqual(Array(tar[257..<262]), Array("ustar".utf8))
        XCTAssertEqual(tar[156], 0x30)                      // typeflag regular
        XCTAssertEqual(tar[0..<5].map { $0 }, Array("a.txt".utf8))
    }

    func testNameTooLong_throws() {
        let long = String(repeating: "x", count: 101)
        XCTAssertThrowsError(
            try TarArchive.create([TarArchive.Entry(name: long, data: Data())]))
    }

    func testBadChecksum_throws() throws {
        var tar = [UInt8](try TarArchive.create(entries))
        tar[0] = tar[0] &+ 1                                 // corrupt the name byte
        XCTAssertThrowsError(try TarArchive.extract(Data(tar))) { error in
            XCTAssertEqual(error as? TarArchiveError, .badChecksum)
        }
    }
}
