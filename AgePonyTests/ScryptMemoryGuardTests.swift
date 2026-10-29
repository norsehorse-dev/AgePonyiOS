//
//  ScryptMemoryGuardTests.swift
//  AgePonyTests
//
//  5.1.1 (L-2): a passphrase decrypt refuses a scrypt work factor that won't fit
//  in memory before it derives anything. The header is rewritten to ask for
//  2^22 (4 GiB); nothing here runs scrypt at that size: `fits` refuses first.
//

import XCTest
import AgePonyCore
@testable import AgePony

@MainActor
final class ScryptMemoryGuardTests: XCTestCase {

    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ScryptGuard-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    /// A real passphrase file at 2^10, with the work factor in its header
    /// rewritten. The MAC no longer matches, which doesn't matter: the guard
    /// reads the stanzas only.
    private func passphraseFile(workFactor: Int) throws -> Data {
        var file = try Age.encrypt(plaintext: Data("secret".utf8), passphrase: "pw", workFactor: 10)
        guard workFactor != 10 else { return file }
        let range = try XCTUnwrap(file.range(of: Data(" 10\n".utf8)))
        file.replaceSubrange(range, with: Data(" \(workFactor)\n".utf8))
        return file
    }

    private func write(_ data: Data, _ name: String) throws -> URL {
        let url = dir.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    private func assertWontFit(_ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            guard case .scryptWontFit(let message)? = error as? FileEncryptorError else {
                return XCTFail("expected scryptWontFit, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(message.contains("2^22"), message, file: file, line: line)
        }
    }

    func testBinaryFileRefusedBeforeDeriving() throws {
        let url = try write(try passphraseFile(workFactor: 22), "big.age")
        var asked: [Int] = []
        assertWontFit {
            try FileEncryptor.checkScryptMemory(inputURL: url, armored: false) { asked.append($0); return $0 < 22 }
        }
        XCTAssertEqual(asked, [22])
    }

    func testArmoredFileRefusedBeforeDeriving() throws {
        let armored = AgeArmor.encode(try passphraseFile(workFactor: 22))
        let url = try write(Data(armored.utf8), "big.age")
        assertWontFit {
            try FileEncryptor.checkScryptMemory(inputURL: url, armored: true) { $0 < 22 }
        }
    }

    func testFittingWorkFactorPasses() throws {
        let url = try write(try passphraseFile(workFactor: 10), "small.age")
        XCTAssertNoThrow(try FileEncryptor.checkScryptMemory(inputURL: url, armored: false) { $0 < 22 })
    }

    func testKeyFileIsNotAsked() throws {
        let id = X25519Identity.generate()
        let file = try Age.encrypt(plaintext: Data("x".utf8), to: [try X25519Recipient(publicKey: id.publicKey)])
        let url = try write(file, "key.age")
        var asked = 0
        XCTAssertNoThrow(try FileEncryptor.checkScryptMemory(inputURL: url, armored: false) { _ in asked += 1; return false })
        XCTAssertEqual(asked, 0)
    }

    func testMalformedWorkFactorIsLeftToTheCore() throws {
        let salt = Data(count: 16).base64EncodedString().replacingOccurrences(of: "=", with: "")
        for arg in ["+5", "022", "", "abc", "100"] {
            let stanza = Stanza(type: "scrypt", args: [salt, arg], body: Data(count: 32))
            XCTAssertNoThrow(try FileEncryptor.checkScryptMemory(stanzas: [stanza]) { _ in false }, arg)
        }
    }

    /// Text decrypt runs the same check on the buffered header.
    func testTextDecryptRefusedBeforeDeriving() throws {
        let binary = try passphraseFile(workFactor: 22)
        var asked: [Int] = []
        assertWontFit {
            _ = try TextDecryptor.decrypt(
                binary: binary, identities: [], passphrase: "pw",
                storedIdentities: [], recipients: [], signers: [],
                scryptFits: { asked.append($0); return false }
            )
        }
        XCTAssertEqual(asked, [22])
    }
}
