import XCTest
@testable import AgePonyCore

final class BcryptPBKDFTests: XCTestCase {
    /// OpenBSD `regress/lib/libutil/bcrypt_pbkdf` vectors (also matches Python `bcrypt.kdf`).
    /// password="password", salt="salt", rounds=4, keylen=32 →
    ///   5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9
    func testKAT_password_salt_4rounds_32bytes() throws {
        let derived = try BcryptPBKDF.bcryptPBKDF(
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            rounds: 4,
            keylen: 32
        )
        XCTAssertEqual(derived.map { String(format: "%02x", $0) }.joined(),
                       "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9")
    }

    /// password="password", salt="salt", rounds=8, keylen=32 →
    ///   e17e1533acc14423155493c99b9c3bbe62ea0884207a7802e7ba72eff94d085e
    func testKAT_password_salt_8rounds_32bytes() throws {
        let derived = try BcryptPBKDF.bcryptPBKDF(
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            rounds: 8,
            keylen: 32
        )
        XCTAssertEqual(derived.map { String(format: "%02x", $0) }.joined(),
                       "e17e1533acc14423155493c99b9c3bbe62ea0884207a7802e7ba72eff94d085e")
    }

    /// password="password\0" + 32-byte salt, rounds=8, keylen=32 →
    ///   994bd970b0f190b5ad45bb6a292e82fdc83d7e077877479b08395f3fa58504cc
    func testKAT_passwordWithNull_longSalt() throws {
        let pwd = Data([0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00])  // "password\0"
        let salt = Data([
            0xa3, 0x9b, 0xa0, 0xa1, 0xed, 0x57, 0x91, 0x83, 0xc7, 0xc7, 0xfc, 0x69,
            0xff, 0x90, 0xd5, 0xd2, 0xa4, 0x73, 0xdd, 0xee, 0x1d, 0xb1, 0xc7, 0xea,
            0x6f, 0xae, 0xcb, 0x12, 0xe7, 0x36, 0x99, 0xb2
        ])
        let derived = try BcryptPBKDF.bcryptPBKDF(
            password: pwd, salt: salt, rounds: 8, keylen: 32
        )
        XCTAssertEqual(derived.map { String(format: "%02x", $0) }.joined(),
                       "994bd970b0f190b5ad45bb6a292e82fdc83d7e077877479b08395f3fa58504cc")
    }

    /// Vector specific to our embedded test PEM (the salt+rounds extracted from it,
    /// verified against `bcrypt.kdf` in Python).
    /// passphrase="agepony-test-passphrase", salt=<16B from PEM>, rounds=16, keylen=48 (aes256 key+iv) →
    ///   key (32B): 27b53cae33b083b21632aae07d559a1b0ee995bb127b5965c941a85bb590e3e5
    ///   iv  (16B): 9e683bdcbb12f444c1c01946bf5d71fe
    func testKAT_testPEMVector_aes256() throws {
        let salt = Data([0x4f, 0x24, 0x3f, 0xb9, 0x1d, 0x04, 0x9b, 0xd7,
                         0xc6, 0xec, 0x57, 0x14, 0xa8, 0x63, 0xed, 0xf1])
        let derived = try BcryptPBKDF.bcryptPBKDF(
            password: Data("agepony-test-passphrase".utf8),
            salt: salt,
            rounds: 16,
            keylen: 48
        )
        let hex = derived.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex,
            "27b53cae33b083b21632aae07d559a1b0ee995bb127b5965c941a85bb590e3e5"
            + "9e683bdcbb12f444c1c01946bf5d71fe")
    }

    func testRejectsZeroRounds() {
        XCTAssertThrowsError(try BcryptPBKDF.bcryptPBKDF(
            password: Data("x".utf8), salt: Data("y".utf8), rounds: 0, keylen: 32))
    }

    func testRejectsEmptyPassword() {
        XCTAssertThrowsError(try BcryptPBKDF.bcryptPBKDF(
            password: Data(), salt: Data("y".utf8), rounds: 4, keylen: 32))
    }

    func testRejectsEmptySalt() {
        XCTAssertThrowsError(try BcryptPBKDF.bcryptPBKDF(
            password: Data("x".utf8), salt: Data(), rounds: 4, keylen: 32))
    }
}
