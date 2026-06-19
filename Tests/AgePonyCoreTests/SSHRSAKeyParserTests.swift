import XCTest
@testable import AgePonyCore

final class SSHRSAKeyParserTests: XCTestCase {
    func testParsePublicKey_testFixture() throws {
        let parts = try SSHRSAKeyParser.parsePublicKey(RSAKeyTests.testPubLine)
        // e = 65537 (0x010001)
        XCTAssertEqual(parts.e, Data([0x01, 0x00, 0x01]))
        // n is 2048 bits = 256 bytes
        XCTAssertEqual(parts.n.count, 256)
        // First byte of n from the fixture: 0xce
        XCTAssertEqual(parts.n.first, 0xce)
        XCTAssertEqual(parts.comment, "test@agepony")
        // wireBlob is the base64-decoded blob; first 4 bytes are length-11 BE of "ssh-rsa"
        XCTAssertEqual(parts.wireBlob.prefix(4), Data([0x00, 0x00, 0x00, 0x07]))
    }

    func testParsePublicKey_rejectsWrongType() {
        let line = "ssh-ed25519 AAAA other"
        XCTAssertThrowsError(try SSHRSAKeyParser.parsePublicKey(line)) { error in
            guard case SSHRSAKeyParserError.wrongKeyType = error else {
                return XCTFail("expected wrongKeyType, got \(error)")
            }
        }
    }

    func testParsePublicKey_rejectsMalformedBase64() {
        let line = "ssh-rsa !@#$ test"
        XCTAssertThrowsError(try SSHRSAKeyParser.parsePublicKey(line))
    }

    func testParseOpenSSHPrivateKey_testFixture() throws {
        let parts = try SSHRSAKeyParser.parseOpenSSHPrivateKey(RSAKeyTests.testPrivPEM)
        // Match against pre-extracted expected values from Python cryptography:
        //   d_first8   = 132497574b99921f
        //   p_first8   = ea14fb3c92e8f91d
        //   q_first8   = e190d21186b3f300
        //   iqmp_first8 = 1a0063541583464b
        XCTAssertEqual(parts.d.prefix(8).map { String(format: "%02x", $0) }.joined(),
                       "132497574b99921f")
        XCTAssertEqual(parts.p.prefix(8).map { String(format: "%02x", $0) }.joined(),
                       "ea14fb3c92e8f91d")
        XCTAssertEqual(parts.q.prefix(8).map { String(format: "%02x", $0) }.joined(),
                       "e190d21186b3f300")
        XCTAssertEqual(parts.iqmp.prefix(8).map { String(format: "%02x", $0) }.joined(),
                       "1a0063541583464b")
        // n == pub.n
        let pubParts = try SSHRSAKeyParser.parsePublicKey(RSAKeyTests.testPubLine)
        XCTAssertEqual(parts.n, pubParts.n)
        XCTAssertEqual(parts.e, pubParts.e)
    }

    func testParseOpenSSHPrivateKey_acceptsCRLF() throws {
        let crlf = RSAKeyTests.testPrivPEM.replacingOccurrences(of: "\n", with: "\r\n")
        XCTAssertNoThrow(try SSHRSAKeyParser.parseOpenSSHPrivateKey(crlf))
    }

    func testParseOpenSSHPrivateKey_rejectsMissingFraming() {
        // Strip the BEGIN line
        let bad = RSAKeyTests.testPrivPEM
            .replacingOccurrences(of: "-----BEGIN OPENSSH PRIVATE KEY-----\n", with: "")
        XCTAssertThrowsError(try SSHRSAKeyParser.parseOpenSSHPrivateKey(bad))
    }

    func testWireBlobIsConsistentBetweenPubAndPriv() throws {
        // The wireBlob in the parsed private key should match the wireBlob from the pub line
        let priv = try SSHRSAKeyParser.parseOpenSSHPrivateKey(RSAKeyTests.testPrivPEM)
        let pub = try SSHRSAKeyParser.parsePublicKey(RSAKeyTests.testPubLine)
        XCTAssertEqual(priv.wireBlob, pub.wireBlob)
    }
}
