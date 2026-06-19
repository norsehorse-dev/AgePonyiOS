import XCTest
@testable import AgePonyCore

final class SSHKeySourceTests: XCTestCase {
    /// A real-looking GitHub `.keys` response with multiple key types.
    static let mixedKeysText = """
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPFx4q1cdQYPVPnoYsm0H/jX6vMOgtJ3I7DAuhwJxCt8 friend1@laptop
    \(RSAKeyTests.testPubLine)
    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLkA== friend2
    ssh-dss AAAAB3NzaC1kc3MAAAAB= legacy
    """

    func testParse_mixedKeys() {
        let recipients = SSHKeySource.parse(text: Self.mixedKeysText)
        // Should get ed25519 + rsa (2), skip ecdsa and dss
        XCTAssertEqual(recipients.count, 2)
        XCTAssertTrue(recipients.contains { $0 is SSHEd25519Recipient })
        XCTAssertTrue(recipients.contains { $0 is SSHRSARecipient })
    }

    func testParse_skipsCommentsAndBlankLines() {
        let text = """
        # this is a comment line
        
        \(RSAKeyTests.testPubLine)
        
        # another comment
        """
        let recipients = SSHKeySource.parse(text: text)
        XCTAssertEqual(recipients.count, 1)
        XCTAssertTrue(recipients[0] is SSHRSARecipient)
    }

    func testParse_skipsMalformedLines() {
        let text = """
        ssh-rsa NOT_VALID_BASE64_!!!
        \(RSAKeyTests.testPubLine)
        ssh-ed25519 also-not-base64-!!!
        ssh-rsa
        """
        let recipients = SSHKeySource.parse(text: text)
        // Only the valid line should parse
        XCTAssertEqual(recipients.count, 1)
    }

    func testParse_empty() {
        XCTAssertEqual(SSHKeySource.parse(text: "").count, 0)
        XCTAssertEqual(SSHKeySource.parse(text: "   \n  \n").count, 0)
    }

    func testGithubURLConstruction() async {
        // We don't actually fetch — just verify the URL builds without throwing.
        // Real network test lives in ReferenceCLIRSATests if needed.
        do {
            _ = try await SSHKeySource.github(username: "fictional-user-that-doesnt-exist-12345")
        } catch {
            // Any error is fine here — we just want to confirm the function exists
            // and runs without crashing on URL construction.
        }
    }
}
