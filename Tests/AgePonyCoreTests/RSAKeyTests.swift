import XCTest
import Security
@testable import AgePonyCore

final class RSAKeyTests: XCTestCase {
    /// Embedded 2048-bit RSA test fixture (generated with Python cryptography for offline tests).
    static let testPrivPEM = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcnNh
AAAAAwEAAQAAAQEAzkDcssvZS+bgcCPHdIlWEYCZFytzUrfgP9nsCoQuJfE5XY152fW2TS35
HIWqtZ2AqBWj5fv57wgbcjdlVLgtF1JHYLS2xU9CrO6mPB3WCTYD76HCOz78E7cP86yshT1h
2itsar0scWvPkuDzp7xy1j9cCyoSKQHAm5WGYn0sv7+Vyc7isXaGK9Uaxicm6wycCBpouOM9
vnliwpnzgcDbU2Ohwla0QzNnUHjwKL4HjQp+BAbJ97trntKucxmeTSZ5PzIdFz4W4sxgbhJY
OOAHakSFZr9V6wS3XxNpFffJ2sk79X+QKiM8pkfgiYV6AdnugnqvpoD7NNmgeJcSEW+6rQAA
A7icyhTdnMoU3QAAAAdzc2gtcnNhAAABAQDOQNyyy9lL5uBwI8d0iVYRgJkXK3NSt+A/2ewK
hC4l8TldjXnZ9bZNLfkchaq1nYCoFaPl+/nvCBtyN2VUuC0XUkdgtLbFT0Ks7qY8HdYJNgPv
ocI7PvwTtw/zrKyFPWHaK2xqvSxxa8+S4POnvHLWP1wLKhIpAcCblYZifSy/v5XJzuKxdoYr
1RrGJybrDJwIGmi44z2+eWLCmfOBwNtTY6HCVrRDM2dQePAovgeNCn4EBsn3u2ue0q5zGZ5N
Jnk/Mh0XPhbizGBuElg44AdqRIVmv1XrBLdfE2kV98nayTv1f5AqIzymR+CJhXoB2e6Ceq+m
gPs02aB4lxIRb7qtAAAAAwEAAQAAAQATJJdXS5mSHzjwL4yblwOTVvQz36cxzjnUs003zKeG
g1USXHHVdlDCk7nDQ+9hhooiZPUeq2cPIG7WXaiHVxttnAgJRGc8+OufUVHB0qMYR8MlwpsH
FK7LcE+IC5wXjGhAmjcoe6uxpef7d0AmGVTZ6Gzf5w+4bp6J0jRJf9oKEdC+dscWhkPI3zrN
3gJJ9BbczcC7T4euKAZa0md+4xQPvRbN55eXwkxFB/pS0RmC/uLqH1VBjA/R9Q51E7UAABz8
PLE6wddJWkwcI7g6Y6UHb04EAamrZogn1FqrR4fwP909eywSxPQuQhjjTu/FuoDsvegzodQk
iapS+d/Cax2hAAAAgBoAY1QVg0ZLXE04Q6NokbAgenvOxOVjihaMGEkdrKDGQh9WOFqghnCl
tvVacZyfKlI4bJNmDSX83ASqzL4gT3mVXQSsQ6MUSPKTbydrWZFaBr+a/gbkcEq3a7lnF5Bl
IJ7QpHohqWl2wHKfCng+52HTOl3wemSEmn6AmAw0IWjSAAAAgQDqFPs8kuj5HQ3RQAMFijvt
PV+q1izUWojzZloEIb5zj7OpgcIL7XuVOWf0WkPXhvkd121P292WCUrNoO7vlyeahAruoJyd
NYvGtBiDTHOiKSsEozHypq1s9B+QNLyAGMoQ9i6wM2mz3deJHSZhec0XZhLdO9M/IGu/IVXG
9hAiFwAAAIEA4ZDSEYaz8wAPvwpQyrywU2XdE3k0NaMGlEbk0VrZxAMpdywcHTHy6MoCTvb2
BW2HToLsVHlpgUT3wWsozKIHE9uhK+e+O5cwNZHN4KzZgk4MXfHq3LZ4z3smBZA4WM5Zu3BQ
zzc28OkrsRfeWVEvdtkdp0FKwYkhRidhRsYRl9sAAAAAAQID
-----END OPENSSH PRIVATE KEY-----
"""

    static let testPubLine = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOQNyyy9lL5uBwI8d0iVYRgJkXK3NSt+A/2ewKhC4l8TldjXnZ9bZNLfkchaq1nYCoFaPl+/nvCBtyN2VUuC0XUkdgtLbFT0Ks7qY8HdYJNgPvocI7PvwTtw/zrKyFPWHaK2xqvSxxa8+S4POnvHLWP1wLKhIpAcCblYZifSy/v5XJzuKxdoYr1RrGJybrDJwIGmi44z2+eWLCmfOBwNtTY6HCVrRDM2dQePAovgeNCn4EBsn3u2ue0q5zGZ5NJnk/Mh0XPhbizGBuElg44AdqRIVmv1XrBLdfE2kV98nayTv1f5AqIzymR+CJhXoB2e6Ceq+mgPs02aB4lxIRb7qt test@agepony"

    func testMakePublic_fromTestFixture() throws {
        let parts = try SSHRSAKeyParser.parsePublicKey(Self.testPubLine)
        let key = try RSAKey.makePublic(n: parts.n, e: parts.e)
        XCTAssertEqual(SecKeyGetBlockSize(key), 256)  // 2048 bits = 256 bytes
        // Verify it can be used for raw encryption (textbook RSA)
        let m = Data(repeating: 0x01, count: 256)
        m.withUnsafeBytes { _ in }  // sanity
        var err: Unmanaged<CFError>?
        let result = SecKeyCreateEncryptedData(key, .rsaEncryptionRaw, Data(repeating: 0x00, count: 256) as CFData, &err)
        XCTAssertNotNil(result)
    }

    func testMakePrivate_fromTestFixture() throws {
        let parts = try SSHRSAKeyParser.parseOpenSSHPrivateKey(Self.testPrivPEM)
        let priv = try RSAKey.makePrivate(
            n: parts.n, e: parts.e, d: parts.d, p: parts.p, q: parts.q, iqmp: parts.iqmp
        )
        XCTAssertEqual(SecKeyGetBlockSize(priv), 256)
    }

    /// Verify that a public+private pair from the same OpenSSH PEM round-trips
    /// a textbook RSA operation: encrypt with pub → decrypt with priv → original.
    func testPublicPrivatePair_textbookRoundTrip() throws {
        let parts = try SSHRSAKeyParser.parseOpenSSHPrivateKey(Self.testPrivPEM)
        let pub = try RSAKey.makePublic(n: parts.n, e: parts.e)
        let priv = try RSAKey.makePrivate(
            n: parts.n, e: parts.e, d: parts.d, p: parts.p, q: parts.q, iqmp: parts.iqmp
        )
        // Textbook RSA: encrypt a value m in [0, n). For safety use a small message padded with zeros.
        var input = Data(repeating: 0, count: 256)
        for i in 200..<256 { input[i] = UInt8(i - 200) }
        var err: Unmanaged<CFError>?
        guard let ct = SecKeyCreateEncryptedData(pub, .rsaEncryptionRaw, input as CFData, &err) as Data? else {
            return XCTFail("encrypt failed: \(String(describing: err?.takeRetainedValue()))")
        }
        guard let pt = SecKeyCreateDecryptedData(priv, .rsaEncryptionRaw, ct as CFData, &err) as Data? else {
            return XCTFail("decrypt failed: \(String(describing: err?.takeRetainedValue()))")
        }
        // SecKey raw decrypt may strip leading zero bytes; pad before compare
        var padded = pt
        if padded.count < 256 {
            padded = Data(repeating: 0, count: 256 - padded.count) + padded
        }
        XCTAssertEqual(padded, input)
    }
}
