import Foundation

extension SSHRSAIdentity {
    /// Construct an RSA identity from a passphrase-protected (or unencrypted) OpenSSH PEM.
    /// If the PEM is unencrypted, `passphrase` is ignored.
    ///
    /// Implementation: synthesize a `cipher=none, kdf=none` PEM from the decrypted contents
    /// and feed it to the existing `init(openSSHPrivateKey:)` parser. No duplication of the
    /// envelope-parsing logic; we just bypass the cipher layer when needed.
    public init(openSSHPrivateKey pem: String, passphrase: String?) throws {
        let unencrypted = try OpenSSHEncryptedKey.decryptedPEM(pem: pem, passphrase: passphrase)
        try self.init(openSSHPrivateKey: unencrypted)
    }
}
