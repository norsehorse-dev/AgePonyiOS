import Foundation
import CryptoKit

/// CTAP2 **PIN/UV auth protocol one** — the cryptographic half of talking to a
/// FIDO security key that has a PIN set (a YubiKey with a FIDO2 PIN, a Token2,
/// and similar). The UP-only path used elsewhere can't enrol or sign on a
/// PIN-protected key; this protocol is what unblocks them.
///
/// The shape of the protocol (all values little-endian-free, raw bytes):
///
///   1. Ask the authenticator for its key-agreement public key (a COSE P-256
///      key — `getKeyAgreement`, handled in the command layer).
///   2. Generate a platform ephemeral P-256 key pair.
///   3. Derive a 32-byte **shared secret** = SHA-256( ECDH-x ), where ECDH-x is
///      the x-coordinate of platform-private × authenticator-public. (CryptoKit's
///      P-256 `SharedSecret` *is* that x-coordinate, so we hash it directly.)
///   4. `encrypt` / `decrypt` use AES-256-CBC with the shared secret as the key
///      and an **all-zero IV**, no padding.
///   5. `authenticate` is HMAC-SHA-256 truncated to its first 16 bytes — used
///      both for the PIN hash exchange and to authorise each makeCredential /
///      getAssertion with the obtained PIN token.
///
/// Everything here is pure and reference-tested; no hardware or transport.
public enum PinProtocolV1 {

    /// The protocol identifier the authenticator expects in clientPin requests
    /// and in the `pinUvAuthProtocol` field of makeCredential / getAssertion.
    public static let version: Int = 1

    /// All-zero 16-byte IV used for every AES-CBC operation in this protocol.
    public static let zeroIV = Data(repeating: 0, count: 16)

    // MARK: - Key agreement

    /// A freshly generated platform ephemeral key pair: the private key (kept to
    /// derive the shared secret) and the public key as an X9.63 `04 || X || Y`
    /// blob (handed to the authenticator, COSE-encoded, in `getPinToken`).
    public static func generatePlatformKeyPair() -> (private: P256.KeyAgreement.PrivateKey, publicX963: Data) {
        let priv = P256.KeyAgreement.PrivateKey()
        return (priv, priv.publicKey.x963Representation)
    }

    /// Derive the shared secret from the platform private key and the
    /// authenticator's key-agreement public key (X9.63 `04 || X || Y`).
    /// Returns SHA-256 of the ECDH x-coordinate (32 bytes).
    public static func sharedSecret(
        platformPrivate: P256.KeyAgreement.PrivateKey,
        authenticatorPublicX963: Data
    ) throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: authenticatorPublicX963)
        let ecdh = try platformPrivate.sharedSecretFromKeyAgreement(with: peer)
        let x = ecdh.withUnsafeBytes { Data($0) }   // the 32-byte x-coordinate
        return Data(SHA256.hash(data: x))
    }

    // MARK: - Encrypt / decrypt (AES-256-CBC, zero IV, no padding)

    public static func encrypt(sharedSecret: Data, plaintext: Data) throws -> Data {
        try AESCBC.encrypt(key: sharedSecret, iv: zeroIV, input: plaintext)
    }

    public static func decrypt(sharedSecret: Data, ciphertext: Data) throws -> Data {
        try AESCBC.decrypt(key: sharedSecret, iv: zeroIV, input: ciphertext)
    }

    // MARK: - Authenticate (truncated HMAC-SHA-256)

    /// HMAC-SHA-256(`key`, `message`) truncated to its first 16 bytes — the
    /// protocol-one MAC. Used for `pinUvAuthParam` over the clientDataHash.
    public static func authenticate(key: Data, message: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(Data(mac).prefix(16))
    }

    // MARK: - PIN hash exchange

    /// The encrypted PIN hash sent in `getPinToken`:
    /// AES-256-CBC( sharedSecret, iv=0, LEFT(SHA-256(PIN-UTF8), 16) ).
    public static func pinHashEnc(sharedSecret: Data, pin: String) throws -> Data {
        let pinHash16 = Data(SHA256.hash(data: Data(pin.utf8))).prefix(16)
        return try encrypt(sharedSecret: sharedSecret, plaintext: Data(pinHash16))
    }

    /// Decrypt the PIN token returned by `getPinToken`.
    public static func decryptPinToken(sharedSecret: Data, pinTokenEnc: Data) throws -> Data {
        try decrypt(sharedSecret: sharedSecret, ciphertext: pinTokenEnc)
    }

    /// `pinUvAuthParam` for a makeCredential / getAssertion request:
    /// LEFT( HMAC-SHA-256(pinToken, clientDataHash), 16 ).
    public static func pinUvAuthParam(pinToken: Data, clientDataHash: Data) -> Data {
        authenticate(key: pinToken, message: clientDataHash)
    }
}
