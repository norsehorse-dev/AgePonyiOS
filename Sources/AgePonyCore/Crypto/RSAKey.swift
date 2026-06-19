import Foundation
import Security

public enum RSAKeyError: Error {
    case secKeyCreationFailed(String)
    case invalidKeyComponent
}

/// Build `SecKey` objects from raw RSA components. The OpenSSH ssh-rsa private key format
/// stores `(n, e, d, iqmp, p, q)` but Apple's `SecKeyCreateWithData` needs PKCS#1
/// `RSAPrivateKey` which requires the CRT extras `exp1 = d mod (p-1)` and `exp2 = d mod (q-1)`
/// — we compute those via `BigUInt.mod` and DER-encode the result.
public enum RSAKey {
    /// Construct a public `SecKey` from big-endian `n` and `e` byte arrays.
    public static func makePublic(n: Data, e: Data) throws -> SecKey {
        guard !n.isEmpty, !e.isEmpty else { throw RSAKeyError.invalidKeyComponent }
        let der = ASN1DER.sequence(
            ASN1DER.integer(n) + ASN1DER.integer(e)
        )
        let nBits = bitLength(of: n)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: nBits,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &error) else {
            let msg = (error?.takeRetainedValue()).map { (CFErrorCopyDescription($0) as String) } ?? "unknown"
            throw RSAKeyError.secKeyCreationFailed("public: " + msg)
        }
        return key
    }

    /// Construct a private `SecKey` from the six components stored in the OpenSSH ssh-rsa wire format.
    /// Computes the missing PKCS#1 CRT fields `exp1`, `exp2` internally.
    public static func makePrivate(n: Data, e: Data, d: Data, p: Data, q: Data, iqmp: Data) throws -> SecKey {
        guard !n.isEmpty, !e.isEmpty, !d.isEmpty, !p.isEmpty, !q.isEmpty, !iqmp.isEmpty else {
            throw RSAKeyError.invalidKeyComponent
        }
        // exp1 = d mod (p - 1), exp2 = d mod (q - 1)
        let pBI = BigUInt(bigEndianBytes: p)
        let qBI = BigUInt(bigEndianBytes: q)
        let dBI = BigUInt(bigEndianBytes: d)
        let pm1 = BigUInt.subtractOne(pBI)
        let qm1 = BigUInt.subtractOne(qBI)
        let exp1 = dBI.mod(pm1).toBigEndianBytes()
        let exp2 = dBI.mod(qm1).toBigEndianBytes()

        var contents = Data()
        contents.append(ASN1DER.integer(Data([0x00])))  // version = 0
        contents.append(ASN1DER.integer(n))
        contents.append(ASN1DER.integer(e))
        contents.append(ASN1DER.integer(d))
        contents.append(ASN1DER.integer(p))
        contents.append(ASN1DER.integer(q))
        contents.append(ASN1DER.integer(exp1))
        contents.append(ASN1DER.integer(exp2))
        contents.append(ASN1DER.integer(iqmp))
        let der = ASN1DER.sequence(contents)

        let nBits = bitLength(of: n)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: nBits,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &error) else {
            let msg = (error?.takeRetainedValue()).map { (CFErrorCopyDescription($0) as String) } ?? "unknown"
            throw RSAKeyError.secKeyCreationFailed("private: " + msg)
        }
        return key
    }

    /// Exact bit length of a big-endian byte array, ignoring leading zeros.
    static func bitLength(of bytes: Data) -> Int {
        var stripped = bytes
        while stripped.count > 1, stripped.first == 0 {
            stripped = stripped.dropFirst()
        }
        guard let first = stripped.first, first != 0 else { return 0 }
        let topBits = 8 - first.leadingZeroBitCount
        return (stripped.count - 1) * 8 + topBits
    }
}
