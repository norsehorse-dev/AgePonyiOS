import Foundation

/// Minimal ASN.1 DER encoder: just `INTEGER` and `SEQUENCE` since that's all
/// PKCS#1 RSAPublicKey / RSAPrivateKey need.
public enum ASN1DER {
    /// DER-encode a non-negative integer from big-endian bytes.
    /// - Strips leading zeros (DER requires minimal encoding).
    /// - Prepends `0x00` if the high bit of the resulting first byte is set (so it parses as positive).
    /// - Encodes an all-zero input as `INTEGER 0` (one content byte: `0x00`).
    public static func integer(_ bigEndianBytes: Data) -> Data {
        var stripped = bigEndianBytes
        while stripped.count > 1, stripped.first == 0 {
            stripped = stripped.dropFirst()
        }
        // Empty input or single 0 byte → INTEGER 0
        if stripped.isEmpty {
            return Data([0x02, 0x01, 0x00])
        }
        var contents = Data(stripped)
        if let first = contents.first, first & 0x80 != 0 {
            contents = Data([0x00]) + contents
        }
        return Data([0x02]) + length(contents.count) + contents
    }

    /// Wrap arbitrary contents in a constructed `SEQUENCE` (tag `0x30`).
    public static func sequence(_ contents: Data) -> Data {
        return Data([0x30]) + length(contents.count) + contents
    }

    /// DER length encoding: short form for `< 128`, long form otherwise.
    public static func length(_ n: Int) -> Data {
        precondition(n >= 0, "negative length")
        if n < 0x80 {
            return Data([UInt8(n)])
        }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 {
            bytes.append(UInt8(v & 0xff))
            v >>= 8
        }
        bytes.reverse()
        return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
    }
}
