import Foundation

/// Extensions on the existing `SSHWireReader` / `SSHWireWriter` to handle SSH's mpint
/// (multi-precision integer) format. Per RFC 4251 §5: an mpint is a length-prefixed
/// big-endian two's-complement integer. For positive numbers whose high bit is set,
/// a leading `0x00` byte is prepended to disambiguate from a negative value. We treat
/// all RSA values as non-negative and strip that leading zero on read / add it on write.
extension SSHWireReader {
    /// Read an mpint and return the canonical big-endian, leading-zero-stripped bytes.
    public mutating func readMPInt() throws -> Data {
        let raw = try readString()
        // Strip the optional 0x00 sign-bit marker
        if raw.count > 1, raw.first == 0 {
            return Data(raw.dropFirst())
        }
        return raw
    }
}

extension SSHWireWriter {
    /// Write a non-negative value as an mpint, prepending `0x00` if the high bit is set.
    public mutating func writeMPInt(_ value: Data) {
        // Strip any caller-supplied leading zeros for canonical encoding
        var v = value
        while v.count > 1, v.first == 0 {
            v = v.dropFirst()
        }
        if v.isEmpty {
            writeUInt32(0)
            return
        }
        if let first = v.first, first & 0x80 != 0 {
            writeString(Data([0x00]) + v)
        } else {
            writeString(Data(v))
        }
    }
}
