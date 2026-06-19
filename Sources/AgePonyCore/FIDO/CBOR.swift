//
//  CBOR.swift
//  AgePonyCore — FIDO support
//
//  A deliberately small CBOR (RFC 8949) codec covering exactly the subset CTAP2
//  uses: unsigned and negative integers, byte strings, text strings, arrays,
//  maps, booleans, and null. No floats, tags, or indefinite-length items — a
//  FIDO authenticator never sends those in the fields we read, and we never
//  need to produce them.
//
//  Encoding is *canonical* in the CTAP2 sense (CTAP2 §"Message Encoding"):
//  map keys are sorted by the length of their encoded form first, then
//  bytewise. The authenticator rejects non-canonical requests, so this matters
//  for makeCredential / getAssertion. Decoding is order-agnostic and preserves
//  the order it parsed, which is all we need for responses.
//

import Foundation

public enum CBORError: Error, Equatable {
    case truncated
    case unsupportedMajorType(UInt8)
    case unsupportedAdditionalInfo(UInt8)
    case invalidUTF8
    case trailingBytes
}

/// A CBOR value, limited to the CTAP2 subset.
public indirect enum CBOR: Equatable {
    case unsigned(UInt64)
    /// Stores the *encoded* argument `n`; the represented integer is `-1 - n`.
    case negative(UInt64)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    /// Ordered key/value pairs. Canonicalised on encode; preserved on decode.
    case map([(CBOR, CBOR)])
    case bool(Bool)
    case null

    public static func == (lhs: CBOR, rhs: CBOR) -> Bool {
        switch (lhs, rhs) {
        case let (.unsigned(a), .unsigned(b)): return a == b
        case let (.negative(a), .negative(b)): return a == b
        case let (.bytes(a), .bytes(b)): return a == b
        case let (.text(a), .text(b)): return a == b
        case let (.array(a), .array(b)): return a == b
        case let (.map(a), .map(b)):
            guard a.count == b.count else { return false }
            for (x, y) in zip(a, b) where !(x.0 == y.0 && x.1 == y.1) { return false }
            return true
        case let (.bool(a), .bool(b)): return a == b
        case (.null, .null): return true
        default: return false
        }
    }

    // MARK: Convenience constructors / accessors

    /// Build the smallest integer encoding (unsigned or negative).
    public static func int(_ i: Int) -> CBOR {
        i >= 0 ? .unsigned(UInt64(i)) : .negative(UInt64(-1 - i))
    }

    /// The represented integer, for `unsigned` / `negative`; nil otherwise.
    public var intValue: Int? {
        switch self {
        case .unsigned(let v): return Int(exactly: v)
        case .negative(let n): return Int(exactly: n).map { -1 - $0 }
        default: return nil
        }
    }

    public var bytesValue: Data? {
        if case .bytes(let d) = self { return d }
        return nil
    }

    public var textValue: String? {
        if case .text(let s) = self { return s }
        return nil
    }

    /// Look up a value in a `map` by an integer key.
    public func value(forIntKey key: Int) -> CBOR? {
        guard case .map(let pairs) = self else { return nil }
        for (k, v) in pairs where k.intValue == key { return v }
        return nil
    }

    /// Look up a value in a `map` by a text key.
    public func value(forTextKey key: String) -> CBOR? {
        guard case .map(let pairs) = self else { return nil }
        for (k, v) in pairs where k.textValue == key { return v }
        return nil
    }
}

// MARK: - Encoding

public extension CBOR {

    func encoded() -> Data {
        var out = Data()
        encode(into: &out)
        return out
    }

    private func encode(into out: inout Data) {
        switch self {
        case .unsigned(let v):
            CBOR.writeHead(major: 0, value: v, into: &out)
        case .negative(let n):
            CBOR.writeHead(major: 1, value: n, into: &out)
        case .bytes(let d):
            CBOR.writeHead(major: 2, value: UInt64(d.count), into: &out)
            out.append(d)
        case .text(let s):
            let u = Data(s.utf8)
            CBOR.writeHead(major: 3, value: UInt64(u.count), into: &out)
            out.append(u)
        case .array(let items):
            CBOR.writeHead(major: 4, value: UInt64(items.count), into: &out)
            for item in items { item.encode(into: &out) }
        case .map(let pairs):
            CBOR.writeHead(major: 5, value: UInt64(pairs.count), into: &out)
            // CTAP2 canonical ordering: by encoded-key length, then bytewise.
            let sorted = pairs.sorted { a, b in
                let ka = a.0.encoded(), kb = b.0.encoded()
                if ka.count != kb.count { return ka.count < kb.count }
                return ka.lexicographicallyPrecedes(kb)
            }
            for (k, v) in sorted {
                k.encode(into: &out)
                v.encode(into: &out)
            }
        case .bool(let b):
            out.append(b ? 0xF5 : 0xF4)
        case .null:
            out.append(0xF6)
        }
    }

    private static func writeHead(major: UInt8, value: UInt64, into out: inout Data) {
        let m = major << 5
        switch value {
        case ..<24:
            out.append(m | UInt8(value))
        case ..<0x100:
            out.append(m | 24); out.append(UInt8(value))
        case ..<0x1_0000:
            out.append(m | 25)
            out.append(UInt8(value >> 8)); out.append(UInt8(value & 0xFF))
        case ..<0x1_0000_0000:
            out.append(m | 26)
            for shift in stride(from: 24, through: 0, by: -8) {
                out.append(UInt8((value >> UInt64(shift)) & 0xFF))
            }
        default:
            out.append(m | 27)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((value >> UInt64(shift)) & 0xFF))
            }
        }
    }
}

// MARK: - Decoding

/// Cursor-based decoder. `decode()` reads one item and advances `offset`,
/// which lets a caller decode an embedded item (e.g. a COSE key inside
/// authenticatorData) and learn where it ended.
public struct CBORReader {
    private let data: Data
    public private(set) var offset: Int

    public init(_ data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    public var isAtEnd: Bool { offset >= data.endIndex }

    /// Decode a single top-level item and require the input is fully consumed.
    public static func decode(_ data: Data) throws -> CBOR {
        var r = CBORReader(data)
        let v = try r.decode()
        guard r.isAtEnd else { throw CBORError.trailingBytes }
        return v
    }

    private mutating func readByte() throws -> UInt8 {
        guard offset < data.endIndex else { throw CBORError.truncated }
        defer { offset += 1 }
        return data[offset]
    }

    private mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0, offset + count <= data.endIndex else { throw CBORError.truncated }
        let slice = data[offset ..< offset + count]
        offset += count
        return Data(slice)
    }

    private mutating func readArgument(_ info: UInt8) throws -> UInt64 {
        switch info {
        case 0 ..< 24:
            return UInt64(info)
        case 24:
            return UInt64(try readByte())
        case 25:
            return (UInt64(try readByte()) << 8) | UInt64(try readByte())
        case 26:
            var v: UInt64 = 0
            for _ in 0 ..< 4 { v = (v << 8) | UInt64(try readByte()) }
            return v
        case 27:
            var v: UInt64 = 0
            for _ in 0 ..< 8 { v = (v << 8) | UInt64(try readByte()) }
            return v
        default:
            throw CBORError.unsupportedAdditionalInfo(info)
        }
    }

    public mutating func decode() throws -> CBOR {
        let initial = try readByte()
        let major = initial >> 5
        let info = initial & 0x1F

        switch major {
        case 0:
            return .unsigned(try readArgument(info))
        case 1:
            return .negative(try readArgument(info))
        case 2:
            let len = Int(try readArgument(info))
            return .bytes(try readBytes(len))
        case 3:
            let len = Int(try readArgument(info))
            let raw = try readBytes(len)
            guard let s = String(data: raw, encoding: .utf8) else { throw CBORError.invalidUTF8 }
            return .text(s)
        case 4:
            let count = Int(try readArgument(info))
            var items: [CBOR] = []
            items.reserveCapacity(count)
            for _ in 0 ..< count { items.append(try decode()) }
            return .array(items)
        case 5:
            let count = Int(try readArgument(info))
            var pairs: [(CBOR, CBOR)] = []
            pairs.reserveCapacity(count)
            for _ in 0 ..< count {
                let k = try decode()
                let v = try decode()
                pairs.append((k, v))
            }
            return .map(pairs)
        case 7:
            switch info {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22, 23: return .null            // null / undefined
            default: throw CBORError.unsupportedAdditionalInfo(info)
            }
        default:
            throw CBORError.unsupportedMajorType(major)
        }
    }
}
