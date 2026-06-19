//
//  SSHWireFormat.swift
//  AgePonyCore
//
//  Reader for the SSH wire format defined in RFC 4251 §5.
//
//  The wire format uses simple length-prefixed encoding. The two types we
//  actually need to parse for age v1 are:
//
//    string:   4-byte big-endian length, then that many bytes
//    uint32:   4 bytes big-endian
//
//  (For ssh-rsa support in slice 1b-2 we'll also need `mpint`, which is a
//  string interpreted as a two's-complement big-endian integer.)
//

import Foundation

public enum SSHWireFormatError: Error, Equatable {
    case unexpectedEnd
    case lengthTooLarge
}

/// Read-only cursor over SSH wire-format bytes.
public struct SSHWireReader {
    public let data: Data
    public private(set) var offset: Int

    public init(_ data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    public var remaining: Int { data.endIndex - offset }
    public var isAtEnd: Bool { offset >= data.endIndex }

    /// Read a single byte.
    public mutating func readByte() throws -> UInt8 {
        guard offset < data.endIndex else { throw SSHWireFormatError.unexpectedEnd }
        let b = data[offset]
        offset += 1
        return b
    }

    /// Read a 4-byte big-endian uint32.
    public mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= data.endIndex else { throw SSHWireFormatError.unexpectedEnd }
        let v = (UInt32(data[offset    ]) << 24)
              | (UInt32(data[offset + 1]) << 16)
              | (UInt32(data[offset + 2]) <<  8)
              | (UInt32(data[offset + 3]))
        offset += 4
        return v
    }

    /// Read an SSH "string": uint32 length-prefix followed by that many bytes.
    public mutating func readString() throws -> Data {
        let len = try readUInt32()
        // Guard against absurd lengths.
        guard Int(len) <= remaining else {
            throw SSHWireFormatError.lengthTooLarge
        }
        let n = Int(len)
        let bytes = data.subdata(in: offset..<(offset + n))
        offset += n
        return bytes
    }

    /// Read N raw bytes (no length prefix).
    public mutating func readBytes(_ count: Int) throws -> Data {
        guard count <= remaining else { throw SSHWireFormatError.unexpectedEnd }
        let bytes = data.subdata(in: offset..<(offset + count))
        offset += count
        return bytes
    }
}

/// Builder for SSH wire-format bytes.
public struct SSHWireWriter {
    public private(set) var data: Data

    public init() {
        self.data = Data()
    }

    public mutating func writeByte(_ b: UInt8) {
        data.append(b)
    }

    public mutating func writeUInt32(_ v: UInt32) {
        data.append(UInt8((v >> 24) & 0xff))
        data.append(UInt8((v >> 16) & 0xff))
        data.append(UInt8((v >>  8) & 0xff))
        data.append(UInt8( v        & 0xff))
    }

    public mutating func writeString(_ s: Data) {
        writeUInt32(UInt32(s.count))
        data.append(s)
    }

    public mutating func writeString(_ s: String) {
        writeString(Data(s.utf8))
    }
}
