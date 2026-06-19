//
//  TarArchive.swift
//  AgePonyCore — archiving
//
//  A minimal, dependency-free USTAR (POSIX tar) writer and reader, covering
//  exactly what AgePony needs: bundle several files into one archive so the
//  whole bundle can be encrypted or signed as a single age payload, and read
//  the bundle back out after decryption.
//
//  Only regular files are produced — no directories, symlinks, or long-name
//  (PAX/GNU) extensions. Names must fit the 100-byte USTAR `name` field, which
//  is fine for the leaf filenames AgePony bundles. The output is the compact
//  form: each entry is a 512-byte header plus its data padded to 512, followed
//  by the two zero blocks that mark end-of-archive. (Unlike GNU tar we don't pad
//  to a 10240-byte record boundary — every tar tool still reads the compact
//  form, and it keeps small bundles small.)
//
//  Cross-checked byte-for-byte against Python's `tarfile` (USTAR_FORMAT).
//

import Foundation

public enum TarArchiveError: Error, Equatable {
    case nameTooLong(String)
    case truncated
    case badChecksum
    case unsupportedEntryType(UInt8)
    case invalidSize
}

public enum TarArchive {

    private static let blockSize = 512

    public struct Entry: Equatable {
        public let name: String
        public let data: Data
        public init(name: String, data: Data) {
            self.name = name
            self.data = data
        }
    }

    // MARK: - Create

    /// Build a USTAR archive from `entries`. mtime is fixed at 0 and mode at
    /// 0644 so the output is deterministic.
    public static func create(_ entries: [Entry]) throws -> Data {
        var out = Data()
        for entry in entries {
            out.append(try header(name: entry.name, size: entry.data.count))
            out.append(entry.data)
            let remainder = entry.data.count % blockSize
            if remainder != 0 {
                out.append(Data(count: blockSize - remainder))
            }
        }
        // End-of-archive: two zero blocks.
        out.append(Data(count: blockSize * 2))
        return out
    }

    private static func header(name: String, size: Int) throws -> Data {
        let nameBytes = Array(name.utf8)
        guard nameBytes.count <= 100 else { throw TarArchiveError.nameTooLong(name) }

        var h = [UInt8](repeating: 0, count: blockSize)

        func put(_ s: String, at offset: Int, max: Int) {
            for (i, b) in Array(s.utf8).prefix(max).enumerated() { h[offset + i] = b }
        }
        func putBytes(_ bytes: [UInt8], at offset: Int) {
            for (i, b) in bytes.enumerated() { h[offset + i] = b }
        }

        putBytes(nameBytes, at: 0)                          // name (100)
        put("0000644", at: 100, max: 7)                     // mode  + NUL
        put("0000000", at: 108, max: 7)                     // uid
        put("0000000", at: 116, max: 7)                     // gid
        put(String(format: "%011o", size), at: 124, max: 11) // size (octal) + NUL
        put("00000000000", at: 136, max: 11)                // mtime 0 + NUL
        // checksum field (148..155): spaces while computing.
        for i in 148..<156 { h[i] = 0x20 }
        h[156] = 0x30                                       // typeflag '0' regular
        put("ustar", at: 257, max: 5); h[262] = 0           // magic "ustar\0"
        h[263] = 0x30; h[264] = 0x30                        // version "00"

        // Checksum = sum of all bytes with the checksum field as spaces.
        let sum = h.reduce(0) { $0 + Int($1) }
        // 6 octal digits, NUL, space.
        let cks = String(format: "%06o", sum)
        putBytes(Array(cks.utf8), at: 148)
        h[154] = 0
        h[155] = 0x20

        return Data(h)
    }

    // MARK: - Extract

    /// Parse a USTAR archive into its entries. Verifies each header checksum.
    public static func extract(_ archive: Data) throws -> [Entry] {
        let bytes = [UInt8](archive)
        var offset = 0
        var entries: [Entry] = []

        while offset + blockSize <= bytes.count {
            let header = Array(bytes[offset ..< offset + blockSize])
            // End-of-archive: an all-zero block.
            if header.allSatisfy({ $0 == 0 }) { break }
            offset += blockSize

            try verifyChecksum(header)

            let typeflag = header[156]
            guard typeflag == 0x30 || typeflag == 0 else {
                throw TarArchiveError.unsupportedEntryType(typeflag)
            }

            let name = parseString(header, 0, 100)
            let size = try parseOctal(header, 124, 12)

            guard offset + size <= bytes.count else { throw TarArchiveError.truncated }
            let data = Data(bytes[offset ..< offset + size])
            entries.append(Entry(name: name, data: data))

            // Advance past the data, rounded up to a block boundary.
            let padded = size + (size % blockSize == 0 ? 0 : blockSize - size % blockSize)
            offset += padded
        }
        return entries
    }

    private static func verifyChecksum(_ header: [UInt8]) throws {
        let stored = try parseOctal(header, 148, 8)
        var sum = 0
        for (i, b) in header.enumerated() {
            sum += (148..<156).contains(i) ? 0x20 : Int(b)
        }
        guard sum == stored else { throw TarArchiveError.badChecksum }
    }

    private static func parseString(_ header: [UInt8], _ start: Int, _ len: Int) -> String {
        var slice = Array(header[start ..< start + len])
        if let nul = slice.firstIndex(of: 0) { slice = Array(slice[..<nul]) }
        return String(decoding: slice, as: UTF8.self)
    }

    private static func parseOctal(_ header: [UInt8], _ start: Int, _ len: Int) throws -> Int {
        var value = 0
        for b in header[start ..< start + len] {
            if b == 0 || b == 0x20 { continue }           // skip NUL / space padding
            guard b >= 0x30 && b <= 0x37 else { throw TarArchiveError.invalidSize }
            value = value * 8 + Int(b - 0x30)
        }
        return value
    }
}
