//
//  LanTransfer.swift
//  AgePonyCore
//
//  Phone-to-phone delivery of a key transfer over the local network: the wire format,
//  without the sockets. The app drives a `Network.framework` listener / connection and
//  feeds bytes through here, so the protocol stays testable and identical to Android.
//
//  The receiving phone listens on a TCP port and puts everything the sender needs in its
//  QR code: the one-time `age1pq1` recipient, a random 16-byte token, the port and its
//  local addresses. The sender encrypts the transfer to that recipient, connects and
//  pushes the ciphertext. Only ciphertext crosses the network; the token stops anyone
//  else on it from filling the receiver's slot.
//
//  Framing is RelayPony's wire protocol v1: `type(1) | length(4, BE) | payload`. One
//  transfer is one "file":
//
//    sender   -> HELLO(v1, scheme age, device name, handle = token hex)
//    sender   -> FILE_BEGIN(u64 size) FILE_CHUNK* FILE_END(sha256) DONE
//    receiver -> ACK(1 byte: 1 accepted, 0 refused)
//
//  Limits match Android: 16 MiB per transfer, 64 KiB chunks, HELLO within 10 s of
//  connecting and the whole transfer within 120 s of the token checking out (the app
//  enforces the clocks), at most 4 connections at once.
//
//  Mirrors Android agepony-core `portability/LanTransfer.kt`.
//

import Foundation
import CryptoKit

public enum LanTransferError: Error, Equatable {
    case notAnInvite
    case damagedInvite
    case protocolError(String)
    case wrongToken
    case tooLarge
    case refused
}

public enum LanTransfer {
    static let hello: UInt8 = 0x01
    static let fileBegin: UInt8 = 0x03
    static let fileChunk: UInt8 = 0x04
    static let fileEnd: UInt8 = 0x05
    static let ack: UInt8 = 0x06
    static let done: UInt8 = 0x07
    static let wireVersion: UInt8 = 1
    static let schemeAge: UInt8 = 0x01

    public static let tokenSize = 16
    public static let maxBytes = 16 * 1024 * 1024
    public static let chunkSize = 64 * 1024
    public static let handshakeDeadline: TimeInterval = 10
    public static let transferDeadline: TimeInterval = 120
    public static let maxConnections = 4
    static let invitePrefix = "AGEPONY:XFER1/"

    /// What the receiver's QR code carries, upper-cased for the QR alphanumeric set:
    /// `AGEPONY:XFER1/<RECIPIENT>/<TOKEN HEX>/<PORT>/<IP>+<IP>`.
    public struct Invite: Equatable {
        public let recipient: String
        public let token: Data
        public let port: UInt16
        public let hosts: [String]

        public init(recipient: String, token: Data, port: UInt16, hosts: [String]) throws {
            guard token.count == tokenSize, port > 0 else { throw LanTransferError.damagedInvite }
            self.recipient = recipient
            self.token = token
            self.port = port
            self.hosts = hosts
        }

        public func encode() -> String {
            (invitePrefix + recipient.trimmingCharacters(in: .whitespaces) + "/" + hex(token) + "/" + String(port) + "/"
                + hosts.joined(separator: "+")).uppercased()
        }

        public static func isInvite(_ s: String) -> Bool {
            s.trimmingCharacters(in: .whitespacesAndNewlines).uppercased().hasPrefix(invitePrefix)
        }

        public static func decode(_ s: String) throws -> Invite {
            let t = s.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            guard t.hasPrefix(invitePrefix) else { throw LanTransferError.notAnInvite }
            let parts = t.dropFirst(invitePrefix.count).split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 4, let token = unhex(parts[1]), let port = UInt16(parts[2]) else {
                throw LanTransferError.damagedInvite
            }
            let hosts = parts[3].split(separator: "+").map(String.init).filter { !$0.isEmpty }
            return try Invite(recipient: parts[0].lowercased(), token: token, port: port, hosts: hosts)
        }
    }

    public static func newToken() -> Data { MLKEM768.randomBytes(tokenSize) }

    // MARK: - Sender

    /// Everything the sender writes, in order: HELLO, FILE_BEGIN, the chunks, FILE_END
    /// and DONE. Write it, then read one frame with `SenderAckParser`.
    public static func senderStream(sealed: Data, deviceName: String, token: Data) throws -> Data {
        guard sealed.count <= maxBytes else { throw LanTransferError.tooLarge }
        var out = frame(hello, helloPayload(deviceName: deviceName, handle: hex(token)))
        let size = UInt64(sealed.count)
        out += frame(fileBegin, Data((0..<8).map { UInt8(truncatingIfNeeded: size >> UInt64(56 - 8 * $0)) }))
        var offset = sealed.startIndex
        while offset < sealed.endIndex {
            let end = min(offset + chunkSize, sealed.endIndex)
            out += frame(fileChunk, Data(sealed[offset..<end]))
            offset = end
        }
        out += frame(fileEnd, Data(SHA256.hash(data: sealed)))
        out += frame(done, Data())
        return out
    }

    /// Reads the receiver's ACK.
    public struct SenderAckParser {
        var buffer = Data()
        public init() {}

        /// Feed bytes from the connection. Returns nil until a full frame has arrived,
        /// then true when the receiver accepted. Throws on anything but an ACK.
        public mutating func feed(_ data: Data) throws -> Bool? {
            buffer.append(data)
            guard let (type, payload, _) = try LanTransfer.takeFrame(buffer, max: 16) else { return nil }
            guard type == LanTransfer.ack else { throw LanTransferError.protocolError("expected ACK") }
            return payload.first == 1
        }
    }

    // MARK: - Receiver

    /// The ACK frame the receiver sends back.
    public static func ackFrame(accepted: Bool) -> Data { frame(ack, Data([accepted ? 1 : 0])) }

    /// Incremental parser for one incoming connection. Feed it bytes as they arrive.
    /// It throws on a protocol error, a wrong token, or anything over the limits; the
    /// app then drops the connection (and, for a wrong token, keeps listening).
    public struct ReceiveParser {
        public enum State: Equatable {
            /// Waiting for HELLO (the handshake clock is running).
            case awaitingHello
            /// HELLO carried the right token; the transfer is arriving.
            case receiving
            /// The whole transfer arrived and checked out.
            case complete(Data)
        }

        let token: Data
        let limit: Int
        var buffer = Data()
        var body = Data()
        var declaredSize: Int?
        var ended = false
        public private(set) var state: State = .awaitingHello

        public init(token: Data, maxBytes: Int = LanTransfer.maxBytes) {
            self.token = token
            self.limit = maxBytes
        }

        @discardableResult
        public mutating func feed(_ data: Data) throws -> State {
            buffer.append(data)
            while !state.isComplete {
                let max: Int
                switch (state, declaredSize, ended) {
                case (.awaitingHello, _, _): max = 4096
                case (_, nil, _): max = 64
                case (_, _, true): max = 16
                default: max = LanTransfer.chunkSize
                }
                guard let (type, payload, used) = try LanTransfer.takeFrame(buffer, max: max) else { break }
                buffer = Data(buffer.dropFirst(used))
                try handle(type, payload)
            }
            return state
        }

        mutating func handle(_ type: UInt8, _ payload: Data) throws {
            if state == .awaitingHello {
                guard type == LanTransfer.hello else { throw LanTransferError.protocolError("expected HELLO") }
                let handle = try LanTransfer.parseHelloHandle(payload)
                let expected = Data(LanTransfer.hex(token).utf8)
                let given = Data(handle.utf8)
                var diff = UInt8(given.count == expected.count ? 0 : 1)
                for (a, b) in zip(given, expected) { diff |= a ^ b }
                guard diff == 0 else { throw LanTransferError.wrongToken }
                state = .receiving
                return
            }
            guard let size = declaredSize else {
                guard type == LanTransfer.fileBegin, payload.count == 8 else { throw LanTransferError.protocolError("expected FILE_BEGIN") }
                let n = payload.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
                guard n <= UInt64(limit) else { throw LanTransferError.tooLarge }
                declaredSize = Int(n)
                return
            }
            if ended {
                guard type == LanTransfer.done else { throw LanTransferError.protocolError("expected DONE") }
                state = .complete(body)
                return
            }
            switch type {
            case LanTransfer.fileChunk:
                guard body.count + payload.count <= size else { throw LanTransferError.protocolError("too much data") }
                body.append(payload)
            case LanTransfer.fileEnd:
                guard body.count == size else { throw LanTransferError.protocolError("size mismatch") }
                guard Data(SHA256.hash(data: body)) == payload else { throw LanTransferError.protocolError("checksum mismatch") }
                ended = true
            default:
                throw LanTransferError.protocolError("unexpected frame")
            }
        }
    }

    // MARK: - Framing

    static func frame(_ type: UInt8, _ payload: Data) -> Data {
        let n = UInt32(payload.count)
        return Data([type, UInt8(n >> 24), UInt8(n >> 16 & 0xFF), UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF)]) + payload
    }

    /// One frame from the front of `buffer`: (type, payload, bytes used), nil if more
    /// bytes are needed. Refuses a declared length over `max` before buffering it.
    static func takeFrame(_ buffer: Data, max: Int) throws -> (UInt8, Data, Int)? {
        let b = buffer
        guard b.count >= 5 else { return nil }
        let s = b.startIndex
        let len = Int(b[s + 1]) << 24 | Int(b[s + 2]) << 16 | Int(b[s + 3]) << 8 | Int(b[s + 4])
        guard len <= max else { throw LanTransferError.protocolError("frame too large") }
        guard b.count >= 5 + len else { return nil }
        return (b[s], Data(b[(s + 5)..<(s + 5 + len)]), 5 + len)
    }

    static func helloPayload(deviceName: String, handle: String) -> Data {
        let name = Data(Data(deviceName.utf8).prefix(200))
        let h = Data(handle.utf8)
        var out = Data([wireVersion, schemeAge])
        out += Data([UInt8(name.count >> 8), UInt8(name.count & 0xFF)]) + name
        out += Data([UInt8(h.count >> 8), UInt8(h.count & 0xFF)]) + h
        return out
    }

    static func parseHelloHandle(_ p: Data) throws -> String {
        let b = Array(p)
        var i = 0
        func u8() throws -> Int {
            guard i < b.count else { throw LanTransferError.protocolError("HELLO truncated") }
            defer { i += 1 }
            return Int(b[i])
        }
        func take(_ n: Int) throws -> [UInt8] {
            guard i + n <= b.count else { throw LanTransferError.protocolError("HELLO truncated") }
            defer { i += n }
            return Array(b[i..<(i + n)])
        }
        guard try u8() >= 1 else { throw LanTransferError.protocolError("bad HELLO version") }
        guard try u8() == Int(schemeAge) else { throw LanTransferError.protocolError("not an age transfer") }
        _ = try take(try u8() << 8 | (try u8()))
        return String(decoding: try take(try u8() << 8 | (try u8())), as: UTF8.self)
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    static func unhex(_ s: String) -> Data? {
        guard s.count == tokenSize * 2 else { return nil }
        var out = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard let byte = UInt8(s[i..<j], radix: 16) else { return nil }
            out.append(byte)
            i = j
        }
        return out
    }
}

extension LanTransfer.ReceiveParser.State {
    var isComplete: Bool {
        if case .complete = self { return true }
        return false
    }
}
