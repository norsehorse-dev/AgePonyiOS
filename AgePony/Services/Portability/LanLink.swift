//
//  LanLink.swift
//  AgePony
//
//  Phone-to-phone delivery of a key transfer over the local network (5.0.1, parity with
//  Android 5.0.0). The wire format and its limits live in AgePonyCore's LanTransfer; this
//  file is only the Network.framework plumbing, structured like RelayPony's
//  NWConnectionTransport (decision Q8) but asynchronous, since a screen drives it.
//
//  Receiver: an NWListener on an ephemeral TCP port, bound to the Wi-Fi (or hotspot)
//  address the QR code advertises, so the port isn't open on cellular or a VPN. At most
//  four connections at once; each must present HELLO with the right token within 10 s,
//  and once it has, the whole transfer within 120 s. When the slots are full, the oldest
//  connection that hasn't shown the token makes room. The screen opens the transfer
//  before the ACK goes out, so "Sent" on the other phone means it arrived and opened here.
//
//  Sender: one NWConnection per advertised address, never over cellular, writes the whole
//  stream and waits for the ACK.
//
//  Only ciphertext crosses the network, and nothing here reaches the internet. No Bonjour:
//  the address comes from the QR code, so there is no NSBonjourServices entry.
//
//  Mirrors Android agepony-core `portability/LanTransfer.kt` and app `net/LocalNetwork.kt`.
//

import Foundation
import Network
import AgePonyCore

/// Why a local transfer didn't go through, in words for the screen.
nonisolated enum LanLinkError: LocalizedError, Equatable {
    case localNetworkDenied
    case unreachable(String?)
    case refused
    case closed
    case tooLarge

    var errorDescription: String? {
        switch self {
        case .localNetworkDenied:
            return String(localized: "AgePony isn't allowed on the local network. Turn it on under Privacy & Security, Local Network, in the Settings app, or use a file instead.")
        case .unreachable(let detail):
            let base = String(localized: "Couldn't reach the other phone. Put both on the same Wi-Fi (or one on the other's hotspot).")
            return detail.map { "\(base) (\($0))" } ?? base
        case .refused:
            return String(localized: "The other phone refused the transfer. Start Receive keys again and rescan.")
        case .closed:
            return String(localized: "The other phone closed the connection.")
        case .tooLarge:
            return String(localized: "Transfer is too large to send directly.")
        }
    }

    /// A code for a report, shown after the message. Never the error's own text
    /// (5.1.0, U5). Nil for an error with no code worth showing.
    static func code(for error: Error) -> String? {
        if let nw = error as? NWError {
            switch nw {
            case .posix(let code): return "POSIX \(code.rawValue)"
            case .dns(let code):   return "DNS \(code)"
            case .tls(let status): return "OSStatus \(status)"
            default:               return nil
            }
        }
        guard type(of: error) is NSError.Type else { return nil }
        let ns = error as NSError
        return "\(ns.domain) \(ns.code)"
    }

    /// iOS reports a denied Local Network permission as this DNS-SD error.
    static let policyDenied: Int32 = -65570

    static func isPolicyDenied(_ error: NWError) -> Bool {
        if case .dns(let code) = error { return code == policyDenied }
        return false
    }
}

// MARK: - This phone's addresses

nonisolated enum LocalNetwork {
    struct Address: Equatable {
        let ip: String
        let interface: String
    }

    /// This phone's private IPv4 addresses on Wi-Fi (`en*`) or its own hotspot (`bridge*`),
    /// for the receive QR code. Cellular (`pdp_ip*`), VPN tunnels (`utun*`), AWDL and
    /// loopback are left out.
    static func localAddresses() -> [Address] {
        var out: [Address] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            let flags = Int32(ifa.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0, flags & IFF_LOOPBACK == 0,
                  let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            let name = String(cString: ifa.pointee.ifa_name)
            guard name.hasPrefix("en") || name.hasPrefix("bridge") else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count),
                              nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let ip = String(decoding: host.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            guard isPrivate(ip), !out.contains(where: { $0.ip == ip }) else { continue }
            out.append(Address(ip: ip, interface: name))
        }
        // Wi-Fi first: it's the address the sender is most likely to share.
        return out.sorted { ($0.interface == "en0" ? 0 : 1, $0.interface) < ($1.interface == "en0" ? 0 : 1, $1.interface) }
    }

    /// The address to bind the listener to (audit AS-3): the Wi-Fi address when there is one,
    /// or the only one listed (this phone's hotspot, say). Nil means several candidates and
    /// none of them Wi-Fi, so listen on all of them.
    static func bindAddress(_ addresses: [Address]) -> Address? {
        addresses.first(where: { $0.interface == "en0" }) ?? (addresses.count == 1 ? addresses[0] : nil)
    }

    static func isPrivate(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        switch (parts[0], parts[1]) {
        case (10, _): return true
        case (172, 16...31): return true
        case (192, 168): return true
        default: return false
        }
    }
}

// MARK: - Receiver

/// Listens for one key transfer. Create, `start`, and `stop` when the screen goes away.
/// Callbacks arrive on the main queue except `open`, which runs on the link's own queue
/// (it decrypts) and must return quickly whether the transfer was taken.
nonisolated final class TransferListener: @unchecked Sendable {

    /// Runs on the link queue with the exact sealed bytes. Return true once they opened;
    /// the sender then hears "accepted" and every other connection is refused.
    typealias Open = @Sendable (Data) -> Bool

    private let token: Data
    private let bindHost: String?
    private let open: Open
    private let queue = DispatchQueue(label: "agepony.transfer.listen")

    private var listener: NWListener?
    private var conns: [ObjectIdentifier: Conn] = [:]
    private var taken = false
    private var closed = false
    private var triedUnbound = false

    /// The port once listening, and whether it is bound to `bindHost` alone.
    var onReady: (@MainActor (UInt16, Bool) -> Void)?
    /// The listener couldn't start (or was refused the local network).
    var onFailed: (@MainActor (Error) -> Void)?

    private final class Conn {
        let connection: NWConnection
        let startedAt = DispatchTime.now()
        var parser: LanTransfer.ReceiveParser
        var authenticated = false
        var deadline: DispatchWorkItem?

        init(_ c: NWConnection, token: Data) {
            connection = c
            parser = LanTransfer.ReceiveParser(token: token)
        }
    }

    init(token: Data, bindHost: String?, open: @escaping Open) {
        self.token = token
        self.bindHost = bindHost
        self.open = open
    }

    func start() {
        queue.async { self.listen(bound: self.bindHost != nil) }
    }

    func stop() {
        queue.async { self.shutdown() }
    }

    private func listen(bound: Bool) {
        guard !closed else { return }
        let params = NWParameters.tcp
        params.prohibitedInterfaceTypes = [.cellular]
        if bound, let host = bindHost {
            params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: .any)
        }
        let l: NWListener
        do {
            l = try NWListener(using: params)
        } catch {
            fallBack(bound: bound, error: error)
            return
        }
        listener = l
        l.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if let port = l.port?.rawValue {
                    let cb = self.onReady
                    Task { @MainActor in cb?(port, bound) }
                }
            case .failed(let error) where LanLinkError.isPolicyDenied(error):
                // Final: no fallback to all interfaces can get past the permission.
                l.cancel()
                self.listener = nil
                self.fail(LanLinkError.localNetworkDenied)
            case .failed(let error):
                l.cancel()
                self.fallBack(bound: bound, error: error)
            default:
                break
            }
        }
        l.newConnectionHandler = { [weak self] c in self?.admit(c) }
        l.start(queue: queue)
    }

    /// A bind to the Wi-Fi address that fails falls back to every interface rather than
    /// losing the direct route, as Android does.
    private func fallBack(bound: Bool, error: Error) {
        listener = nil
        if bound && !triedUnbound && !closed {
            triedUnbound = true
            listen(bound: false)
        } else {
            fail(error)
        }
    }

    private func fail(_ error: Error) {
        let cb = onFailed
        Task { @MainActor in cb?(error) }
    }

    private func admit(_ connection: NWConnection) {
        guard !closed, !taken else { connection.cancel(); return }
        if conns.count >= LanTransfer.maxConnections {
            let victim = conns.values.filter { !$0.authenticated }.min { $0.startedAt < $1.startedAt }
            guard let victim else { connection.cancel(); return }
            drop(victim)
        }
        let c = Conn(connection, token: token)
        conns[ObjectIdentifier(c)] = c
        arm(c, seconds: LanTransfer.handshakeDeadline)
        connection.stateUpdateHandler = { [weak self, weak c] state in
            guard let self, let c else { return }
            switch state {
            case .failed, .cancelled: self.forget(c)
            default: break
            }
        }
        connection.start(queue: queue)
        read(c)
    }

    /// A total deadline, not a per-read timeout: a sender trickling bytes is cut off on time.
    private func arm(_ c: Conn, seconds: TimeInterval) {
        c.deadline?.cancel()
        let item = DispatchWorkItem { [weak self, weak c] in
            guard let self, let c else { return }
            self.drop(c)
        }
        c.deadline = item
        queue.asyncAfter(deadline: .now() + seconds, execute: item)
    }

    private func read(_ c: Conn) {
        c.connection.receive(minimumIncompleteLength: 1, maximumLength: LanTransfer.chunkSize + 5) { [weak self, weak c] data, _, isComplete, error in
            guard let self, let c, self.conns[ObjectIdentifier(c)] != nil else { return }
            if let data, !data.isEmpty {
                let state: LanTransfer.ReceiveParser.State
                do {
                    state = try c.parser.feed(data)
                } catch {
                    self.finish(c, accepted: false)
                    return
                }
                switch state {
                case .awaitingHello:
                    break
                case .receiving:
                    if !c.authenticated {
                        c.authenticated = true
                        self.arm(c, seconds: LanTransfer.transferDeadline)
                    }
                case .complete(let bytes):
                    self.finish(c, accepted: self.take(bytes))
                    return
                }
            }
            if isComplete || error != nil {
                self.drop(c)
                return
            }
            self.read(c)
        }
    }

    /// Hand the bytes to `open`, one connection at a time, until one is taken.
    private func take(_ bytes: Data) -> Bool {
        guard !taken, !closed else { return false }
        let ok = open(bytes)
        if ok { taken = true }
        return ok
    }

    private func finish(_ c: Conn, accepted: Bool) {
        c.deadline?.cancel()
        c.connection.send(content: LanTransfer.ackFrame(accepted: accepted), completion: .contentProcessed { [weak self, weak c] _ in
            guard let self, let c else { return }
            self.drop(c)
            if accepted { self.shutdown() }
        })
    }

    private func drop(_ c: Conn) {
        c.deadline?.cancel()
        c.connection.cancel()
        forget(c)
    }

    private func forget(_ c: Conn) {
        conns[ObjectIdentifier(c)] = nil
    }

    private func shutdown() {
        closed = true
        listener?.cancel()
        listener = nil
        for c in conns.values { drop(c) }
        conns.removeAll()
    }
}

// MARK: - Sender

nonisolated enum TransferSender {

    /// Deliver `sealed` to the receiver in `invite`, trying each advertised address in turn.
    /// Returns only when the receiver acknowledged the transfer.
    static func send(invite: LanTransfer.Invite, sealed: Data, deviceName: String) async throws {
        guard sealed.count <= LanTransfer.maxBytes else { throw LanLinkError.tooLarge }
        let stream = try LanTransfer.senderStream(sealed: sealed, deviceName: deviceName, token: invite.token)
        var lastError: Error?
        for host in invite.hosts {
            do {
                try await deliver(stream, host: host, port: invite.port)
                return
            } catch let e as LanLinkError where e == .refused || e == .localNetworkDenied {
                throw e
            } catch {
                lastError = error
            }
        }
        if let e = lastError as? LanLinkError { throw e }
        if let e = lastError as? LanTransferError { throw e }
        throw LanLinkError.unreachable(lastError.flatMap { LanLinkError.code(for: $0) })
    }

    /// One attempt against one address: 5 s to connect, 30 s for the rest.
    private static func deliver(_ stream: Data, host: String, port: UInt16) async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw LanLinkError.unreachable(nil) }
        let params = NWParameters.tcp
        // Never over cellular, where a private address leads nowhere. Not `.wifi` only:
        // when this iPhone is the hotspot the other phone sits behind `bridge100`.
        params.prohibitedInterfaceTypes = [.cellular]
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
        let queue = DispatchQueue(label: "agepony.transfer.send")
        let once = Once()

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                func finish(_ result: Result<Void, Error>) {
                    guard once.claim() else { return }
                    connection.cancel()
                    cont.resume(with: result)
                }
                let connectTimeout = DispatchWorkItem { finish(.failure(LanLinkError.unreachable(String(localized: "timed out")))) }
                let permissionTimeout = DispatchWorkItem { finish(.failure(LanLinkError.localNetworkDenied)) }
                queue.asyncAfter(deadline: .now() + 5, execute: connectTimeout)

                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        connectTimeout.cancel()
                        permissionTimeout.cancel()
                        queue.asyncAfter(deadline: .now() + 30) { finish(.failure(LanLinkError.closed)) }
                        connection.send(content: stream, completion: .contentProcessed { error in
                            if let error { finish(.failure(error)) }
                        })
                        let ack = AckBox()
                        func readAck() {
                            connection.receive(minimumIncompleteLength: 1, maximumLength: 64) { data, _, isComplete, error in
                                if let data, !data.isEmpty {
                                    do {
                                        if let accepted = try ack.parser.feed(data) {
                                            finish(accepted ? .success(()) : .failure(LanLinkError.refused))
                                            return
                                        }
                                    } catch {
                                        finish(.failure(LanLinkError.refused))
                                        return
                                    }
                                }
                                if isComplete || error != nil {
                                    finish(.failure(LanLinkError.closed))
                                    return
                                }
                                readAck()
                            }
                        }
                        readAck()
                    case .waiting(let error) where LanLinkError.isPolicyDenied(error):
                        // iOS reports this while its first-use Local Network alert is up, and
                        // goes on to .ready if the user allows it. Give them time to answer.
                        if !connectTimeout.isCancelled {
                            connectTimeout.cancel()
                            queue.asyncAfter(deadline: .now() + 60, execute: permissionTimeout)
                        }
                    case .failed(let error):
                        finish(.failure(LanLinkError.isPolicyDenied(error) ? LanLinkError.localNetworkDenied : error))
                    case .cancelled:
                        finish(.failure(LanLinkError.closed))
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    /// The ACK parser, shared by the receive callbacks on the connection's queue.
    private final class AckBox: @unchecked Sendable {
        var parser = LanTransfer.SenderAckParser()
    }

    /// Resumes a continuation exactly once across the connection's callbacks and timers.
    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func claim() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if done { return false }
            done = true
            return true
        }
    }
}
