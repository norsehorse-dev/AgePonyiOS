//
//  ProxyConfig.swift
//  AgePonyCore
//
//  Proxy settings for the one network call AgePony makes: the GitHub key fetch
//  under Add Recipient (4.0.0). Everything else in the app is offline.
//
//  iOS note: URLSession can route HTTP/HTTPS proxies but not SOCKS (the
//  kCFNetworkProxiesSOCKS* keys are macOS-only), so this is HTTP-proxy only.
//  Android's SOCKS/Orbot one-tap has no URLSession equivalent; routing through
//  Tor on iOS means pointing this at an HTTP proxy that fronts Tor.
//
//  When a proxy is active and unreachable the fetch fails rather than falling
//  back to a direct connection, since a silent direct connection is the exact
//  leak the proxy exists to prevent.
//

import Foundation

public struct ProxyConfig: Equatable, Sendable {

    public enum Mode: String, Sendable, CaseIterable {
        case off
        case http
    }

    public var mode: Mode
    public var host: String
    public var port: Int
    public var username: String?
    public var password: String?

    public init(mode: Mode, host: String = "", port: Int = 0,
                username: String? = nil, password: String? = nil) {
        self.mode = mode
        self.host = host
        self.port = port
        self.username = username
        self.password = password
    }

    public static let direct = ProxyConfig(mode: .off)

    public var isActive: Bool { mode != .off }

    /// An active proxy needs a usable host and port. Off is always valid.
    public var isValid: Bool {
        if mode == .off { return true }
        return !host.trimmingCharacters(in: .whitespaces).isEmpty && (1...65535).contains(port)
    }
}
