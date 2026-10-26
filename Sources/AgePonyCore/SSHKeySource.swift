import Foundation

public enum SSHKeySourceError: Error {
    case invalidURL
    case fetchFailed(Int)
    case noUsableKeys
    case proxyMisconfigured
}

/// Fetches SSH public keys from URLs that serve `authorized_keys`-style content
/// (one SSH public key per line). The canonical use case is `https://github.com/{user}.keys`
/// and `https://gitlab.com/{user}.keys`, which is how people commonly publish their
/// SSH identities for use as age recipients.
///
/// This is the one place AgePony reaches the network. An optional `ProxyConfig`
/// routes the request through a SOCKS5 (Tor/Orbot) or HTTP proxy. When a proxy is
/// active and unreachable the request errors out rather than falling back to a
/// direct connection.
public enum SSHKeySource {
    /// Fetch keys from an arbitrary URL and return all parseable recipients.
    public static func fetch(from url: URL, proxy: ProxyConfig? = nil) async throws -> [any AgeRecipient] {
        if let proxy, proxy.isActive, !proxy.isValid {
            throw SSHKeySourceError.proxyMisconfigured
        }

        var req = URLRequest(url: url)
        req.timeoutInterval = 30
        req.setValue("AgePony/1.0", forHTTPHeaderField: "User-Agent")

        let (session, owned) = makeSession(proxy: proxy)
        defer { if owned { session.finishTasksAndInvalidate() } }

        let (data, response) = try await session.data(for: req)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw SSHKeySourceError.fetchFailed(http.statusCode)
        }
        let text = String(data: data, encoding: .utf8) ?? ""
        return parse(text: text)
    }

    /// Parse a multi-line `authorized_keys`-style string, skipping comments and unknown key types.
    public static func parse(text: String) -> [any AgeRecipient] {
        var out: [any AgeRecipient] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let trimmed = String(line).trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let parts = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard parts.count >= 2 else { continue }
            let keyType = String(parts[0])
            switch keyType {
            case "ssh-ed25519":
                if let pub = parseEd25519Pub(base64Blob: String(parts[1])),
                   let r = try? SSHEd25519Recipient(edPublicKey: pub) {
                    out.append(r)
                }
            case "ssh-rsa":
                if let r = try? SSHRSARecipient(sshPublicKeyLine: trimmed) {
                    out.append(r)
                }
            default:
                continue  // skip ecdsa-*, dsa, unknown types
            }
        }
        return out
    }

    /// Convenience: fetch `https://github.com/{username}.keys`.
    public static func github(username: String, proxy: ProxyConfig? = nil) async throws -> [any AgeRecipient] {
        guard let url = URL(string: "https://github.com/\(username).keys") else {
            throw SSHKeySourceError.invalidURL
        }
        return try await fetch(from: url, proxy: proxy)
    }

    /// Convenience: fetch `https://gitlab.com/{username}.keys`.
    public static func gitlab(username: String, proxy: ProxyConfig? = nil) async throws -> [any AgeRecipient] {
        guard let url = URL(string: "https://gitlab.com/\(username).keys") else {
            throw SSHKeySourceError.invalidURL
        }
        return try await fetch(from: url, proxy: proxy)
    }

    // MARK: - Proxy plumbing

    /// Build the URLSession for a request. Returns the shared session (which must
    /// not be invalidated) for a direct connection, or a fresh proxied session we
    /// own. The `owned` flag tells the caller whether to invalidate it.
    private static func makeSession(proxy: ProxyConfig?) -> (session: URLSession, owned: Bool) {
        // Never URLSession.shared: an ephemeral session keeps no cookies, cache or
        // credentials on disk, so nothing of the lookup outlives it (audit L-25).
        guard let proxy, proxy.isActive else { return (URLSession(configuration: .ephemeral), true) }

        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = proxyDictionary(proxy)

        // HTTP proxies surface username/password as a standard auth challenge.
        let delegate: ProxyAuthDelegate?
        if proxy.mode == .http, let user = proxy.username, let pass = proxy.password,
           !user.isEmpty, !pass.isEmpty {
            delegate = ProxyAuthDelegate(user: user, password: pass)
        } else {
            delegate = nil
        }
        return (URLSession(configuration: config, delegate: delegate, delegateQueue: nil), true)
    }

    private static func proxyDictionary(_ p: ProxyConfig) -> [AnyHashable: Any] {
        switch p.mode {
        case .off:
            return [:]
        case .http:
            // Route both HTTP and HTTPS (GitHub is HTTPS) through the proxy.
            return [
                kCFNetworkProxiesHTTPEnable as String: 1,
                kCFNetworkProxiesHTTPProxy as String: p.host,
                kCFNetworkProxiesHTTPPort as String: p.port,
                "HTTPSEnable": 1,
                "HTTPSProxy": p.host,
                "HTTPSPort": p.port,
            ]
        }
    }

    /// Extract the 32-byte ed25519 pub from an ssh-ed25519 base64-encoded wire blob.
    private static func parseEd25519Pub(base64Blob: String) -> Data? {
        guard let blob = Data(base64Encoded: base64Blob) else { return nil }
        var reader = SSHWireReader(blob)
        guard let typeBytes = try? reader.readString(),
              String(data: typeBytes, encoding: .utf8) == "ssh-ed25519",
              let pub = try? reader.readString(),
              pub.count == 32 else { return nil }
        return pub
    }
}

/// Answers an HTTP proxy's Basic auth challenge with the configured credentials.
private final class ProxyAuthDelegate: NSObject, URLSessionDataDelegate {
    private let user: String
    private let password: String

    init(user: String, password: String) {
        self.user = user
        self.password = password
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.isProxy() {
            completionHandler(.useCredential,
                              URLCredential(user: user, password: password, persistence: .forSession))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
