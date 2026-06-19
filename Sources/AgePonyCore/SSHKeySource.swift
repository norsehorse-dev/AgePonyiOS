import Foundation

public enum SSHKeySourceError: Error {
    case invalidURL
    case fetchFailed(Int)
    case noUsableKeys
}

/// Fetches SSH public keys from URLs that serve `authorized_keys`-style content
/// (one SSH public key per line). The canonical use case is `https://github.com/{user}.keys`
/// and `https://gitlab.com/{user}.keys`, which is how people commonly publish their
/// SSH identities for use as age recipients.
public enum SSHKeySource {
    /// Fetch keys from an arbitrary URL and return all parseable recipients.
    public static func fetch(from url: URL) async throws -> [any AgeRecipient] {
        var req = URLRequest(url: url)
        req.timeoutInterval = 30
        req.setValue("AgePony/1.0", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: req)
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
    public static func github(username: String) async throws -> [any AgeRecipient] {
        guard let url = URL(string: "https://github.com/\(username).keys") else {
            throw SSHKeySourceError.invalidURL
        }
        return try await fetch(from: url)
    }

    /// Convenience: fetch `https://gitlab.com/{username}.keys`.
    public static func gitlab(username: String) async throws -> [any AgeRecipient] {
        guard let url = URL(string: "https://gitlab.com/\(username).keys") else {
            throw SSHKeySourceError.invalidURL
        }
        return try await fetch(from: url)
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
