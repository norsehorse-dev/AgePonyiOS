//
//  AllowedSigners.swift
//  AgePonyCore
//
//  Parse and serialize the OpenSSH `allowed_signers` file format, the trust
//  store `ssh-keygen -Y verify -f allowed_signers` reads. AgePony's
//  trusted-signers vault collection (C2) round-trips through this so a list
//  built in the app drops straight onto a machine's command line and back.
//
//  Line format (per ssh-keygen(1), ALLOWED SIGNERS):
//
//      principals [options] keytype base64-key [comment]
//
//  where `principals` is a comma-separated list (no spaces), `options` is an
//  optional comma-separated list of restrictions (e.g.
//  namespaces="agepony", valid-after=...), and comment is free text.
//  Blank lines and lines beginning with '#' are ignored.
//

import Foundation

public struct AllowedSigner: Equatable {
    /// Comma-separated principals split out (e.g. ["alice@example.com"]).
    public let principals: [String]
    /// Raw options field, preserved verbatim if present (e.g. `namespaces="agepony"`).
    public let options: String?
    /// Key algorithm, e.g. "ssh-ed25519".
    public let keyType: String
    /// Base64 of the SSH public-key wire blob.
    public let keyBase64: String
    /// Optional trailing comment.
    public let comment: String?

    public init(
        principals: [String],
        options: String? = nil,
        keyType: String,
        keyBase64: String,
        comment: String? = nil
    ) {
        self.principals = principals
        self.options = options
        self.keyType = keyType
        self.keyBase64 = keyBase64
        self.comment = comment
    }

    /// The public key as raw SSH wire bytes, if the base64 decodes.
    public var publicKeyWire: Data? {
        Data(base64Encoded: keyBase64)
    }

    /// Does this entry authorize `principal` to sign with the key whose wire
    /// blob is `publicKeyWire`? Principal matching is exact (and case-sensitive,
    /// matching ssh-keygen's behavior for plain identities); pattern principals
    /// are not expanded here.
    public func matches(principal: String, publicKeyWire candidate: Data) -> Bool {
        guard let mine = self.publicKeyWire, mine == candidate else { return false }
        return principals.contains(principal)
    }

    // MARK: Options (audit L-6)

    /// The options field parsed. Dates without a trailing `Z` are local time in `zone`,
    /// as ssh-keygen reads them.
    public func parsedOptions(zone: TimeZone = .current) -> AllowedSignerOptions {
        AllowedSignerOptions.parse(options, zone: zone)
    }

    /// `cert-authority`: the key signs certificates. AgePony has no certificate support,
    /// so such an entry permits nothing.
    public var isCertAuthority: Bool { parsedOptions(zone: .gmt).certAuthority }

    /// False only with `no-touch-required`: a security-key signature must carry a touch.
    public var requiresTouch: Bool { !parsedOptions(zone: .gmt).noTouchRequired }

    /// `verify-required`: a security-key signature must carry user verification.
    public var requiresUserVerification: Bool { parsedOptions(zone: .gmt).verifyRequired }

    /// Options AgePony doesn't know, verbatim. Any of these makes `permits` false, as
    /// OpenSSH refuses the line.
    public var unknownOptions: [String] { parsedOptions(zone: .gmt).unknown }

    /// Does this entry allow a signature in `namespace` made at `date`? Mirrors
    /// `ssh-keygen -Y verify`: false for `cert-authority`, a namespace outside
    /// `namespaces=`, a time outside `valid-after` / `valid-before`, or a malformed or
    /// unknown option. Says nothing about the key itself.
    public func permits(namespace: String, at date: Date = Date(), zone: TimeZone = .current) -> Bool {
        parsedOptions(zone: zone).permits(namespace: namespace, at: date, agePonyFamily: false)
    }

    /// `permits` for AgePony's own formats: `namespaces="agepony"` also permits the v2
    /// namespaces (sig stanza and bundle), so a restriction written before 5.0.1 keeps
    /// working. An explicit `!` negation of a v2 namespace still wins.
    public func permitsAgePony(namespace: String, at date: Date = Date(), zone: TimeZone = .current) -> Bool {
        parsedOptions(zone: zone).permits(namespace: namespace, at: date, agePonyFamily: true)
    }

    /// Whole-entry policy for a verified signature: the namespace is allowed at `date`,
    /// and a security-key signature carries the flags this entry demands (touch unless
    /// `no-touch-required`, user verification with `verify-required`). The caller still
    /// checks the key matches.
    public func accepts(_ verification: SSHSigVerification, at date: Date = Date(), zone: TimeZone = .current) -> Bool {
        let opts = parsedOptions(zone: zone)
        guard opts.permits(namespace: verification.namespace, at: date, agePonyFamily: true) else { return false }
        if verification.userPresent == false && !opts.noTouchRequired { return false }
        if opts.verifyRequired && verification.userVerified == false { return false }
        return true
    }
}

/// The options field of an allowed_signers line, parsed the way OpenSSH's sshsig.c does
/// (audit L-6). A comma-separated list; a value may be double-quoted and then hold commas
/// and spaces (`\"` is a literal quote). Names are case-insensitive.
///
/// Understood: `cert-authority`, `namespaces="pattern,list"`, `valid-after=` and
/// `valid-before=` (`YYYYMMDD`, `YYYYMMDDHHMM` or `YYYYMMDDHHMMSS`, a trailing `Z` or
/// `UTC` meaning UTC, otherwise local time), `no-touch-required`, `verify-required`.
/// Anything else lands in `unknown`. A duplicate clause, a bad date, an unterminated
/// quote, an empty item, or valid-before not after valid-after sets `error`. Either makes
/// `permits` false. Mirrors Android `AllowedSignerOptions`.
public struct AllowedSignerOptions: Equatable {
    public let raw: String?
    public let certAuthority: Bool
    /// The `namespaces=` value, dequoted, or nil when absent (every namespace allowed).
    public let namespaces: String?
    public let validAfter: Date?
    public let validBefore: Date?
    public let noTouchRequired: Bool
    public let verifyRequired: Bool
    public let unknown: [String]
    public let error: String?

    static var agePonyV2Namespaces: Set<String> { [SignatureStanza.namespaceV2, SignedBundle.namespaceV2] }

    public func permits(namespace: String, at date: Date, agePonyFamily: Bool = false) -> Bool {
        if error != nil || !unknown.isEmpty || certAuthority { return false }
        if let validAfter, date < validAfter { return false }
        if let validBefore, date > validBefore { return false }
        guard let list = namespaces else { return true }
        switch Self.matchPatternList(namespace, list) {
        case 1: return true
        case -1: return false
        default:
            return agePonyFamily && Self.agePonyV2Namespaces.contains(namespace)
                && Self.matchPatternList(SSHSig.defaultNamespace, list) == 1
        }
    }

    public static func parse(_ raw: String?, zone: TimeZone = .current) -> AllowedSignerOptions {
        var ca = false, noTouch = false, verify = false
        var namespaces: String?
        var after: Date?, before: Date?
        var unknown: [String] = []
        var error: String?
        func fail(_ m: String) { if error == nil { error = m } }

        var items: [String] = []
        if let raw, !raw.isEmpty {
            if let split = splitItems(raw) { items = split } else { fail("unterminated quote in options") }
        }
        var sawAfter = false, sawBefore = false
        for item in items {
            let eq = item.firstIndex(of: "=")
            let name = (eq.map { String(item[..<$0]) } ?? item).lowercased()
            let value = eq.map { String(item[item.index(after: $0)...]) }
            if item.isEmpty { fail("empty option"); continue }
            switch (name, value) {
            case ("cert-authority", nil): ca = true
            case ("no-touch-required", nil): noTouch = true
            case ("verify-required", nil): verify = true
            case ("namespaces", let v?):
                if namespaces != nil { fail("multiple namespaces clauses") }
                if let d = dequote(v) { namespaces = d } else { fail("bad namespaces value"); namespaces = "" }
            case ("valid-after", let v?), ("valid-before", let v?):
                let t = dequote(v).flatMap { parseTime($0, zone: zone) }
                if t == nil { fail("invalid \(name) time") }
                if name == "valid-after" {
                    if sawAfter { fail("multiple valid-after clauses") }
                    sawAfter = true; after = t
                } else {
                    if sawBefore { fail("multiple valid-before clauses") }
                    sawBefore = true; before = t
                }
            default:
                unknown.append(item)
            }
        }
        if let a = after, let b = before, !(b > a) { fail("valid-before is not after valid-after") }
        return AllowedSignerOptions(raw: raw, certAuthority: ca, namespaces: namespaces, validAfter: after,
                                    validBefore: before, noTouchRequired: noTouch, verifyRequired: verify,
                                    unknown: unknown, error: error)
    }

    /// Split on commas outside double quotes. Nil for an unterminated quote.
    static func splitItems(_ raw: String) -> [String]? {
        var items: [String] = []
        var cur = ""
        var quoted = false
        let c = Array(raw)
        var i = 0
        while i < c.count {
            if c[i] == "\\", i + 1 < c.count, c[i + 1] == "\"" { cur.append("\\\""); i += 2; continue }
            if c[i] == "\"" { quoted.toggle(); cur.append("\"") }
            else if c[i] == ",", !quoted { items.append(cur); cur = "" }
            else { cur.append(c[i]) }
            i += 1
        }
        if quoted { return nil }
        items.append(cur)
        return items
    }

    /// A quoted value loses its quotes (`\"` becomes `"`); the closing quote must end
    /// the item. An unquoted value is taken as is.
    static func dequote(_ v: String) -> String? {
        guard v.hasPrefix("\"") else { return v }
        let c = Array(v)
        var out = ""
        var i = 1
        while i < c.count {
            if c[i] == "\\", i + 1 < c.count, c[i + 1] == "\"" { out.append("\""); i += 2; continue }
            if c[i] == "\"" { return i == c.count - 1 ? out : nil }
            out.append(c[i])
            i += 1
        }
        return nil
    }

    /// OpenSSH parse_absolute_time. Nil if malformed, or not after the epoch.
    static func parseTime(_ s: String, zone: TimeZone) -> Date? {
        var body = s
        var utc = false
        if body.count > 1, body.uppercased().hasSuffix("Z") { utc = true; body.removeLast() }
        else if body.count > 3, body.uppercased().hasSuffix("UTC") { utc = true; body.removeLast(3) }
        guard [8, 12, 14].contains(body.count), body.allSatisfy({ ("0"..."9").contains($0) }) else { return nil }
        let d = Array(body)
        func num(_ from: Int, _ len: Int) -> Int { Int(String(d[from..<(from + len)]))! }
        var comps = DateComponents()
        comps.year = num(0, 4); comps.month = num(4, 2); comps.day = num(6, 2)
        comps.hour = body.count >= 12 ? num(8, 2) : 0
        comps.minute = body.count >= 12 ? num(10, 2) : 0
        comps.second = body.count == 14 ? num(12, 2) : 0
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = utc ? TimeZone(identifier: "UTC")! : zone
        // Reject out-of-range fields (month 13, Feb 30) instead of letting them roll over.
        guard let date = cal.date(from: comps) else { return nil }
        let back = cal.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        guard back.year == comps.year, back.month == comps.month, back.day == comps.day,
              back.hour == comps.hour, back.minute == comps.minute, back.second == comps.second else { return nil }
        return date.timeIntervalSince1970 > 0 ? date : nil
    }

    /// OpenSSH match_pattern_list (case-sensitive): 1 if a pattern matches, -1 if a `!`
    /// pattern matches (which wins), 0 if none does. Patterns aren't trimmed.
    static func matchPatternList(_ s: String, _ list: String) -> Int {
        var positive = false
        for entry in list.split(separator: ",", omittingEmptySubsequences: false) {
            let negated = entry.hasPrefix("!")
            let pattern = negated ? String(entry.dropFirst()) : String(entry)
            if globMatch(s, pattern) {
                if negated { return -1 }
                positive = true
            }
        }
        return positive ? 1 : 0
    }

    /// `*` matches any run (including none), `?` exactly one character. Iterative.
    static func globMatch(_ str: String, _ pat: String) -> Bool {
        let s = Array(str), p = Array(pat)
        var si = 0, pi = 0, star = -1, mark = 0
        while si < s.count {
            if pi < p.count && (p[pi] == "?" || p[pi] == s[si]) { si += 1; pi += 1 }
            else if pi < p.count && p[pi] == "*" { star = pi; pi += 1; mark = si }
            else if star >= 0 { pi = star + 1; mark += 1; si = mark }
            else { return false }
        }
        while pi < p.count && p[pi] == "*" { pi += 1 }
        return pi == p.count
    }
}

public enum AllowedSigners {

    /// Key types recognized as the start of the key field (used to tell whether
    /// the token after the principals is an options field or the key type).
    private static let knownKeyTypes: Set<String> = [
        "ssh-ed25519",
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com"
    ]

    /// Parse an allowed_signers file body. Unparseable lines are skipped.
    public static func parse(_ text: String) -> [AllowedSigner] {
        var out: [AllowedSigner] = []
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
                             .replacingOccurrences(of: "\r", with: "\n")
        for rawLine in normalized.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if let signer = parseLine(line) { out.append(signer) }
        }
        return out
    }

    /// Parse a single non-comment line, or nil if it isn't well-formed.
    ///
    /// Fields split on spaces and tabs, as ssh-keygen splits them, except that a
    /// principals field starting with a double quote runs to the closing quote, and an
    /// options field may hold spaces inside double quotes (`namespaces="a, b"`) (audit
    /// L-6). The options field is kept verbatim; `parsedOptions` interprets it.
    public static func parseLine(_ line: String) -> AllowedSigner? {
        let c = Array(line)
        var pos = 0
        func isSpace(_ ch: Character) -> Bool { ch == " " || ch == "\t" }
        func skipSpace() { while pos < c.count && isSpace(c[pos]) { pos += 1 } }
        func word() -> String? {
            skipSpace()
            guard pos < c.count else { return nil }
            let start = pos
            while pos < c.count && !isSpace(c[pos]) { pos += 1 }
            return String(c[start..<pos])
        }

        skipSpace()
        let principalsField: String
        if pos < c.count && c[pos] == "\"" {
            guard let close = c[(pos + 1)...].firstIndex(of: "\"") else { return nil }
            principalsField = String(c[(pos + 1)..<close])
            pos = close + 1
        } else {
            guard let w = word() else { return nil }
            principalsField = w
        }
        let principals = principalsField.split(separator: ",").map(String.init)
        guard !principals.isEmpty else { return nil }

        skipSpace()
        let afterPrincipals = pos
        var options: String?
        guard var keyType = word() else { return nil }
        if !knownKeyTypes.contains(keyType) {
            pos = afterPrincipals
            guard let opts = optionsField(c, from: pos) else { return nil }
            options = opts
            pos += opts.count
            guard let k = word() else { return nil }
            keyType = k
        }
        guard knownKeyTypes.contains(keyType) else { return nil }
        guard let keyBase64 = word(), Data(base64Encoded: keyBase64) != nil else { return nil }
        var rest: [String] = []
        while let w = word() { rest.append(w) }
        return AllowedSigner(principals: principals, options: options, keyType: keyType,
                             keyBase64: keyBase64, comment: rest.isEmpty ? nil : rest.joined(separator: " "))
    }

    /// The options field starting at `from`: OpenSSH sshkey_advance_past_options, which
    /// stops at the first space or tab outside double quotes and skips `\"`.
    static func optionsField(_ c: [Character], from: Int) -> String? {
        var i = from
        var quoted = false
        while i < c.count && (quoted || (c[i] != " " && c[i] != "\t")) {
            if c[i] == "\\" && i + 1 < c.count && c[i + 1] == "\"" { i += 1 }
            else if c[i] == "\"" { quoted.toggle() }
            i += 1
        }
        return quoted ? nil : String(c[from..<i])
    }

    /// Serialize signers back into allowed_signers file text (LF-terminated).
    public static func serialize(_ signers: [AllowedSigner]) -> String {
        var out = ""
        for s in signers {
            let joined = s.principals.joined(separator: ",")
            // A principal with a space only survives the round trip quoted (see parseLine).
            var fields: [String] = [joined.contains(where: { $0 == " " || $0 == "\t" }) ? "\"\(joined)\"" : joined]
            if let opts = s.options, !opts.isEmpty { fields.append(opts) }
            fields.append(s.keyType)
            fields.append(s.keyBase64)
            if let c = s.comment, !c.isEmpty { fields.append(c) }
            out.append(fields.joined(separator: " "))
            out.append("\n")
        }
        return out
    }

    /// Build a signer entry from an SSH public-key line (`keytype base64 [comment]`)
    /// for one or more principals. Convenient for "promote recipient to signer".
    public static func makeSigner(
        principals: [String],
        sshPublicKeyLine: String,
        namespaceRestricted: Bool = false
    ) -> AllowedSigner? {
        let parts = sshPublicKeyLine
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: " ", omittingEmptySubsequences: true)
            .map(String.init)
        guard parts.count >= 2 else { return nil }
        let keyType = parts[0]
        guard knownKeyTypes.contains(keyType) else { return nil }
        let keyBase64 = parts[1]
        guard Data(base64Encoded: keyBase64) != nil else { return nil }
        let comment = parts.count >= 3 ? parts[2...].joined(separator: " ") : nil
        let options = namespaceRestricted ? "namespaces=\"\(SSHSig.defaultNamespace)\"" : nil
        return AllowedSigner(
            principals: principals,
            options: options,
            keyType: keyType,
            keyBase64: keyBase64,
            comment: comment
        )
    }
}
