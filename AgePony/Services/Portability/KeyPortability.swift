//
//  KeyPortability.swift
//  AgePony
//
//  Moving keys between devices and on and off paper (5.0.1, parity with Android 5.0.0).
//  The wire formats live in AgePonyCore (KeyTransfer, PaperBackup); this file decides what
//  AgePony puts in them and how what comes back is merged into the vault.
//
//  `agepony.json` uses Android's record shapes (decision Q6), so a transfer opens on either
//  platform. The two vaults store a few key types differently, and the conversion happens
//  here, nowhere else:
//
//    type            iOS vault                          agepony.json (Android)
//    x25519          pub 32 raw, priv 32                same, "x25519"
//    postQuantum     pub 1216, priv 32-byte seed        same, "mlkem768x25519"
//    sshEd25519      pub = SSH wire blob,               pub = 32-byte raw key,
//                    priv = seed(32) || pub(32)         priv = 32-byte seed
//    sshRSA          pub = SSH wire blob,               pub = UTF-8 `ssh-rsa BASE64 [comment]`,
//                    priv = OpenSSH PEM                 priv = OpenSSH PEM
//    yubikey         pub 33 compressed, priv 9 stub     same, "yubikeyPiv"
//    skEd25519 / skEcdsaP256: pub = sk wire, priv = credential id, same on both
//
//  Recipients follow the same split (ssh-ed25519 raw vs wire, ssh-rsa line vs wire;
//  `yubikey` is "yubikeyP256"). Hardware-bound identities (Secure Enclave here, Keystore
//  on Android) never leave the device and are dropped on both ends.
//
//  Mirrors Android `vault/KeyPortability.kt`.
//

import Foundation
import CryptoKit
import Security
import AgePonyCore

// MARK: - agepony.json (Android's shapes)

/// The `agepony.json` entry of a key transfer.
struct TransferMetadata: Codable {
    var format: String = KeyTransfer.formatLine
    var app: String = "AgePony iOS"
    var identities: [WireIdentity] = []
    var recipients: [WireRecipient] = []
    var signers: [WireSigner] = []
}

/// Android `StoredIdentity`.
struct WireIdentity: Codable, Equatable {
    var id: String
    var name: String
    var type: String
    var publicKeyB64: String
    var privateKeyB64: String
    var sshComment: String?
    var keystoreAlias: String?
    var createdAt: Int64
}

/// Android `StoredRecipient`.
struct WireRecipient: Codable, Equatable {
    var id: String
    var name: String
    var type: String
    var publicKeyB64: String
    var sshComment: String?
    var source: String
    var sourceMetadata: String?
    var createdAt: Int64
}

/// Android `StoredSigner`.
struct WireSigner: Codable, Equatable {
    var id: String
    var name: String
    var keyType: String
    var publicKeyWireB64: String
    var comment: String?
    var source: String
    var createdAt: Int64
    var options: String?
}

/// A trusted signer as it arrived, before the user decides on it. Carries the
/// allowed_signers options this vault can't store (see `refusalReason`).
struct IncomingSigner: Identifiable {
    let signer: StoredSigner
    let options: String?
    var id: UUID { signer.id }

    /// Why this entry can't be imported, or nil. The iOS vault keeps no
    /// allowed_signers options, so an entry restricted by them (a namespace, a
    /// validity window, a CA key) would lose its restrictions here. Skipped
    /// instead of silently trusted more widely than it was (audit L-6).
    var refusalReason: String? {
        guard let o = options?.trimmingCharacters(in: .whitespaces), !o.isEmpty else { return nil }
        return "It carries allowed_signers restrictions (\(o)) that AgePony on iPhone can't keep, so it isn't imported."
    }
}

enum KeyPortability {

    // MARK: What may move

    /// Identity kinds that can leave this device. Secure Enclave keys never can.
    static func isTransferable(_ identity: StoredIdentity) -> Bool {
        switch identity.type {
        case .secureEnclaveTag, .secureEnclaveTagPQ, .secureEnclaveP256: return false
        case .x25519, .postQuantum, .yubikey, .sshEd25519, .sshRSA, .skEd25519, .skEcdsaP256: return true
        }
    }

    /// Identity kinds a paper backup supports: the age keys, whose secret is a short string.
    static func isPaperBackable(_ identity: StoredIdentity) -> Bool {
        identity.type == .x25519 || identity.type == .postQuantum
    }

    /// The age identity-file entry for an age identity, or nil for other kinds.
    static func identityLine(_ identity: StoredIdentity) -> KeyTransfer.IdentityLine? {
        let created = iso(identity.createdAt)
        switch identity.type {
        case .x25519:
            guard let id = try? X25519Identity(privateKey: identity.privateKeyMaterial) else { return nil }
            return .init(name: identity.name, publicKey: id.ageRecipient, secretKey: id.ageIdentityString, createdISO: created)
        case .postQuantum:
            guard let id = try? HybridIdentity(seed: identity.privateKeyMaterial),
                  let r = try? id.recipient() else { return nil }
            return .init(name: identity.name, publicKey: r.ageRecipient, secretKey: id.ageIdentityString, createdISO: created)
        case .yubikey:
            // A plugin identity line; `age -i` uses it with age-plugin-yubikey installed.
            guard let stub = identity.yubiKeyStub else { return nil }
            return .init(name: identity.name,
                         publicKey: Bech32.encodeYubiKeyRecipient(Array(identity.publicKeyMaterial)),
                         secretKey: stub.encode(), createdISO: created)
        default:
            return nil
        }
    }

    // MARK: Sending

    static func buildBundle(identities: [StoredIdentity],
                            recipients: [StoredRecipient],
                            signers: [StoredSigner]) throws -> KeyTransfer.Bundle {
        let movable = identities.filter(isTransferable)
        let identitiesTxt = KeyTransfer.identityFile(movable.compactMap(identityLine))

        // OpenSSH private keys as files too, so `age -d | tar x` gives keys ssh can use.
        var ssh: [String: String] = [:]
        for identity in movable where identity.type == .sshRSA || identity.type == .sshEd25519 {
            let pem = identity.privateDisplayString()
            guard pem.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----") else { continue }
            var key = identity.name
            var n = 2
            while ssh[key] != nil { key = "\(identity.name)-\(n)"; n += 1 }
            ssh[key] = pem
        }

        var meta = TransferMetadata()
        meta.identities = movable.compactMap(wire)
        meta.recipients = recipients.compactMap(wire)
        meta.signers = signers.map(wire)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let json = String(decoding: try encoder.encode(meta), as: UTF8.self)
        return KeyTransfer.Bundle(identitiesTxt: identitiesTxt, sshKeys: ssh, metadataJSON: json)
    }

    // MARK: Receiving

    /// What an incoming transfer holds, before anything is written.
    struct Incoming {
        var identities: [StoredIdentity]
        var recipients: [StoredRecipient]
        var signers: [IncomingSigner]
    }

    /// Read what a transfer holds. Each record is decoded on its own, so one entry this
    /// version doesn't understand (a newer key type, say) is skipped instead of discarding
    /// the rest. Identities whose private key doesn't produce their stated public key are
    /// dropped, and so are recipients and signers whose key doesn't parse.
    static func readBundle(_ bundle: KeyTransfer.Bundle) -> Incoming {
        if let data = bundle.metadataJSON.data(using: .utf8),
           let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            func each<T: Decodable>(_ key: String, _: T.Type) -> [T] {
                guard let array = root[key] as? [Any] else { return [] }
                return array.compactMap { element in
                    guard JSONSerialization.isValidJSONObject(element),
                          let bytes = try? JSONSerialization.data(withJSONObject: element) else { return nil }
                    return try? JSONDecoder().decode(T.self, from: bytes)
                }
            }
            let ids = each("identities", WireIdentity.self).compactMap(storedIdentity)
                .filter { isTransferable($0) && isConsistent($0) }
            let recips = each("recipients", WireRecipient.self).compactMap(storedRecipient)
                .filter { (try? $0.toAgeRecipient()) != nil }
            let signers = each("signers", WireSigner.self).compactMap(incomingSigner)
            return Incoming(identities: ids, recipients: recips, signers: signers)
        }
        // No AgePony metadata (a hand-built transfer): the plain identity file and SSH keys.
        var ids = identitiesFromText(bundle.identitiesTxt)
        for name in bundle.sshKeys.keys.sorted() {
            if let pem = bundle.sshKeys[name],
               let id = try? SSHIdentityImporter.makeStoredIdentity(fromOpenSSHPEM: pem, passphrase: nil, name: name) {
                ids.append(id)
            }
        }
        return Incoming(identities: ids, recipients: [], signers: [])
    }

    /// Parse the age secret keys in an identity file into vault records, keeping `# name:`
    /// labels. X25519 and post-quantum keys only.
    static func identitiesFromText(_ identityFile: String) -> [StoredIdentity] {
        let names = PaperBackup.namesByKey(identityFile: identityFile)
        var out: [StoredIdentity] = []
        for (i, secret) in PaperBackup.secretKeys(identityFile: identityFile).enumerated() {
            let name = names[secret] ?? "restored key \(i + 1)"
            if secret.hasPrefix("AGE-SECRET-KEY-PQ-") {
                guard let pq = try? HybridIdentity(ageIdentity: secret) else { continue }
                out.append(StoredIdentity(name: name, type: .postQuantum,
                                          publicKeyMaterial: pq.publicKey, privateKeyMaterial: pq.seed))
            } else if let x = try? X25519Identity(ageIdentity: secret) {
                out.append(StoredIdentity(name: name, type: .x25519,
                                          publicKeyMaterial: x.publicKey, privateKeyMaterial: x.privateKey))
            }
        }
        return out
    }

    struct ImportSummary {
        var identitiesAdded = 0
        var recipientsAdded = 0
        var signersAdded = 0
        var skipped = 0
    }

    /// Merge `incoming` into the vault, skipping anything already present (same type and
    /// public key). The caller passes only the entries the user chose; signers in particular
    /// must be ones the user ticked (audit M-6). Imported identities never become the active
    /// identity: a key that arrived from elsewhere must not quietly turn into the
    /// encrypt-to-self key.
    @discardableResult
    static func importInto(_ vault: Vault, _ incoming: Incoming) throws -> ImportSummary {
        var s = ImportSummary()
        for identity in incoming.identities {
            if !isTransferable(identity) || isKnown(vault, identity) { s.skipped += 1; continue }
            try vault.addIdentity(fresh(identity), activate: false)
            s.identitiesAdded += 1
        }
        for r in incoming.recipients {
            if isKnown(vault, r) { s.skipped += 1; continue }
            try vault.addRecipient(fresh(r))
            s.recipientsAdded += 1
        }
        for inc in incoming.signers {
            if inc.refusalReason != nil || isKnown(vault, inc.signer) { s.skipped += 1; continue }
            try vault.addSigner(fresh(inc.signer))
            s.signersAdded += 1
        }
        return s
    }

    // MARK: Preview helpers (audit M-6)

    /// Already in the vault (or its recycle bin) with the same type and key: import skips it.
    static func isKnown(_ vault: Vault, _ identity: StoredIdentity) -> Bool {
        (vault.identities + vault.trashedIdentities.map(\.identity)).contains {
            $0.type == identity.type && $0.publicKeyMaterial == identity.publicKeyMaterial
        }
    }

    static func isKnown(_ vault: Vault, _ recipient: StoredRecipient) -> Bool {
        vault.recipients.contains { $0.type == recipient.type && $0.publicKeyMaterial == recipient.publicKeyMaterial }
    }

    static func isKnown(_ vault: Vault, _ signer: StoredSigner) -> Bool {
        vault.signers.contains { $0.publicKeyWire == signer.publicKeyWire }
    }

    /// An existing entry with the same name but a different key. Two keys under one name
    /// is how a planted key passes for a real one, so the preview warns.
    static func nameClash(_ vault: Vault, _ identity: StoredIdentity) -> StoredIdentity? {
        if isKnown(vault, identity) { return nil }
        return vault.identities.first { sameName($0.name, identity.name) }
    }

    static func nameClash(_ vault: Vault, _ recipient: StoredRecipient) -> StoredRecipient? {
        if isKnown(vault, recipient) { return nil }
        return vault.recipients.first { sameName($0.name, recipient.name) }
    }

    /// A signer's name is what a verified file shows, so it may not reuse a signer's or an
    /// identity's name.
    static func nameClash(_ vault: Vault, _ signer: StoredSigner) -> String? {
        if isKnown(vault, signer) { return nil }
        if vault.signers.contains(where: { sameName($0.name, signer.name) }) { return "a trusted signer" }
        if vault.identities.contains(where: { sameName($0.name, signer.name) }) { return "one of your identities" }
        return nil
    }

    /// The key as the preview shows it: `SHA256:` fingerprint for SSH keys, the shortened
    /// key string otherwise.
    static func keySummary(_ identity: StoredIdentity) -> String {
        switch identity.type {
        case .sshEd25519, .sshRSA, .skEd25519, .skEcdsaP256, .secureEnclaveP256:
            return FileVerifier.sshFingerprint(wireBlob: identity.publicKeyMaterial)
        default:
            return shorten(identity.publicDisplayString())
        }
    }

    static func keySummary(_ recipient: StoredRecipient) -> String {
        switch recipient.type {
        case .sshEd25519, .sshRSA:
            return FileVerifier.sshFingerprint(wireBlob: recipient.publicKeyMaterial)
        default:
            return shorten(recipient.publicDisplayString())
        }
    }

    static func typeLabel(_ t: StoredIdentityType) -> String {
        switch t {
        case .x25519: return "age X25519"
        case .postQuantum: return "Quantum-safe (ML-KEM-768 + X25519)"
        case .sshEd25519: return "SSH Ed25519"
        case .sshRSA: return "SSH RSA"
        case .secureEnclaveP256: return "Hardware key"
        case .skEd25519: return "Security key (Ed25519)"
        case .skEcdsaP256: return "Security key (P-256)"
        case .secureEnclaveTag: return "Hardware key (age1tag)"
        case .secureEnclaveTagPQ: return "Hardware key, quantum-safe (age1tagpq)"
        case .yubikey: return "YubiKey (PIV)"
        }
    }

    static func typeLabel(_ t: StoredRecipientType) -> String {
        switch t {
        case .x25519: return "age X25519"
        case .postQuantum: return "Quantum-safe (ML-KEM-768 + X25519)"
        case .sshEd25519: return "SSH Ed25519"
        case .sshRSA: return "SSH RSA"
        case .yubikey: return "YubiKey (P-256)"
        case .tag: return "Hardware key (age1tag)"
        case .tagPQ: return "Hardware key, quantum-safe (age1tagpq)"
        }
    }

    /// A note for identities whose public key can't be fully checked here (audit AS-2):
    /// for a security key or a YubiKey the private half stays on the device.
    static func unverifiableNote(_ identity: StoredIdentity) -> String? {
        switch identity.type {
        case .skEd25519, .skEcdsaP256:
            return "Lives on a security key: its public key can't be checked without that key."
        case .yubikey:
            return "Lives on a YubiKey: decrypting with it needs that YubiKey."
        default:
            return nil
        }
    }

    // MARK: Consistency (audit AS-2)

    /// The stored public key must be the one the private material gives: otherwise a
    /// transfer could pair someone else's public key with a private key, and the vault would
    /// encrypt to (or trust signatures from) a key the user doesn't hold.
    static func isConsistent(_ identity: StoredIdentity) -> Bool {
        let pub = identity.publicKeyMaterial
        let priv = identity.privateKeyMaterial
        switch identity.type {
        case .x25519:
            return (try? X25519Identity(privateKey: priv))?.publicKey == pub
        case .postQuantum:
            return (try? HybridIdentity(seed: priv))?.publicKey == pub
        case .sshEd25519:
            guard priv.count == 64,
                  let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: priv.prefix(32)),
                  key.publicKey.rawRepresentation == priv.suffix(32),
                  let recipient = try? SSHEd25519Recipient(edPublicKey: Data(priv.suffix(32))) else { return false }
            return recipient.wireBlob == pub
        case .sshRSA:
            return rsaPairMatches(pem: priv, publicWire: pub)
        case .yubikey:
            // No secret travels: the stub points at a YubiKey slot. Its tag is a hash of the
            // slot's public key, so the stored key must be a valid point with that hash.
            guard (try? P256Recipient(compressedPublicKey: pub)) != nil,
                  let stub = try? YubiKeyStub(bytes: priv) else { return false }
            return stub.matchesKey(compressedPublicKey: pub)
        case .skEd25519:
            // A credential id is opaque; what can be checked is a well-formed key on a valid point.
            guard (1...1023).contains(priv.count),
                  let parts = try? SSHSig.skEd25519Components(fromWire: pub),
                  (try? Ed25519Conversion.publicKeyToX25519(edPublicKey: parts.publicKey)) != nil else { return false }
            return SSHSig.skEd25519PublicKeyWire(rawPublicKey: parts.publicKey, application: parts.application) == pub
        case .skEcdsaP256:
            guard (1...1023).contains(priv.count),
                  let parts = try? SSHSig.skEcdsaP256Components(fromWire: pub),
                  (try? P256.Signing.PublicKey(x963Representation: parts.q)) != nil else { return false }
            return SSHSig.skEcdsaP256PublicKeyWire(x963Q: parts.q, application: parts.application) == pub
        case .secureEnclaveTag, .secureEnclaveTagPQ, .secureEnclaveP256:
            return false
        }
    }

    /// The PEM parses, its public half is the stated one, and the private key really is the
    /// other half of it: a test signature made with it verifies under the stated key.
    private static func rsaPairMatches(pem: Data, publicWire: Data) -> Bool {
        guard let text = String(data: pem, encoding: .utf8),
              let parts = try? SSHRSAKeyParser.parseOpenSSHPrivateKey(text),
              let stated = try? SSHSig.rsaComponents(fromWire: publicWire),
              let inner = try? SSHSig.rsaComponents(fromWire: parts.wireBlob),
              stripZeros(stated.n) == stripZeros(inner.n), stripZeros(stated.e) == stripZeros(inner.e),
              let identity = try? SSHRSAIdentity(openSSHPrivateKey: text),
              let statedKey = try? SSHRSARecipient(sshPublicKeyLine: "ssh-rsa " + publicWire.base64EncodedString()) else {
            return false
        }
        let probe = Data("agepony transfer key check".utf8)
        let alg = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        guard let sig = SecKeyCreateSignature(identity.privateSecKey, alg, probe as CFData, nil) else { return false }
        return SecKeyVerifySignature(statedKey.publicSecKey, alg, probe as CFData, sig, nil)
    }

    private static func stripZeros(_ d: Data) -> Data { Data(d.drop(while: { $0 == 0 })) }

    // MARK: iOS <-> agepony.json

    static func wire(_ i: StoredIdentity) -> WireIdentity? {
        let type: String
        var pub = i.publicKeyMaterial
        var priv = i.privateKeyMaterial
        switch i.type {
        case .x25519: type = "x25519"
        case .postQuantum: type = "mlkem768x25519"
        case .sshEd25519:
            type = "sshEd25519"
            guard priv.count == 64 else { return nil }
            pub = Data(priv.suffix(32))
            priv = Data(priv.prefix(32))
        case .sshRSA:
            type = "sshRSA"
            pub = Data(rsaLine(wire: i.publicKeyMaterial, comment: i.sshComment).utf8)
        case .yubikey: type = "yubikeyPiv"
        case .skEd25519: type = "skEd25519"
        case .skEcdsaP256: type = "skEcdsaP256"
        case .secureEnclaveTag, .secureEnclaveTagPQ, .secureEnclaveP256: return nil
        }
        return WireIdentity(id: i.id.uuidString.lowercased(), name: i.name, type: type,
                            publicKeyB64: pub.base64EncodedString(), privateKeyB64: priv.base64EncodedString(),
                            sshComment: i.sshComment, keystoreAlias: nil, createdAt: millis(i.createdAt))
    }

    static func storedIdentity(_ w: WireIdentity) -> StoredIdentity? {
        guard let pub = Data(base64Encoded: w.publicKeyB64), let priv = Data(base64Encoded: w.privateKeyB64) else { return nil }
        let type: StoredIdentityType
        var publicMaterial = pub
        var privateMaterial = priv
        var comment = w.sshComment
        switch w.type {
        case "x25519": type = .x25519
        case "mlkem768x25519": type = .postQuantum
        case "sshEd25519":
            type = .sshEd25519
            guard pub.count == 32, priv.count == 32 else { return nil }
            publicMaterial = SSHSig.ed25519PublicKeyWire(pub)
            privateMaterial = priv + pub
        case "sshRSA":
            type = .sshRSA
            guard let line = String(data: pub, encoding: .utf8),
                  let parsed = try? SSHRSAKeyParser.parsePublicKey(line) else { return nil }
            publicMaterial = parsed.wireBlob
            if comment == nil, !parsed.comment.isEmpty { comment = parsed.comment }
        case "yubikeyPiv": type = .yubikey
        case "skEd25519": type = .skEd25519
        case "skEcdsaP256": type = .skEcdsaP256
        default: return nil // hardware-bound on the sender, or a type this version doesn't know
        }
        return StoredIdentity(id: UUID(), name: w.name, type: type, publicKeyMaterial: publicMaterial,
                              privateKeyMaterial: privateMaterial, sshComment: comment, createdAt: date(w.createdAt))
    }

    static func wire(_ r: StoredRecipient) -> WireRecipient? {
        let type: String
        var pub = r.publicKeyMaterial
        switch r.type {
        case .x25519: type = "x25519"
        case .postQuantum: type = "mlkem768x25519"
        case .sshEd25519:
            type = "sshEd25519"
            guard let raw = try? StoredRecipient.extractEd25519PublicKey(fromWireBlob: r.publicKeyMaterial) else { return nil }
            pub = raw
        case .sshRSA:
            type = "sshRSA"
            pub = Data(rsaLine(wire: r.publicKeyMaterial, comment: r.sshComment).utf8)
        case .yubikey: type = "yubikeyP256"
        case .tag: type = "tag"
        case .tagPQ: type = "tagPQ"
        }
        // Android has no "contacts" source; it would drop the record.
        let source: String
        switch r.source {
        case .contacts: source = r.type.pastedSource.rawValue
        default: source = r.source.rawValue
        }
        return WireRecipient(id: r.id.uuidString.lowercased(), name: r.name, type: type,
                             publicKeyB64: pub.base64EncodedString(), sshComment: r.sshComment, source: source,
                             sourceMetadata: r.sourceMetadata, createdAt: millis(r.createdAt))
    }

    static func storedRecipient(_ w: WireRecipient) -> StoredRecipient? {
        guard let pub = Data(base64Encoded: w.publicKeyB64) else { return nil }
        let type: StoredRecipientType
        var material = pub
        var comment = w.sshComment
        switch w.type {
        case "x25519": type = .x25519
        case "mlkem768x25519": type = .postQuantum
        case "sshEd25519":
            type = .sshEd25519
            guard pub.count == 32 else { return nil }
            material = SSHSig.ed25519PublicKeyWire(pub)
        case "sshRSA":
            type = .sshRSA
            guard let line = String(data: pub, encoding: .utf8),
                  let parsed = try? SSHRSAKeyParser.parsePublicKey(line) else { return nil }
            material = parsed.wireBlob
            if comment == nil, !parsed.comment.isEmpty { comment = parsed.comment }
        case "yubikeyP256": type = .yubikey
        case "tag": type = .tag
        case "tagPQ": type = .tagPQ
        default: return nil
        }
        let source = StoredRecipientSource(rawValue: w.source) ?? type.pastedSource
        return StoredRecipient(id: UUID(), name: w.name, type: type, publicKeyMaterial: material,
                               sshComment: comment, source: source, sourceMetadata: w.sourceMetadata,
                               createdAt: date(w.createdAt))
    }

    static func wire(_ s: StoredSigner) -> WireSigner {
        WireSigner(id: s.id.uuidString.lowercased(), name: s.name, keyType: s.keyType,
                   publicKeyWireB64: s.publicKeyWire.base64EncodedString(), comment: s.comment,
                   source: s.source.rawValue, createdAt: millis(s.createdAt), options: nil)
    }

    /// A signer whose stored wire decodes and starts with its stated key type.
    static func incomingSigner(_ w: WireSigner) -> IncomingSigner? {
        guard let wire = Data(base64Encoded: w.publicKeyWireB64), let wireType = sshKeyType(wire),
              wireType == w.keyType || (wireType == "ssh-rsa" && w.keyType.hasPrefix("rsa-sha2-")) else { return nil }
        let signer = StoredSigner(id: UUID(), name: w.name, keyType: w.keyType, publicKeyWire: wire,
                                  comment: w.comment, source: StoredSigner.Source(rawValue: w.source) ?? .pasteKey,
                                  createdAt: date(w.createdAt))
        return IncomingSigner(signer: signer, options: w.options)
    }

    // MARK: Small helpers

    private static func fresh(_ i: StoredIdentity) -> StoredIdentity {
        StoredIdentity(id: UUID(), name: i.name, type: i.type, publicKeyMaterial: i.publicKeyMaterial,
                       privateKeyMaterial: i.privateKeyMaterial, sshComment: i.sshComment, createdAt: i.createdAt)
    }

    private static func fresh(_ r: StoredRecipient) -> StoredRecipient {
        StoredRecipient(id: UUID(), name: r.name, type: r.type, publicKeyMaterial: r.publicKeyMaterial,
                        sshComment: r.sshComment, source: r.source, sourceMetadata: r.sourceMetadata, createdAt: r.createdAt)
    }

    private static func fresh(_ s: StoredSigner) -> StoredSigner {
        StoredSigner(id: UUID(), name: s.name, keyType: s.keyType, publicKeyWire: s.publicKeyWire,
                     comment: s.comment, source: s.source, createdAt: s.createdAt)
    }

    private static func rsaLine(wire: Data, comment: String?) -> String {
        let c = comment?.trimmingCharacters(in: .whitespaces) ?? ""
        return "ssh-rsa " + wire.base64EncodedString() + (c.isEmpty ? "" : " " + c)
    }

    /// The key type string at the front of an SSH public-key wire blob.
    private static func sshKeyType(_ wire: Data) -> String? {
        let b = Array(wire)
        guard b.count >= 4 else { return nil }
        let n = Int(b[0]) << 24 | Int(b[1]) << 16 | Int(b[2]) << 8 | Int(b[3])
        guard n > 0, n <= 64, b.count >= 4 + n else { return nil }
        return String(bytes: b[4..<(4 + n)], encoding: .utf8)
    }

    private static func sameName(_ a: String, _ b: String) -> Bool {
        a.trimmingCharacters(in: .whitespaces).caseInsensitiveCompare(b.trimmingCharacters(in: .whitespaces)) == .orderedSame
    }

    private static func shorten(_ s: String) -> String {
        s.count <= 28 ? s : "\(s.prefix(16))…\(s.suffix(8))"
    }

    private static func millis(_ d: Date) -> Int64 { Int64((d.timeIntervalSince1970 * 1000).rounded()) }

    private static func date(_ millis: Int64) -> Date { Date(timeIntervalSince1970: TimeInterval(millis) / 1000) }

    private static func iso(_ d: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: d)
    }
}
