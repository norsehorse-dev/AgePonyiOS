//
//  StoredRecipient+Hydration.swift
//  AgePony
//
//  Extension on StoredRecipient mirroring the hydration helpers defined
//  on StoredIdentity in 1c. Kept as a separate extension file so 1c's
//  VaultModels.swift stays untouched by 1e — easier to review the diff
//  and impossible to accidentally drop existing content from VaultModels.
//
//  Hydrates the persisted public-key bytes back into the matching
//  concrete crypto-layer recipient type (X25519Recipient,
//  SSHEd25519Recipient, SSHRSARecipient).
//

import Foundation
import AgePonyCore

public extension StoredRecipient {

    /// Construct the concrete crypto-layer recipient. Used by the
    /// EncryptFlow when building the `[AgeRecipient]` list passed to
    /// `Age.encrypt(plaintext:to:)`.
    func toAgeRecipient() throws -> any AgeRecipient {
        switch type {
        case .x25519:
            return try X25519Recipient(publicKey: publicKeyMaterial)
        case .sshEd25519:
            let edPub = try Self.extractEd25519PublicKey(fromWireBlob: publicKeyMaterial)
            return try SSHEd25519Recipient(edPublicKey: edPub)
        case .sshRSA:
            let b64 = publicKeyMaterial.base64EncodedString()
            let line = "ssh-rsa \(b64)" + (sshComment.map { " \($0)" } ?? "")
            return try SSHRSARecipient(sshPublicKeyLine: line)
        }
    }

    /// Human-readable form of the public key — `age1...` for X25519, or
    /// `ssh-* BASE64 [comment]` for the SSH types. Used by the row in
    /// RecipientListView and on the detail view.
    func publicDisplayString() -> String {
        switch type {
        case .x25519:
            // For x25519 recipients, derive the `age1...` form from the raw
            // public key bytes. We can't reuse X25519Identity's accessor
            // because we don't have a private key — go through Bech32 directly.
            return Bech32.encodeAgeRecipient(Array(publicKeyMaterial))
        case .sshEd25519:
            let b64 = publicKeyMaterial.base64EncodedString()
            return "ssh-ed25519 \(b64)" + (sshComment.map { " \($0)" } ?? "")
        case .sshRSA:
            let b64 = publicKeyMaterial.base64EncodedString()
            return "ssh-rsa \(b64)" + (sshComment.map { " \($0)" } ?? "")
        }
    }

    // MARK: - Internal

    /// SSH ed25519 wire blob layout: `<len=11>"ssh-ed25519"<len=32><pubkey>`.
    /// Same helper that lives privately on StoredIdentity in 1c — duplicated
    /// here rather than touching VaultModels.swift.
    static func extractEd25519PublicKey(fromWireBlob blob: Data) throws -> Data {
        guard blob.count >= 4 else { throw StoredRecipientHydrationError.malformedWireBlob }
        let len1 = UInt32(blob[blob.startIndex])     << 24
                 | UInt32(blob[blob.startIndex + 1]) << 16
                 | UInt32(blob[blob.startIndex + 2]) << 8
                 | UInt32(blob[blob.startIndex + 3])
        let typeStart = blob.startIndex + 4
        let typeEnd   = typeStart + Int(len1)
        guard typeEnd <= blob.endIndex else { throw StoredRecipientHydrationError.malformedWireBlob }
        let typeBytes = blob[typeStart..<typeEnd]
        guard String(data: typeBytes, encoding: .utf8) == "ssh-ed25519" else {
            throw StoredRecipientHydrationError.malformedWireBlob
        }
        let lenIdx = typeEnd
        guard lenIdx + 4 <= blob.endIndex else { throw StoredRecipientHydrationError.malformedWireBlob }
        let len2 = UInt32(blob[lenIdx])     << 24
                 | UInt32(blob[lenIdx + 1]) << 16
                 | UInt32(blob[lenIdx + 2]) << 8
                 | UInt32(blob[lenIdx + 3])
        let pubStart = lenIdx + 4
        let pubEnd   = pubStart + Int(len2)
        guard pubEnd <= blob.endIndex, len2 == 32 else {
            throw StoredRecipientHydrationError.malformedWireBlob
        }
        return Data(blob[pubStart..<pubEnd])
    }
}

public enum StoredRecipientHydrationError: Error, Equatable {
    case malformedWireBlob
}
