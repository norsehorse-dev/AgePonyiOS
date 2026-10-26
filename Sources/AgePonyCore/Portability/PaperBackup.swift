//
//  PaperBackup.swift
//  AgePonyCore
//
//  Paper backups of age identities (Android 5.0.0).
//
//  The default protects the page with a passphrase: the identity file is encrypted to an
//  age scrypt recipient and armored, so the QR code and the printed text are an ordinary
//  age file. Restoring needs AgePony or plain `age -d`, so the paper outlives the app.
//
//  The plain form is the bare identity file. Whoever reads that page holds the key.
//
//  Mirrors Android agepony-core `portability/PaperBackup.kt`.
//

import Foundation

public enum PaperBackupError: Error, Equatable {
    case emptyPassphrase
    case notSealed
    case damaged
    case wrongPassphrase
}

public enum PaperBackup {
    /// age's own default work factor: about 256 MB and a second or so to restore on a phone.
    public static let defaultWorkFactor = 18

    static let armorBegin = "-----BEGIN AGE ENCRYPTED FILE-----"

    /// Passphrase-protected, armored age text of `identityFile`.
    public static func seal(identityFile: String, passphrase: String, workFactor: Int = defaultWorkFactor) throws -> String {
        guard !passphrase.isEmpty else { throw PaperBackupError.emptyPassphrase }
        let ct = try Age.encrypt(plaintext: Data(identityFile.utf8), to: [ScryptRecipient(passphrase: passphrase, workFactor: workFactor)])
        return AgeArmor.encode(ct)
    }

    /// True if `scanned` is a passphrase-protected page rather than a plain identity file.
    public static func isSealed(_ scanned: String) -> Bool { scanned.contains(armorBegin) }

    /// Recover the identity file text from a sealed page.
    public static func open(armored: String, passphrase: String) throws -> String {
        guard let start = armored.range(of: armorBegin) else { throw PaperBackupError.notSealed }
        let binary: Data
        do {
            binary = try AgeArmor.decode(String(armored[start.lowerBound...]))
        } catch {
            throw PaperBackupError.damaged
        }
        do {
            return String(decoding: try Age.decrypt(ciphertext: binary, passphrase: passphrase), as: UTF8.self)
        } catch AgeError.wrongPassphrase {
            throw PaperBackupError.wrongPassphrase
        } catch AgeError.noMatchingIdentity {
            throw PaperBackupError.wrongPassphrase
        }
    }

    /// Secret-key lines in an identity file, in order, upper-cased. Accepts an identity
    /// file with comments, or a bare pasted key.
    public static func secretKeys(identityFile: String) -> [String] {
        identityFile.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.uppercased().hasPrefix("AGE-SECRET-KEY-") }
            .map { $0.uppercased() }
    }

    /// The `# name:` comment preceding each secret key, when the file carries one.
    public static func namesByKey(identityFile: String) -> [String: String] {
        var out: [String: String] = [:]
        var pending: String?
        for raw in identityFile.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("# name:") {
                pending = String(line.dropFirst("# name:".count)).trimmingCharacters(in: .whitespaces)
            } else if line.uppercased().hasPrefix("AGE-SECRET-KEY-") {
                if let pending { out[line.uppercased()] = pending }
                pending = nil
            }
        }
        return out
    }

    /// Split `text` into groups for hand transcription: 4-character groups, `perLine`
    /// groups per line.
    public static func transcriptionGroups(_ text: String, perLine: Int = 6) -> [String] {
        let chars = Array(text)
        let groups = stride(from: 0, to: chars.count, by: 4).map { String(chars[$0..<min($0 + 4, chars.count)]) }
        return stride(from: 0, to: groups.count, by: perLine).map { groups[$0..<min($0 + perLine, groups.count)].joined(separator: " ") }
    }
}
