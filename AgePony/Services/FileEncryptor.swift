//
//  FileEncryptor.swift
//  AgePony
//
//  Hotfix 2 on 1g: passphrase workFactor lowered from 18 to 16.
//  workFactor=18 means N=262144 scrypt iterations and ~256 MiB memory,
//  which translates to 20-60 seconds on iPhone in Release builds.
//  workFactor=16 gives N=65536, ~64 MiB memory, 2-5 seconds on iPhone —
//  still strong brute-force resistance (64K iterations) for any
//  reasonable passphrase. Files encrypted at workFactor=16 are still
//  fully readable by the age CLI on macOS / Linux; scrypt parameters are
//  stored in the file's stanza header.
//

import Foundation
import AgePonyCore

public enum FileEncryptorError: Error, Equatable {
    case noRecipients
    case scryptCannotMixWithRecipients
    case writeFailed(String)
    case readFailed(String)
    case ageError(String)
}

public enum FileEncryptor {

    /// scrypt work factor used for all passphrase-based encrypts in the
    /// mobile app. Lower than the age CLI default (18) for mobile UX.
    public static let mobileWorkFactor: Int = 16

    // MARK: - Encrypt

    public static func encrypt(
        inputURL: URL,
        recipients: [any AgeRecipient],
        passphrase: String?,
        armor: Bool
    ) throws -> URL {
        let usingPassphrase = (passphrase?.isEmpty == false)
        if !usingPassphrase && recipients.isEmpty {
            throw FileEncryptorError.noRecipients
        }
        if usingPassphrase && !recipients.isEmpty {
            throw FileEncryptorError.scryptCannotMixWithRecipients
        }

        let scoped = inputURL.startAccessingSecurityScopedResource()
        defer { if scoped { inputURL.stopAccessingSecurityScopedResource() } }

        let plaintext: Data
        do {
            plaintext = try Data(contentsOf: inputURL)
        } catch {
            throw FileEncryptorError.readFailed(error.localizedDescription)
        }

        let ciphertext: Data
        do {
            if usingPassphrase, let pphr = passphrase {
                ciphertext = try Age.encrypt(
                    plaintext: plaintext,
                    passphrase: pphr,
                    workFactor: mobileWorkFactor
                )
            } else {
                ciphertext = try Age.encrypt(plaintext: plaintext, to: recipients)
            }
        } catch {
            throw FileEncryptorError.ageError(String(describing: error))
        }

        let payload: Data
        if armor {
            payload = Data(AgeArmor.encode(ciphertext).utf8)
        } else {
            payload = ciphertext
        }

        let outName = inputURL.lastPathComponent + ".age"
        let outURL = try writeToFreshTempDir(name: outName, bytes: payload)
        return outURL
    }

    // MARK: - Decrypt

    public static func decryptIdentityBased(
        binaryAgeBytes binary: Data,
        outputBaseName: String,
        identities: [any AgeIdentity]
    ) throws -> URL {
        let plaintext: Data
        do {
            plaintext = try Age.decrypt(ciphertext: binary, identities: identities)
        } catch {
            throw FileEncryptorError.ageError(String(describing: error))
        }
        return try writePlaintextToTemp(plaintext: plaintext, sourceName: outputBaseName)
    }

    public static func decryptPassphraseBased(
        binaryAgeBytes binary: Data,
        outputBaseName: String,
        passphrase: String
    ) throws -> URL {
        let plaintext: Data
        do {
            plaintext = try Age.decrypt(ciphertext: binary, passphrase: passphrase)
        } catch {
            throw FileEncryptorError.ageError(String(describing: error))
        }
        return try writePlaintextToTemp(plaintext: plaintext, sourceName: outputBaseName)
    }

    // MARK: - Output naming + temp dir

    private static func writePlaintextToTemp(plaintext: Data, sourceName: String) throws -> URL {
        let outName: String
        if sourceName.lowercased().hasSuffix(".age") {
            outName = String(sourceName.dropLast(4))
        } else {
            outName = sourceName + " (decrypted)"
        }
        return try writeToFreshTempDir(name: outName, bytes: plaintext)
    }

    private static func writeToFreshTempDir(name: String, bytes: Data) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgePonyShare-\(UUID().uuidString.prefix(8))", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            throw FileEncryptorError.writeFailed(error.localizedDescription)
        }
        let url = dir.appendingPathComponent(name)
        do {
            try bytes.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
        } catch {
            throw FileEncryptorError.writeFailed(error.localizedDescription)
        }
        return url
    }

    public static func cleanupTempFile(at url: URL) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.removeItem(at: dir)
    }
}
