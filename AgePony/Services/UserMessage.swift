//
//  UserMessage.swift
//  AgePony
//
//  One place that turns any error the app can surface into a plain, localized
//  sentence for the screen (5.1.0, UI plan U5). Screens never show an error's
//  own text, `String(describing:)` or a type name. Where a code helps a report
//  (OSStatus, APDU status word, URLError or POSIX code), it follows the
//  message in parentheses, as the Keychain errors do since C1.
//
//  Errors that carry a `String` (FileEncryptorError.writeFailed and the like)
//  carry a finished sentence built here, never raw error text, so passing the
//  payload through is safe.
//
//  Unknown errors get the caller's fallback, which names the operation
//  ("Couldn't decrypt the file."), plus the domain and code when the error is
//  a real NSError.
//

import Foundation
import CryptoKit
import LocalAuthentication
import Network
import AgePonyCore
#if canImport(CoreNFC)
import CoreNFC
#endif

enum UserMessage {

    // MARK: - Entry point

    /// A sentence for `error`. `fallback` names what failed and is used for
    /// errors the app doesn't know, so it should be specific
    /// ("Couldn't decrypt the file.").
    static func text(for error: Error, fallback: @autoclosure () -> String) -> String {
        if let message = known(error) { return message }
        let base = fallback()
        if type(of: error) is NSError.Type {
            let ns = error as NSError
            return "\(base) (\(ns.domain) \(ns.code))"
        }
        return base
    }

    /// Whether `error` means the person cancelled (a system sheet, the NFC
    /// sheet, Face ID). Screens usually show nothing for these.
    static func isCancellation(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if let e = error as? BiometricGateError, e == .userCancelled { return true }
        if let e = error as? LAError {
            switch e.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback: return true
            default: break
            }
        }
        if let e = error as? CocoaError, e.code == .userCancelled { return true }
        if let e = error as? URLError, e.code == .cancelled { return true }
        #if canImport(CoreNFC)
        if let e = error as? SecurityKeyError, case .cancelled = e { return true }
        if let e = error as? NFCReaderError, e.code == .readerSessionInvalidationErrorUserCanceled { return true }
        #endif
        return false
    }

    // MARK: - Lockout and password rules (localized here; AgePonyCore's are English only)

    /// "30 seconds", "5 minutes", "1 hour", rounded the way `UnlockAttempts` rounds.
    static func waitDescription(millis: UInt64) -> String {
        let seconds = max((millis + 999) / 1000, 1)
        let formatter = DateComponentsFormatter()
        formatter.unitsStyle = .full
        formatter.maximumUnitCount = 1
        let interval: TimeInterval
        if seconds < 90 {
            formatter.allowedUnits = [.second]
            interval = TimeInterval(seconds)
        } else if seconds < 3600 {
            formatter.allowedUnits = [.minute]
            interval = TimeInterval(((seconds + 59) / 60) * 60)
        } else {
            formatter.allowedUnits = [.hour]
            interval = 3600
        }
        return formatter.string(from: interval) ?? String(localized: "a moment")
    }

    /// The message for an attempt refused by the unlock backoff.
    static func lockout(millis: UInt64) -> String {
        String(localized: "Too many wrong attempts. Try again in \(waitDescription(millis: millis)).")
    }

    /// What's wrong with a new app password or PIN, or nil when it passes the
    /// same rules as `PasswordKeyBlob.policyError`.
    static func secretPolicyProblem(secret: String, isPIN: Bool) -> String? {
        guard PasswordKeyBlob.policyError(secret: secret, isPIN: isPIN) != nil else { return nil }
        if isPIN {
            if secret.contains(where: { !("0"..."9").contains($0) }) {
                return String(localized: "A PIN can only contain digits.")
            }
            return String(localized: "Use at least \(PasswordKeyBlob.minPINLength) digits.")
        }
        return String(localized: "Use at least \(PasswordKeyBlob.minPasswordLength) characters.")
    }

    // MARK: - Dispatch

    private static func known(_ error: Error) -> String? {
        // App errors
        if let e = error as? KeychainError { return e.errorDescription }
        if let e = error as? VaultError { return vault(e) }
        if let e = error as? VaultModelError { return vaultModel(e) }
        if let e = error as? StoredRecipientHydrationError { return hydration(e) }
        if let e = error as? FileEncryptorError { return fileEncryptor(e) }
        if let e = error as? FileSignerError { return fileSigner(e) }
        if let e = error as? SignEncryptError { return signEncrypt(e) }
        if let e = error as? MigrateError { return e.errorDescription }
        if let e = error as? AgeFileInspectorError { return inspector(e) }
        if let e = error as? SSHImportError { return sshImport(e) }
        if let e = error as? RecipientImportError { return recipientImport(e) }
        if let e = error as? SecureEnclaveSignerError { return enclaveSigner(e) }
        if let e = error as? SharedContainerError { return sharedContainer(e) }
        if let e = error as? BiometricGateError { return biometricGate(e) }
        if let e = error as? QRScannerError { return qrScanner(e) }
        if let e = error as? LanLinkError { return e.errorDescription }
        if let e = error as? AgePonyIntentError { return e.errorDescription }
        #if canImport(CoreNFC)
        if let e = error as? SecurityKeyError { return e.errorDescription }
        #endif

        // AgePonyCore: age format
        if let e = error as? AgeError { return age(e) }
        if let e = error as? AgeHeaderError { return header(e) }
        if let e = error as? AgePayloadError { return payload(e) }
        if let e = error as? AgeArmorError { return armor(e) }
        if error is StanzaError { return damagedHeader }
        if let e = error as? Bech32Error { return bech32(e) }
        if error is Scrypt.ScryptError { return String(localized: "The passphrase settings are out of range.") }
        if let e = error as? ScryptStanzaError { return scryptStanza(e) }
        if let e = error as? X25519Error { return x25519(e) }
        if let e = error as? HybridKEMError { return hybridKEM(e) }
        if error is MLKEMError || error is HybridStanzaError {
            return String(localized: "That quantum-safe key is damaged.")
        }
        if error is P256RecipientError || error is P256CurveError || error is HpkeP256Error {
            return String(localized: "That P-256 key is damaged.")
        }
        if let e = error as? TagRecipientError { return tag(e) }
        if let e = error as? SecureEnclaveKeyError { return enclaveKey(e) }
        if error is Ed25519ConversionError {
            return String(localized: "That Ed25519 key can't be converted for encryption.")
        }
        if let e = error as? OAEPError { return oaep(e) }
        if error is AESCBCError || error is AESCTRError || error is RSAKeyError {
            return String(localized: "A step in the RSA key handling failed. The key may be damaged.")
        }

        // AgePonyCore: SSH keys
        if let e = error as? SSHKeyError { return sshKey(e) }
        if let e = error as? SSHRSAKeyParserError { return sshRSAParser(e) }
        if let e = error as? OpenSSHEncryptedKeyError { return openSSHEncrypted(e) }
        if error is SSHEd25519PassphraseError || error is SSHWireFormatError || error is OpenSSHEd25519ExportError {
            return damagedSSHKey
        }
        if error is BcryptPBKDF.BcryptError {
            return String(localized: "This SSH key's passphrase settings can't be used.")
        }
        if let e = error as? SSHEd25519Error { return sshEd25519(e) }
        if let e = error as? SSHRSAStanzaError { return sshRSAStanza(e) }
        if let e = error as? SSHKeySourceError { return sshKeySource(e) }

        // AgePonyCore: signing and bundles
        if let e = error as? SSHSigError { return sshSig(e) }
        if let e = error as? SignedEncryptionError { return signedEncryption(e) }
        if let e = error as? SignedBundleError { return signedBundle(e) }
        if let e = error as? TarArchiveError { return tar(e) }

        // AgePonyCore: hardware
        if let e = error as? PivError { return piv(e) }
        if let e = error as? YubiKeyError { return yubiKey(e) }
        if error is RecordedKeyAgreement.Missing {
            return String(localized: "The YubiKey didn't answer for every key this file needs. Tap it again.")
        }
        if error is CTAP2Error || error is CBORError || error is COSEKeyError || error is AuthenticatorDataError {
            return String(localized: "The security key's answer didn't make sense. Tap it again.")
        }

        // AgePonyCore: passwords and portability
        if let e = error as? PasswordKeyBlob.BlobError { return blob(e) }
        if error is Diceware.DicewareError {
            return String(localized: "The word list for passphrases couldn't be loaded.")
        }
        if let e = error as? KeyTransferError { return keyTransfer(e) }
        if let e = error as? LanTransferError { return lanTransfer(e) }
        if let e = error as? PaperBackupError { return paperBackup(e) }

        // System
        if let e = error as? LAError { return localAuthentication(e) }
        #if canImport(CoreNFC)
        if let e = error as? NFCReaderError { return nfc(e) }
        #endif
        if let e = error as? URLError { return url(e) }
        if let e = error as? CocoaError { return cocoa(e) }
        if let e = error as? POSIXError { return posix(e) }
        if let e = error as? NWError { return network(e) }
        if let e = error as? CryptoKitError { return cryptoKit(e) }
        if error is DecodingError { return String(localized: "The saved data is damaged and couldn't be read.") }
        if error is CancellationError { return String(localized: "Cancelled.") }
        return nil
    }

    private static var damagedHeader: String {
        String(localized: "The file's age header is damaged.")
    }

    private static var damagedSSHKey: String {
        String(localized: "The SSH key is damaged or isn't in a format AgePony reads.")
    }

    // MARK: - App errors

    private static func vault(_ e: VaultError) -> String {
        switch e {
        case .notUnlocked:
            return String(localized: "The vault is locked. Unlock AgePony and try again.")
        case .vaultFileMissing:
            return String(localized: "The vault file is missing. This usually means AgePony was reinstalled.")
        case .malformedVaultFile:
            return String(localized: "The vault file is damaged and can't be read.")
        case .decryptionFailed:
            return String(localized: "The vault couldn't be decrypted. Its key in the Keychain may have been reset.")
        case .wrongPassword:
            return String(localized: "Wrong password or PIN.")
        case .lockedOut(let millis):
            return lockout(millis: millis)
        case .noAppPassword:
            return String(localized: "No app password is set for this vault.")
        case .duressEqualsReal:
            return String(localized: "The duress password must be different from your real one.")
        case .realEqualsDuress:
            return String(localized: "Your password must be different from the duress password.")
        case .weakSecret(let why):
            return weakSecret(why)
        case .kindLockedByDuress:
            return String(localized: "Remove the duress password first to switch between a password and a PIN.")
        case .lockModeLockedByDuress:
            return String(localized: "Remove the duress password first to change how the vault unlocks.")
        case .passwordIsOnlyUnlock:
            return String(localized: "The app password is the only way into the vault. Choose another way to unlock before removing it.")
        case .ownerCheckNeeded:
            return String(localized: "Confirm it's you with Face ID or the passcode, then set the password or PIN again.")
        }
    }

    /// `Vault` reports `PasswordKeyBlob.policyError`'s English text; give the
    /// localized sentence for the same rule.
    private static func weakSecret(_ why: String) -> String {
        if why.contains("only contain digits") { return String(localized: "A PIN can only contain digits.") }
        if why.hasSuffix("digits.") { return String(localized: "Use at least \(PasswordKeyBlob.minPINLength) digits.") }
        if why.hasSuffix("characters.") { return String(localized: "Use at least \(PasswordKeyBlob.minPasswordLength) characters.") }
        return String(localized: "That password is too short.")
    }

    private static func vaultModel(_ e: VaultModelError) -> String {
        switch e {
        case .malformedPublicMaterial(let type), .malformedPrivateMaterial(let type):
            return String(localized: "The stored \(type.sectionTitle) key is damaged.")
        case .signingOnlyIdentity(let type):
            return String(localized: "\(type.sectionTitle) identities can sign but can't decrypt.")
        case .needsYubiKeyTap:
            return String(localized: "This identity is on a YubiKey. Hold the key to your iPhone to use it.")
        }
    }

    private static func hydration(_ e: StoredRecipientHydrationError) -> String {
        switch e {
        case .malformedWireBlob:
            return String(localized: "The stored recipient is damaged.")
        }
    }

    private static func fileEncryptor(_ e: FileEncryptorError) -> String {
        switch e {
        case .noRecipients:
            return String(localized: "Choose at least one recipient.")
        case .scryptCannotMixWithRecipients:
            return String(localized: "A passphrase can't be combined with recipients in the same file.")
        case .writeFailed(let message), .readFailed(let message), .ageError(let message),
             .scryptWontFit(let message), .bundleDamaged(let message):
            return message
        case .cannotOpenInput(let name):
            return String(localized: "Couldn't open \(name).")
        case .cannotOpenOutput(let name):
            return String(localized: "Couldn't create \(name).")
        }
    }

    private static func fileSigner(_ e: FileSignerError) -> String {
        switch e {
        case .identityCannotSign:
            return String(localized: "This identity can't make signatures.")
        case .requiresSecurityKey:
            return String(localized: "This identity is on a security key. Hold the key to your iPhone to sign.")
        case .keyTypeNotYetSupported(let type):
            return String(localized: "AgePony can't sign with \(type.sectionTitle) keys yet.")
        case .malformedIdentityMaterial:
            return String(localized: "This identity's stored key is damaged.")
        case .readFailed(let message), .writeFailed(let message), .signError(let message):
            return message
        }
    }

    private static func signEncrypt(_ e: SignEncryptError) -> String {
        switch e {
        case .signingIdentityCannotSign:
            return String(localized: "The identity you chose to sign with can't make signatures.")
        case .requiresSecurityKey:
            return String(localized: "The signing identity is on a security key. Hold the key to your iPhone to sign.")
        case .cannotOpenInput(let name):
            return String(localized: "Couldn't open \(name).")
        }
    }

    private static func inspector(_ e: AgeFileInspectorError) -> String {
        switch e {
        case .notAnAgeFile:
            return String(localized: "That isn't an age-encrypted file.")
        case .malformedArmor:
            return String(localized: "The armored text is damaged.")
        case .headerParseFailed(let message):
            return message
        case .cannotOpenFile(let name):
            return String(localized: "Couldn't open \(name).")
        }
    }

    private static func sshImport(_ e: SSHImportError) -> String {
        switch e {
        case .passphraseRequired:
            return String(localized: "This SSH key needs its passphrase.")
        case .wrongPassphrase:
            return String(localized: "Wrong passphrase for this SSH key.")
        case .unsupportedKeyType:
            return String(localized: "AgePony can import SSH Ed25519 and RSA keys. This is another type.")
        case .malformedPEM:
            return String(localized: "That isn't a readable OpenSSH private key.")
        }
    }

    private static func recipientImport(_ e: RecipientImportError) -> String {
        switch e {
        case .unrecognizedFormat:
            return String(localized: "That isn't a recipient AgePony recognizes. Paste an age1 recipient or an SSH public key line.")
        case .noUsableKeysInResponse:
            return String(localized: "That GitHub account has no keys AgePony can use.")
        case .fetchFailed(let message):
            return message
        case .invalidUsername:
            return String(localized: "That isn't a valid GitHub username.")
        }
    }

    private static func enclaveSigner(_ e: SecureEnclaveSignerError) -> String {
        switch e {
        case .unavailable:
            return String(localized: "The Secure Enclave isn't available on this device.")
        case .generationFailed(let message), .signFailed(let message):
            return message
        case .malformedKeyData:
            return String(localized: "The stored Secure Enclave key is damaged.")
        }
    }

    private static func sharedContainer(_ e: SharedContainerError) -> String {
        switch e {
        case .containerUnavailable:
            return String(localized: "The folder AgePony shares with its share extension isn't available.")
        case .writeFailed(let message), .readFailed(let message):
            return message
        case .malformedManifest:
            return String(localized: "The shared item is damaged. Share it again.")
        case .unknownToken:
            return String(localized: "The shared item has expired. Share it again.")
        }
    }

    private static func biometricGate(_ e: BiometricGateError) -> String {
        switch e {
        case .unavailable:
            if BiometricGate.biometryOnly {
                // Face ID only (E6): the passcode is never the alternative.
                let name = BiometricGate.biometryName()
                return String(localized: "\(name) isn't available right now.")
            }
            return String(localized: "Face ID, Touch ID and the passcode aren't available on this device.")
        case .userCancelled:
            return String(localized: "Authentication was cancelled.")
        case .failed(let message):
            return message
        }
    }

    private static func qrScanner(_ e: QRScannerError) -> String {
        switch e {
        case .cameraUnavailable:
            return String(localized: "This device has no camera AgePony can use.")
        case .permissionDenied:
            return String(localized: "AgePony isn't allowed to use the camera. Turn it on for AgePony in the Settings app.")
        case .setupFailed:
            return String(localized: "The camera couldn't start. Close the scanner and try again.")
        }
    }

    // MARK: - age format

    private static func age(_ e: AgeError) -> String {
        switch e {
        case .noRecipients:
            return String(localized: "Choose at least one recipient.")
        case .scryptMustBeSoleRecipient:
            return String(localized: "A passphrase can't be combined with recipients in the same file.")
        case .scryptNotAlone:
            return String(localized: "This file mixes a passphrase with other recipients, which age doesn't allow.")
        case .mismatchedRecipientLabels:
            return String(localized: "Some of these recipients can't share a file with the others, such as quantum-safe and classic keys.")
        case .noMatchingIdentity:
            return String(localized: "None of your identities can open this file.")
        case .wrongPassphrase:
            return String(localized: "Wrong passphrase.")
        case .truncatedFile:
            return String(localized: "The file is incomplete. It may have been cut off while copying.")
        case .headerError(let h):
            return header(h)
        case .payloadError(let p):
            return payload(p)
        case .invalidFileKeyLength:
            return damagedHeader
        }
    }

    private static func header(_ e: AgeHeaderError) -> String {
        switch e {
        case .missingVersionLine:
            return String(localized: "That isn't an age-encrypted file.")
        case .unsupportedVersion:
            return String(localized: "This file uses an age format version AgePony doesn't read.")
        case .invalidMAC:
            return String(localized: "The file's header failed its integrity check. It was changed or damaged.")
        case .tooLarge:
            return String(localized: "The file's age header is too large to read.")
        case .missingFooter, .malformedMACLine, .noStanzas, .stanzaError, .notASCII, .unexpectedLine:
            return damagedHeader
        }
    }

    private static func payload(_ e: AgePayloadError) -> String {
        switch e {
        case .decryptFailed:
            return String(localized: "The encrypted contents failed their integrity check. The file was changed or damaged.")
        case .streamReadFailed:
            return String(localized: "Couldn't read the file.")
        case .streamWriteFailed:
            return String(localized: "Couldn't write the output file.")
        case .missingNoncePrefix, .emptyPayload, .truncatedChunk, .unexpectedExtraBytes, .emptyFinalChunk:
            return String(localized: "The encrypted contents are damaged or incomplete.")
        }
    }

    private static func armor(_ e: AgeArmorError) -> String {
        switch e {
        case .missingBeginMarker, .missingEndMarker:
            return String(localized: "The armored text is missing its BEGIN or END line.")
        case .extraDataOutsideArmor:
            return String(localized: "There's extra text outside the armored block.")
        case .invalidBase64, .bodyAfterShortLine, .lineTooLong:
            return String(localized: "The armored text is damaged.")
        }
    }

    private static func bech32(_ e: Bech32Error) -> String {
        switch e {
        case .invalidChecksum:
            return String(localized: "That key has a typo: its checksum doesn't match.")
        case .mixedCase:
            return String(localized: "That key mixes upper and lower case letters.")
        case .unexpectedHRP:
            return String(localized: "That's a different kind of key than this field takes.")
        case .invalidCharacter, .stringTooShort, .stringTooLong, .missingSeparator, .emptyHRP,
             .hrpOutOfRange, .invalidPadding, .invalidBitGroup:
            return String(localized: "That isn't a valid age key.")
        }
    }

    private static func scryptStanza(_ e: ScryptStanzaError) -> String {
        switch e {
        case .decryptFailed:
            return String(localized: "Wrong passphrase.")
        case .invalidWorkFactor:
            return String(localized: "The file's passphrase work factor is out of range.")
        case .invalidStanzaType, .invalidArgs, .invalidSaltLength, .invalidWrappedKey:
            return damagedHeader
        }
    }

    private static func x25519(_ e: X25519Error) -> String {
        switch e {
        case .invalidPublicKeyLength, .invalidPrivateKeyLength:
            return String(localized: "That X25519 key is damaged.")
        case .decryptFailed:
            return String(localized: "None of your identities can open this file.")
        case .lowOrderPublicKey, .invalidStanzaType, .missingEphemeral, .invalidEphemeral, .invalidWrappedKey:
            return damagedHeader
        }
    }

    private static func hybridKEM(_ e: HybridKEMError) -> String {
        switch e {
        case .lowOrderPoint:
            // An all-zero X25519 shared secret: never produced for a real key.
            return String(localized: "This file wasn't made for any of your keys, or it was tampered with.")
        case .invalidSeedLength, .invalidPublicKeyLength, .invalidEncapsulationLength, .invalidTestRandomLength:
            return String(localized: "That quantum-safe key is damaged.")
        }
    }

    private static func tag(_ e: TagRecipientError) -> String {
        switch e {
        case .invalidLength, .malformedMLKEMKey:
            return String(localized: "That hardware key recipient is damaged.")
        case .unexpectedHRP:
            return String(localized: "That's a different kind of key than this field takes.")
        }
    }

    private static func enclaveKey(_ e: SecureEnclaveKeyError) -> String {
        switch e {
        case .unavailable:
            return String(localized: "The Secure Enclave isn't available on this device.")
        case .accessControl:
            return String(localized: "iOS couldn't set up the protection for the Secure Enclave key.")
        case .invalidKeyData:
            return String(localized: "The stored Secure Enclave key is damaged.")
        case .keyAgreementFailed:
            return String(localized: "The Secure Enclave couldn't open this file.")
        case .requiresIOS26:
            return String(localized: "This hardware key was made on another device or needs iOS 26 or later, so it can't decrypt here.")
        }
    }

    private static func oaep(_ e: OAEPError) -> String {
        switch e {
        case .decodingError:
            return String(localized: "The RSA key couldn't open this file.")
        case .keyTooSmall:
            return String(localized: "That RSA key is too small to use.")
        case .messageTooLong:
            return String(localized: "A step in the RSA key handling failed. The key may be damaged.")
        }
    }

    // MARK: - SSH

    private static func sshKey(_ e: SSHKeyError) -> String {
        switch e {
        case .malformedPublicKeyLine:
            return String(localized: "That isn't an SSH public key line.")
        case .unsupportedKeyType(let type), .wrongKeyType(let type):
            return String(localized: "AgePony doesn't use \(type) keys.")
        case .unsupportedCipher(let name), .unsupportedKDF(let name):
            return String(localized: "This SSH key is protected with \(name), which AgePony can't open.")
        case .checkIntsMismatch:
            return String(localized: "Wrong passphrase for this SSH key.")
        case .malformedKeyBlob, .malformedPemFraming, .invalidBase64, .missingMagic, .wrongKeyCount,
             .invalidPublicKeyLength, .invalidPrivateKeyLength, .inconsistentKey:
            return damagedSSHKey
        }
    }

    private static func sshRSAParser(_ e: SSHRSAKeyParserError) -> String {
        switch e {
        case .keySizeTooSmall(let bits):
            return String(localized: "That RSA key is \(bits) bits. AgePony needs at least 2048.")
        case .unsupportedCipher(let name), .unsupportedKDF(let name):
            return String(localized: "This SSH key is protected with \(name), which AgePony can't open.")
        case .wrongKeyType(let type):
            return String(localized: "AgePony doesn't use \(type) keys here.")
        case .checkIntsMismatch:
            return String(localized: "Wrong passphrase for this SSH key.")
        case .malformedPubLine, .wireBlobMismatch, .malformedPEM, .unacceptableKey:
            return damagedSSHKey
        }
    }

    private static func openSSHEncrypted(_ e: OpenSSHEncryptedKeyError) -> String {
        switch e {
        case .passphraseRequired:
            return String(localized: "This SSH key needs its passphrase.")
        case .wrongPassphrase, .checkIntsMismatch:
            return String(localized: "Wrong passphrase for this SSH key.")
        case .unsupportedCipher(let name), .unsupportedKDF(let name):
            return String(localized: "This SSH key is protected with \(name), which AgePony can't open.")
        case .malformedPEM, .malformedKDFOpts:
            return damagedSSHKey
        }
    }

    private static func sshEd25519(_ e: SSHEd25519Error) -> String {
        switch e {
        case .invalidEdPublicKey, .invalidEdPrivateKey:
            return damagedSSHKey
        case .conversionFailed:
            return String(localized: "That Ed25519 key can't be converted for encryption.")
        case .lowOrderPublicKey:
            return String(localized: "That Ed25519 key isn't safe to encrypt to: anyone could open a file encrypted to it. Ask for the key again.")
        }
    }

    private static func sshRSAStanza(_ e: SSHRSAStanzaError) -> String {
        switch e {
        case .keyTooSmall:
            return String(localized: "That RSA key is too small to use.")
        case .wrapFailed:
            return String(localized: "Couldn't encrypt to that SSH RSA key.")
        case .unwrapFailed:
            return String(localized: "The SSH RSA key couldn't open this file.")
        }
    }

    private static func sshKeySource(_ e: SSHKeySourceError) -> String {
        switch e {
        case .invalidURL:
            return String(localized: "That isn't a valid GitHub username.")
        case .fetchFailed(let status):
            return String(localized: "GitHub didn't return the keys (HTTP \(status)).")
        case .noUsableKeys:
            return String(localized: "That GitHub account has no keys AgePony can use.")
        case .proxyMisconfigured:
            return String(localized: "The proxy settings are incomplete. Check Network in Settings.")
        }
    }

    // MARK: - Signing and bundles

    private static func sshSig(_ e: SSHSigError) -> String {
        switch e {
        case .signatureInvalid:
            return String(localized: "The signature doesn't match this file.")
        case .namespaceMismatch(_, let found):
            return String(localized: "This signature was made for something else (namespace \(found)).")
        case .userPresenceRequired:
            return String(localized: "The signature was made without touching the security key, so it doesn't count.")
        case .unsupportedKeyType(let name), .unsupportedHashAlgorithm(let name):
            return String(localized: "This signature uses \(name), which AgePony can't check.")
        case .unsupportedVersion:
            return String(localized: "This signature uses a format version AgePony can't check.")
        case .signingFailed:
            return String(localized: "Couldn't make the signature.")
        case .missingBeginMarker, .missingEndMarker, .invalidBase64, .extraDataOutsideArmor, .badMagic,
             .malformedBlob, .malformedPublicKey, .malformedInnerSignature, .malformedMessageHash:
            return String(localized: "The signature is damaged or isn't an SSH signature.")
        }
    }

    private static func signedEncryption(_ e: SignedEncryptionError) -> String {
        switch e {
        case .passphraseRecipient:
            return String(localized: "A file encrypted with a passphrase can't carry a signature.")
        case .signatureDoesNotCoverMessage:
            return String(localized: "The signature doesn't cover this message.")
        case .plaintextChanged:
            return String(localized: "The decrypted contents don't match what was signed.")
        }
    }

    private static func signedBundle(_ e: SignedBundleError) -> String {
        switch e {
        case .damaged:
            return String(localized: "The signed bundle is damaged.")
        case .missingPayload:
            return String(localized: "The signed bundle has no file in it.")
        case .missingSignature:
            return String(localized: "The signed bundle has no signature in it.")
        case .unreadableManifest:
            return String(localized: "The signed bundle's file list can't be read.")
        }
    }

    private static func tar(_ e: TarArchiveError) -> String {
        switch e {
        case .nameTooLong(let name):
            return String(localized: "The name \(name) is too long to put in a bundle.")
        case .entryTooLarge(let name):
            return String(localized: "\(name) is too large to put in a bundle.")
        case .truncated, .badChecksum, .unsupportedEntryType, .invalidSize, .entryEndedEarly, .entryLongerThanDeclared:
            return String(localized: "The bundle is damaged or incomplete.")
        }
    }

    // MARK: - Hardware keys

    private static func hex(_ value: UInt16) -> String {
        String(format: "%04X", value)
    }

    private static func piv(_ e: PivError) -> String {
        switch e {
        case .pinRequired:
            return String(localized: "This YubiKey key needs its PIN.")
        case .wrongPIN(let left) where left == 0:
            return String(localized: "The PIV PIN is blocked. Unblock it with the PUK in YubiKey Manager.")
        case .wrongPIN(let left):
            return String(AttributedString(localized: "Wrong PIN. ^[\(left) try](inflect: true) left before it locks.").characters)
        case .pinLength:
            return String(localized: "A YubiKey PIN is 6 to 8 characters.")
        case .notPIV(let sw):
            return String(localized: "That key has no PIV applet (status \(hex(sw))).")
        case .noKeyInSlot(_, let sw):
            return String(localized: "That YubiKey has no key in the slot this identity uses (status \(hex(sw))).")
        case .notP256:
            return String(localized: "The key in that slot isn't a P-256 key.")
        case .refused(let sw):
            return String(localized: "The YubiKey refused the request (status \(hex(sw))).")
        case .malformedResponse:
            return String(localized: "The YubiKey's answer didn't make sense. Tap it again.")
        }
    }

    private static func yubiKey(_ e: YubiKeyError) -> String {
        switch e {
        case .wrongYubiKey(let expected, let found):
            return String(localized: "That's YubiKey \(String(found)). This identity is on YubiKey \(String(expected)).")
        case .keyDoesNotMatchStub:
            return String(localized: "The key in that slot isn't the one this identity points at.")
        case .notAStub, .malformedStub:
            return String(localized: "That isn't an age-plugin-yubikey identity (AGE-PLUGIN-YUBIKEY-1…).")
        case .notARetiredSlot:
            return String(localized: "That identity points at a slot age-plugin-yubikey doesn't use.")
        }
    }

    // MARK: - Passwords and portability

    private static func blob(_ e: PasswordKeyBlob.BlobError) -> String {
        switch e {
        case .deviceKeyMissing:
            return String(localized: "This iPhone's key for the app password is missing, so the password can't open the vault.")
        case .duressMaterialUsed:
            return String(localized: "The duress password has already been used on this vault.")
        case .tooShort, .unknownVersion, .implausibleWorkFactor, .shortMAC:
            return String(localized: "The stored app password data is damaged.")
        }
    }

    private static func keyTransfer(_ e: KeyTransferError) -> String {
        switch e {
        case .notATransfer:
            return String(localized: "That isn't an AgePony key transfer.")
        case .unsupportedFormat:
            return String(localized: "That transfer was made by a newer version of AgePony. Update AgePony on this phone.")
        case .tooManyEntries:
            return String(localized: "That transfer has more keys than AgePony takes at once.")
        case .wrongSession:
            return String(localized: "That transfer was sealed for a different receive session. Start Receive keys again and rescan.")
        case .notARecipient:
            return String(localized: "That isn't a receive key from another phone.")
        }
    }

    private static func lanTransfer(_ e: LanTransferError) -> String {
        switch e {
        case .notAnInvite:
            return String(localized: "That QR code isn't from Receive keys on another phone.")
        case .damagedInvite:
            return String(localized: "That receive QR code is damaged. Scan it again.")
        case .protocolError:
            return String(localized: "The other phone sent something unexpected. Start the transfer again.")
        case .wrongToken:
            return String(localized: "The other phone's code didn't match. Start Receive keys again and rescan.")
        case .tooLarge:
            return String(localized: "Transfer is too large to send directly.")
        case .refused:
            return String(localized: "The other phone refused the transfer. Start Receive keys again and rescan.")
        }
    }

    private static func paperBackup(_ e: PaperBackupError) -> String {
        switch e {
        case .emptyPassphrase:
            return String(localized: "Enter the backup passphrase.")
        case .notSealed:
            return String(localized: "That isn't an AgePony paper backup.")
        case .damaged:
            return String(localized: "The backup is damaged or didn't scan completely.")
        case .wrongPassphrase:
            return String(localized: "Wrong backup passphrase.")
        }
    }

    // MARK: - System errors

    private static func localAuthentication(_ e: LAError) -> String {
        switch e.code {
        case .authenticationFailed:
            return String(localized: "Face ID or Touch ID didn't recognize you.")
        case .userCancel, .appCancel, .systemCancel, .userFallback:
            return String(localized: "Authentication was cancelled.")
        case .passcodeNotSet:
            return String(localized: "Set a device passcode in the Settings app to use this lock.")
        case .biometryNotAvailable:
            return String(localized: "Face ID or Touch ID isn't available. Check that AgePony may use it in the Settings app.")
        case .biometryNotEnrolled:
            return String(localized: "Face ID or Touch ID isn't set up on this iPhone.")
        case .biometryLockout:
            return String(localized: "Face ID or Touch ID is locked after too many tries. Lock and unlock your iPhone with the passcode to turn it back on.")
        default:
            return String(localized: "Authentication didn't succeed (LAError \(e.code.rawValue)).")
        }
    }

    #if canImport(CoreNFC)
    private static func nfc(_ e: NFCReaderError) -> String {
        switch e.code {
        case .readerSessionInvalidationErrorUserCanceled:
            return String(localized: "Cancelled.")
        case .readerSessionInvalidationErrorSessionTimeout:
            return String(localized: "The NFC scan timed out. Hold the key to the top of your iPhone and try again.")
        case .readerSessionInvalidationErrorSystemIsBusy:
            return String(localized: "NFC is busy. Wait a moment and try again.")
        case .readerTransceiveErrorTagConnectionLost:
            return String(localized: "The key moved away before the exchange finished. Hold it still and try again.")
        case .readerErrorUnsupportedFeature:
            return String(localized: "This iPhone can't read security keys over NFC.")
        default:
            return String(localized: "The NFC exchange failed (NFC error \((e as NSError).code)).")
        }
    }
    #endif

    private static func url(_ e: URLError) -> String {
        switch e.code {
        case .notConnectedToInternet, .networkConnectionLost, .dataNotAllowed:
            return String(localized: "There's no internet connection.")
        case .timedOut:
            return String(localized: "The server took too long to answer.")
        case .cannotFindHost, .cannotConnectToHost, .dnsLookupFailed:
            return String(localized: "Couldn't reach the server (URLError \(e.code.rawValue)).")
        case .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate,
             .serverCertificateNotYetValid, .serverCertificateHasUnknownRoot:
            return String(localized: "The secure connection to the server failed (URLError \(e.code.rawValue)).")
        case .cancelled:
            return String(localized: "Cancelled.")
        default:
            return String(localized: "The request failed (URLError \(e.code.rawValue)).")
        }
    }

    private static func cocoa(_ e: CocoaError) -> String {
        switch e.code {
        case .fileNoSuchFile, .fileReadNoSuchFile:
            return String(localized: "The file isn't there any more.")
        case .fileReadNoPermission, .fileWriteNoPermission:
            return String(localized: "AgePony isn't allowed to use that file. Pick it again.")
        case .fileWriteOutOfSpace:
            return String(localized: "There isn't enough free storage on this iPhone.")
        case .fileWriteVolumeReadOnly:
            return String(localized: "That location is read-only.")
        case .fileReadCorruptFile:
            return String(localized: "The file is damaged.")
        case .fileReadTooLarge:
            return String(localized: "The file is too large to read.")
        case .fileWriteFileExists:
            return String(localized: "A file with that name already exists.")
        case .userCancelled:
            return String(localized: "Cancelled.")
        default:
            return String(localized: "A file operation failed (Cocoa error \(e.code.rawValue)).")
        }
    }

    private static func posix(_ e: POSIXError) -> String {
        switch e.code {
        case .ENOSPC:
            return String(localized: "There isn't enough free storage on this iPhone.")
        case .EACCES, .EPERM:
            return String(localized: "AgePony isn't allowed to use that file. Pick it again.")
        case .ENOENT:
            return String(localized: "The file isn't there any more.")
        case .EROFS:
            return String(localized: "That location is read-only.")
        default:
            return String(localized: "A system call failed (POSIX \(String(e.code.rawValue))).")
        }
    }

    private static func network(_ e: NWError) -> String {
        switch e {
        case .posix(let code):
            switch code {
            case .ECONNREFUSED:
                return String(localized: "The other phone isn't accepting connections. Open Receive keys on it again.")
            case .ETIMEDOUT, .EHOSTUNREACH, .ENETUNREACH, .EHOSTDOWN:
                return String(localized: "Couldn't reach the other phone. Put both on the same Wi-Fi.")
            default:
                return String(localized: "The connection failed (POSIX \(String(code.rawValue))).")
            }
        case .dns(let code):
            return String(localized: "The connection failed (DNS \(String(code))).")
        case .tls(let status):
            return String(localized: "The secure connection failed (OSStatus \(String(status))).")
        default:
            return String(localized: "The connection failed.")
        }
    }

    private static func cryptoKit(_ e: CryptoKitError) -> String {
        if case .authenticationFailure = e {
            return String(localized: "The data failed its integrity check. It was changed or damaged, or the key is wrong.")
        }
        return String(localized: "A CryptoKit operation failed. The key may be damaged.")
    }
}
