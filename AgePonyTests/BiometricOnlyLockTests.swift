//
//  BiometricOnlyLockTests.swift
//  AgePonyTests
//
//  5.1.0 (E6): the Face ID only lock. These pin the stored names, that the
//  vault key's protection in that mode can't be opened with the passcode, that
//  the mode stays out of the setup ladder, when the mode can be chosen, and the
//  Secure Enclave protection options. The Keychain and LocalAuthentication
//  behavior itself needs a device (see the RC2b device list).
//

import Testing
import Foundation
import Security
import AgePonyCore
@testable import AgePony

@MainActor
struct BiometricOnlyLockTests {

    // MARK: - LockMode

    @Test func lockModeRawValuesAreStable() {
        // Stored in UserDefaults; renaming a case would change how an installed vault locks.
        #expect(LockMode.biometric.rawValue == "biometric")
        #expect(LockMode.biometricOnly.rawValue == "biometricOnly")
        #expect(LockMode.none.rawValue == "none")
        #expect(Set(LockMode.allCases.map(\.rawValue)) == ["biometric", "biometricOnly", "none"])
    }

    @Test func lockModeRoundTrips() throws {
        for mode in LockMode.allCases {
            #expect(LockMode.fromKey(mode.rawValue) == mode)
            let data = try JSONEncoder().encode(mode)
            #expect(try JSONDecoder().decode(LockMode.self, from: data) == mode)
        }
    }

    @Test func unknownStoredModeFallsBackToTheDefaultLock() {
        // Never to Face ID only, which needs a password to recover from a Face ID reset.
        #expect(LockMode.fromKey("faceIDOnly") == .biometric)
        #expect(LockMode.fromKey("") == .biometric)
    }

    @Test func onlyTheDefaultLockAcceptsThePasscode() {
        #expect(LockMode.biometric.acceptsDevicePasscode)
        #expect(!LockMode.biometricOnly.acceptsDevicePasscode)
        #expect(!LockMode.none.acceptsDevicePasscode)
    }

    @Test func biometricOnlyNeedsAnAppPassword() {
        #expect(LockMode.biometricOnly.needsAppPassword)
        #expect(!LockMode.biometric.needsAppPassword)
        #expect(!LockMode.none.needsAppPassword)
    }

    @Test func biometricOnlyKeepsAKeychainCopyBehindAPrompt() {
        #expect(LockMode.biometricOnly.requiresBiometricACL)
        #expect(LockMode.biometric.requiresBiometricACL)
        #expect(!LockMode.none.requiresBiometricACL)
    }

    @Test func biometricOnlyIsUnavailableWithDuress() {
        #expect(!LockMode.biometricOnly.isAvailable(duressSet: true, biometryEnrolled: true))
        #expect(!LockMode.biometric.isAvailable(duressSet: true, biometryEnrolled: true))
        #expect(LockMode.none.isAvailable(duressSet: true, biometryEnrolled: true))
    }

    @Test func biometricOnlyNeedsEnrolledBiometrics() {
        #expect(!LockMode.biometricOnly.isAvailable(duressSet: false, biometryEnrolled: false))
        #expect(LockMode.biometricOnly.isAvailable(duressSet: false, biometryEnrolled: true))
        #expect(LockMode.biometric.isAvailable(duressSet: false, biometryEnrolled: false))
    }

    @Test func biometricOnlyWithoutPasswordNormalizesToTheDefaultLock() {
        // An older version can remove the password; the vault must keep a way in.
        #expect(LockMode.biometricOnly.normalized(hasAppPassword: false) == .biometric)
        #expect(LockMode.biometricOnly.normalized(hasAppPassword: true) == nil)
        #expect(LockMode.biometric.normalized(hasAppPassword: false) == nil)
        #expect(LockMode.none.normalized(hasAppPassword: false) == nil)
        #expect(LockMode.none.normalized(hasAppPassword: true) == nil)
    }

    // MARK: - Keychain protection

    @Test func biometryOnlyItemCarriesItsTag() throws {
        let access = try #require(SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, BiometryOnlyKeyProtection.flags, nil))
        let attrs = KeychainStore.biometryOnlyItemAttributes(Data(repeating: 1, count: 32), account: "a", access: access)
        #expect(attrs[kSecAttrDescription as String] as? String == BiometryOnlyKeyProtection.storedName)
        #expect(attrs[kSecAttrAccessible as String] == nil)
    }

    @Test func biometryOnlyTagQueryNeverReadsTheKey() {
        let query = KeychainStore.biometryOnlyTagQuery(account: "a")
        #expect(query[kSecAttrDescription as String] as? String == BiometryOnlyKeyProtection.storedName)
        #expect(query[kSecReturnData as String] == nil)
        #expect(query[kSecReturnAttributes as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String] as? String == kSecUseAuthenticationUIFail as String)
    }

    @Test func biometryOnlyFlagsLeaveThePasscodeOut() {
        let flags = BiometryOnlyKeyProtection.flags
        #expect(flags == [.biometryCurrentSet])
        #expect(!flags.contains(.devicePasscode))
        #expect(!flags.contains(.userPresence))
        #expect(!flags.contains(.or))
        // .biometryAny would let a passcode holder add a face and then open the item (Q2).
        #expect(!flags.contains(.biometryAny))
    }

    @Test func biometryOnlyIsNotAStepOfTheSetupLadder() {
        let names = MasterKeyProtection.allCases.map(\.rawValue)
        #expect(!names.contains(BiometryOnlyKeyProtection.storedName))
        for enrolled in [true, false] {
            for step in MasterKeyProtection.ladder(biometryEnrolled: enrolled) {
                #expect(step.flags != BiometryOnlyKeyProtection.flags)
            }
        }
        // Read back as "no ladder step", so the passcode-only upgrade in
        // Vault.unlock never fires for a Face ID only item.
        #expect(MasterKeyProtection(rawValue: BiometryOnlyKeyProtection.storedName) == nil)
    }

    @Test func biometryOnlyRefusalMessageCarriesTheCode() {
        let message = KeychainError.biometryOnlyRefused(errSecAuthFailed).localizedDescription
        #expect(message.contains("-25293"))
        #expect(!message.contains("\u{2014}"))
    }

    // MARK: - YubiKey PIN

    @Test func yubiKeyPINLengthIsCheckedBeforeATap() {
        #expect(!DecryptIdentities.pinLengthIsValid(""))
        #expect(!DecryptIdentities.pinLengthIsValid("12345"))
        #expect(DecryptIdentities.pinLengthIsValid("123456"))
        #expect(DecryptIdentities.pinLengthIsValid("12345678"))
        #expect(!DecryptIdentities.pinLengthIsValid("123456789"))
        // Bytes as sent to the key, not characters on screen.
        #expect(!DecryptIdentities.pinLengthIsValid("\u{00E9}\u{00E9}\u{00E9}\u{00E9}\u{00E9}"))
    }

    // MARK: - Secure Enclave keys (Q3)

    @Test func enclaveProtectionFlags() {
        #expect(SecureEnclaveKeyProtection.noPrompt.accessControlFlags == [.privateKeyUsage])
        #expect(SecureEnclaveKeyProtection.userPresence.accessControlFlags == [.privateKeyUsage, .userPresence])
        let bio = SecureEnclaveKeyProtection.biometryCurrentSet.accessControlFlags
        #expect(bio == [.privateKeyUsage, .biometryCurrentSet])
        #expect(!bio.contains(.devicePasscode))
        #expect(!bio.contains(.userPresence))
        #expect(!bio.contains(.biometryAny))
        for protection in SecureEnclaveKeyProtection.allCases {
            #expect(protection.accessControlFlags.contains(.privateKeyUsage))
        }
    }
}
