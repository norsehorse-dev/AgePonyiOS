//
//  KeychainProtectionTests.swift
//  AgePonyTests
//
//  5.1.0: setup no longer stops when iOS refuses the first Keychain protection
//  for the vault key. These pin the order the protections are tried in and the
//  message a refusal shows, so a report always carries the codes.
//

import XCTest
import Security
@testable import AgePony

final class KeychainProtectionTests: XCTestCase {

    func testLadderWithBiometricsStartsWithCurrentSet() {
        XCTAssertEqual(MasterKeyProtection.ladder(biometryEnrolled: true),
                       [.currentBiometryOrPasscode, .userPresence, .passcodeOnly])
    }

    func testLadderWithoutBiometricsSkipsCurrentSet() {
        XCTAssertEqual(MasterKeyProtection.ladder(biometryEnrolled: false),
                       [.userPresence, .passcodeOnly])
    }

    func testEveryStepKeepsASystemPrompt() {
        for protection in MasterKeyProtection.allCases {
            let flags = protection.flags
            XCTAssertTrue(flags.contains(.devicePasscode) || flags.contains(.userPresence),
                          "\(protection) must keep the passcode or user presence in front of the key")
        }
    }

    func testFirstStepIsWhatEarlierVersionsUsed() {
        XCTAssertEqual(MasterKeyProtection.currentBiometryOrPasscode.flags,
                       [.biometryCurrentSet, .or, .devicePasscode])
    }

    func testRefusalMessageCarriesTheCodes() {
        let message = KeychainError.protectionRefused([errSecAuthFailed, errSecAuthFailed]).localizedDescription
        XCTAssertTrue(message.contains("-25293, -25293"), message)
        XCTAssertFalse(message.contains("error 0"), message)
    }

    func testProtectionNamesAreStable() {
        // Stored in UserDefaults; renaming a case would lose what an installed vault recorded.
        XCTAssertEqual(MasterKeyProtection.allCases.map(\.rawValue),
                       ["currentBiometryOrPasscode", "userPresence", "passcodeOnly"])
    }
}
