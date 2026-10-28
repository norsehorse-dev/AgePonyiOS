//
//  EnclaveTagPQVaultTests.swift
//  AgePonyTests
//
//  5.1.0 RC3 (E8): a quantum-safe hardware key made on iOS 26 keeps both halves in the
//  Secure Enclave and stores the new private-material layout under the same
//  `secureEnclaveTagPQ` type. These pin what the vault does with either layout without
//  touching the Enclave (fake blobs; nothing here decrypts). The Enclave path itself is
//  in AgePonyCoreTests/EnclaveTagPQTests and the RC3 device list.
//

import Testing
import Foundation
import AgePonyCore
@testable import AgePony

@MainActor
struct EnclaveTagPQVaultTests {

    private func random(_ n: Int) -> Data {
        Data((0..<n).map { _ in UInt8.random(in: 0...255) })
    }

    /// A real 1249-byte age1tagpq1 public key, and both private layouts with fake blobs.
    private func records() throws -> (enclave: StoredIdentity, seed: StoredIdentity, recipient: TagRecipient) {
        let recipient = try TagIdentity.softwareHybrid(seed: random(32)).recipient
        let enclaveMaterial = try SecureEnclaveTagPQMaterial.enclave(mlkemBlob: random(1489), p256Blob: random(324)).encoded()
        let seedMaterial = try SecureEnclaveTagPQMaterial.vaultSeed(mlkemSeed: random(64), p256Blob: random(324)).encoded()
        let enclave = StoredIdentity(name: "new", type: .secureEnclaveTagPQ,
                                     publicKeyMaterial: recipient.publicKey, privateKeyMaterial: enclaveMaterial)
        let seed = StoredIdentity(name: "old", type: .secureEnclaveTagPQ,
                                  publicKeyMaterial: recipient.publicKey, privateKeyMaterial: seedMaterial)
        return (enclave, seed, recipient)
    }

    /// 5.0.1 decodes this enum strictly inside the vault's identity array: a new case
    /// would make a downgraded build fail to open the whole vault. RC3 adds none.
    @Test func identityTypeRawValues_unchanged() {
        #expect(StoredIdentityType.allCases.map(\.rawValue) == [
            "x25519", "postQuantum", "secureEnclaveTag", "secureEnclaveTagPQ", "yubikey",
            "sshEd25519", "sshRSA", "secureEnclaveP256", "skEd25519", "skEcdsaP256",
        ])
    }

    @Test func bothLayouts_listProbeAndStayHardwareOnly() throws {
        let (enclave, seed, recipient) = try records()
        #expect(enclave.mlkemInSecureEnclave)
        #expect(!seed.mlkemInSecureEnclave)
        let stanza = try recipient.wrap(fileKey: random(16))
        for record in [enclave, seed] {
            #expect(record.isHardwareDecryptionKey)
            #expect(!KeyPortability.isTransferable(record))
            #expect(!KeyPortability.isPaperBackable(record))
            #expect(record.publicDisplayString() == recipient.toBech32())
            let probe = try #require(record.hardwareProbe())
            #expect(probe.matches(stanza: stanza))
            #expect(try probe.unwrap(stanza: stanza) == nil)
            #expect(try record.toAgeRecipient() is TagRecipient)
        }
    }

    @Test func newLayout_survivesTheVaultsJSON() throws {
        let (enclave, _, _) = try records()
        let back = try JSONDecoder().decode(StoredIdentity.self, from: try JSONEncoder().encode(enclave))
        #expect(back.type == .secureEnclaveTagPQ)
        #expect(back.privateKeyMaterial == enclave.privateKeyMaterial)
        #expect(back.mlkemInSecureEnclave)
    }

    @Test func tooShortMaterial_isDamaged() throws {
        let (_, seed, _) = try records()
        let short = StoredIdentity(name: "bad", type: .secureEnclaveTagPQ,
                                   publicKeyMaterial: seed.publicKeyMaterial, privateKeyMaterial: random(64))
        #expect(throws: VaultModelError.malformedPrivateMaterial(.secureEnclaveTagPQ)) {
            _ = try short.toAgeIdentity()
        }
        #expect(!short.mlkemInSecureEnclave)
    }
}
