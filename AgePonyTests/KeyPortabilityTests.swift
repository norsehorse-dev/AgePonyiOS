//
//  KeyPortabilityTests.swift
//  AgePonyTests
//
//  The iOS side of `agepony.json` (5.0.1): records go out in Android's shapes and come
//  back as the same iOS records, a hand-built Android transfer opens, entries this
//  version doesn't know are skipped one by one, and an identity whose public key isn't
//  its private key's is dropped (audit AS-2).
//

import Testing
import Foundation
import AgePonyCore
@testable import AgePony

@MainActor
struct KeyPortabilityTests {

    private func x25519() -> StoredIdentity {
        let id = X25519Identity.generate()
        return StoredIdentity(name: "laptop", type: .x25519, publicKeyMaterial: id.publicKey, privateKeyMaterial: id.privateKey)
    }

    private func postQuantum() throws -> StoredIdentity {
        let id = try HybridIdentity.generate()
        return StoredIdentity(name: "pq", type: .postQuantum, publicKeyMaterial: id.publicKey, privateKeyMaterial: id.seed)
    }

    private func ed25519() -> StoredIdentity {
        let (seed, pub) = OpenSSHEd25519Export.generate()
        return StoredIdentity(name: "ssh", type: .sshEd25519, publicKeyMaterial: SSHSig.ed25519PublicKeyWire(pub),
                              privateKeyMaterial: seed + pub, sshComment: "me@host")
    }

    @Test func identities_roundTripThroughAndroidShapes() throws {
        for original in [x25519(), try postQuantum(), ed25519()] {
            let wire = try #require(KeyPortability.wire(original))
            let back = try #require(KeyPortability.storedIdentity(wire))
            #expect(back.type == original.type)
            #expect(back.name == original.name)
            #expect(back.publicKeyMaterial == original.publicKeyMaterial)
            #expect(back.privateKeyMaterial == original.privateKeyMaterial)
            #expect(KeyPortability.isConsistent(back))
        }
    }

    @Test func ed25519_usesAndroidRawForm() throws {
        let original = ed25519()
        let wire = try #require(KeyPortability.wire(original))
        #expect(wire.type == "sshEd25519")
        #expect(Data(base64Encoded: wire.publicKeyB64)?.count == 32)
        #expect(Data(base64Encoded: wire.privateKeyB64)?.count == 32)
    }

    @Test func postQuantum_usesAndroidTypeName() throws {
        let wire = try #require(KeyPortability.wire(try postQuantum()))
        #expect(wire.type == "mlkem768x25519")
    }

    @Test func secureEnclaveKeys_neverLeave() {
        let se = StoredIdentity(name: "se", type: .secureEnclaveTag, publicKeyMaterial: Data(repeating: 2, count: 33),
                                privateKeyMaterial: Data(repeating: 1, count: 64))
        #expect(!KeyPortability.isTransferable(se))
        #expect(KeyPortability.wire(se) == nil)
    }

    @Test func mismatchedPublicKey_isDropped() throws {
        let a = x25519()
        let b = x25519()
        let forged = StoredIdentity(name: "forged", type: .x25519, publicKeyMaterial: b.publicKeyMaterial,
                                    privateKeyMaterial: a.privateKeyMaterial)
        #expect(!KeyPortability.isConsistent(forged))

        let e1 = ed25519()
        let e2 = ed25519()
        let forgedSSH = StoredIdentity(name: "forged", type: .sshEd25519, publicKeyMaterial: e2.publicKeyMaterial,
                                       privateKeyMaterial: e1.privateKeyMaterial)
        #expect(!KeyPortability.isConsistent(forgedSSH))
    }

    @Test func recipients_roundTrip_andContactsSourceStaysReadableOnAndroid() throws {
        let pq = try postQuantum()
        let r1 = StoredRecipient(name: "alice", type: .postQuantum, publicKeyMaterial: pq.publicKeyMaterial, source: .contacts)
        let e = ed25519()
        let r2 = StoredRecipient(name: "bob", type: .sshEd25519, publicKeyMaterial: e.publicKeyMaterial,
                                 sshComment: "bob@host", source: .pasteSSH)
        for r in [r1, r2] {
            let wire = try #require(KeyPortability.wire(r))
            #expect(["pasteAge", "pasteSSH", "qrScan", "github", "derivedFromIdentity"].contains(wire.source))
            let back = try #require(KeyPortability.storedRecipient(wire))
            #expect(back.type == r.type)
            #expect(back.publicKeyMaterial == r.publicKeyMaterial)
        }
    }

    /// A transfer as Android 5.0.x writes it (kotlinx.serialization, encodeDefaults, explicit
    /// nulls), with one record of a type this version doesn't know and one hardware key.
    @Test func androidMetadata_opens_skippingUnknownAndHardware() throws {
        let x = X25519Identity.generate()
        let e = ed25519()
        let edRaw = Data(e.privateKeyMaterial.suffix(32))
        let edSeed = Data(e.privateKeyMaterial.prefix(32))
        let json = """
        {"format":"agepony.com/transfer v1","app":"AgePony Android",
         "identities":[
          {"id":"1","name":"phone","type":"x25519","publicKeyB64":"\(x.publicKey.base64EncodedString())","privateKeyB64":"\(x.privateKey.base64EncodedString())","sshComment":null,"keystoreAlias":null,"createdAt":1727000000000},
          {"id":"2","name":"ssh","type":"sshEd25519","publicKeyB64":"\(edRaw.base64EncodedString())","privateKeyB64":"\(edSeed.base64EncodedString())","sshComment":"me@host","keystoreAlias":null,"createdAt":1727000000000},
          {"id":"3","name":"hw","type":"hardwareTag","publicKeyB64":"AA==","privateKeyB64":"","sshComment":null,"keystoreAlias":"k","createdAt":1},
          {"id":"4","name":"future","type":"somethingNew","publicKeyB64":"AA==","privateKeyB64":"AA==","createdAt":1}
         ],
         "recipients":[
          {"id":"5","name":"alice","type":"sshEd25519","publicKeyB64":"\(edRaw.base64EncodedString())","sshComment":null,"source":"pasteSSH","sourceMetadata":null,"createdAt":1}
         ],
         "signers":[
          {"id":"6","name":"ci","keyType":"ssh-ed25519","publicKeyWireB64":"\(e.publicKeyMaterial.base64EncodedString())","comment":null,"source":"pasteKey","createdAt":1,"options":null},
          {"id":"7","name":"scoped","keyType":"ssh-ed25519","publicKeyWireB64":"\(e.publicKeyMaterial.base64EncodedString())","comment":null,"source":"importAllowedSigners","createdAt":1,"options":"namespaces=\\"git\\""}
         ]}
        """
        let incoming = KeyPortability.readBundle(KeyTransfer.Bundle(identitiesTxt: "", metadataJSON: json))
        #expect(incoming.identities.map(\.name) == ["phone", "ssh"])
        #expect(incoming.identities[1].publicKeyMaterial == e.publicKeyMaterial)
        #expect(incoming.identities[1].privateKeyMaterial == e.privateKeyMaterial)
        #expect(incoming.recipients.count == 1)
        #expect(incoming.recipients[0].publicKeyMaterial == e.publicKeyMaterial)
        #expect(incoming.signers.count == 2)
        #expect(incoming.signers[0].refusalReason == nil)
        #expect(incoming.signers[1].refusalReason != nil)
    }

    @Test func bundle_sealsAndOpens_endToEnd() throws {
        let ids = [x25519(), try postQuantum(), ed25519()]
        let bundle = try KeyPortability.buildBundle(identities: ids, recipients: [], signers: [])
        #expect(bundle.sshKeys.count == 1)
        let receiver = try HybridIdentity.generate()
        let sealed = try KeyTransfer.seal(bundle, to: try receiver.recipient())
        let opened = KeyPortability.readBundle(try KeyTransfer.open(sealed, with: receiver))
        #expect(opened.identities.map(\.type) == ids.map(\.type))
        #expect(opened.identities.map(\.privateKeyMaterial) == ids.map(\.privateKeyMaterial))
    }

    @Test func noMetadata_fallsBackToIdentityFile() throws {
        let x = X25519Identity.generate()
        let text = "# name: from age-keygen\n\(x.ageIdentityString)\n"
        let incoming = KeyPortability.readBundle(KeyTransfer.Bundle(identitiesTxt: text))
        #expect(incoming.identities.count == 1)
        #expect(incoming.identities[0].name == "from age-keygen")
        #expect(incoming.identities[0].privateKeyMaterial == x.privateKey)
    }

    @Test func paperPassphraseWeakness() {
        #expect(PaperBackupView.passphraseWeakness("short") != nil)
        #expect(PaperBackupView.passphraseWeakness("apple-banana-cherry") != nil)
        #expect(PaperBackupView.passphraseWeakness("apple-banana-cherry-dates-elder-figs") == nil)
        #expect(PaperBackupView.passphraseWeakness("x7#Kq9!mW2$vL4") == nil)
    }

    @Test func localNetwork_privateRanges() {
        #expect(LocalNetwork.isPrivate("192.168.1.20"))
        #expect(LocalNetwork.isPrivate("172.20.10.1"))
        #expect(LocalNetwork.isPrivate("10.0.0.5"))
        #expect(!LocalNetwork.isPrivate("172.32.0.1"))
        #expect(!LocalNetwork.isPrivate("8.8.8.8"))
    }
}
