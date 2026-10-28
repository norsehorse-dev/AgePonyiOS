//
//  CryptoKitSpikeTests.swift
//  AgePonyCoreTests
//
//  5.1.0 RC3 spike for E8 (AgePony_5.1.0_Evaluation_Requests.md, write-up in
//  AgePony_5.1.0_RC3_Spike.md): can Apple CryptoKit's post-quantum APIs (macOS 26 /
//  iOS 26) replace or back AgePony's own ML-KEM and X-Wing code, byte for byte with age?
//  Test-only. Nothing in Sources/ changes.
//
//    S1  X-Wing HPKE (the mlkem768x25519 stanza) both ways, and against the CCTV vectors;
//        S1e records whether CryptoKit refuses the keys AgePony refuses on encrypt.
//    S2  XWingMLKEM768X25519.PrivateKey(seedRepresentation:) vs AGE-SECRET-KEY-PQ-1 seeds.
//    S3  MLKEM768.PrivateKey(seedRepresentation:) vs the 64-byte d || z seed the
//        age1tagpq1 keys keep in the vault, and the MLKEM768-P256 combiner fed an ML-KEM
//        secret that CryptoKit computed.
//    S4  SecureEnclave.MLKEM768: generate, decapsulate, dataRepresentation round trip,
//        access control at creation, and an age1tagpq1 file opened with both halves in
//        the Enclave through a test-local identity.
//    S5  AgePony's own path on the same vectors. The authoritative check is
//        CCTVTestkitTests.testCCTVVectors; S5 only prints a matching summary line.
//
//  Every CryptoKit post-quantum call sits behind `#available(macOS 26, iOS 26, *)`. On an
//  older system each gated test prints "Sx: SKIPPED ..." and throws XCTSkip, so the suite
//  stays green. Every test prints one summary line starting with its id:
//
//    swift test --filter CryptoKitSpikeTests 2>&1 | grep -E "S[1-5]|Executed|error:|skipped"
//
//  Name clash: AgePonyCore and CryptoKit (26) both have a `MLKEM768`. Inside AgePonyCore
//  the module's own type wins; in this file every use is written `AgePonyCore.MLKEM768` or
//  `CryptoKit.MLKEM768` so there is no doubt which one runs.
//

// Compile gate: the post-quantum CryptoKit types only exist in the macOS 26 / iOS 26 SDK
// (Xcode 26, Swift 6.2). With an older Xcode the fallback class at the bottom compiles
// instead and skips with that reason, so the rest of the test target still builds.
#if (os(macOS) || os(iOS)) && compiler(>=6.2)
import XCTest
import Foundation
import CryptoKit
import LocalAuthentication
import Security
@testable import AgePonyCore

final class CryptoKitSpikeTests: XCTestCase {

    // MARK: - Constants

    static let hybridInfo = Data("age-encryption.org/mlkem768x25519".utf8)
    static let hybridStanzaType = "mlkem768x25519"

    static var osVersion: String { ProcessInfo.processInfo.operatingSystemVersionString }

    static func needs26(_ id: String, _ what: String) -> XCTSkip {
        print("\(id): SKIPPED, needs macOS 26 / iOS 26 (\(what)); running on \(osVersion)")
        return XCTSkip("needs macOS 26: \(what) is a macOS 26 / iOS 26 CryptoKit API (running on \(osVersion))")
    }

    // MARK: - S1a: CryptoKit opens the CCTV hybrid vectors

    func testS1a_CryptoKitOpensCCTVHybridVectors() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S1a", "HPKE.KEM.XWingMLKEM768X25519")
        }
        let vectors = try Self.loadHybridVectors()
        XCTAssertFalse(vectors.isEmpty, "no *hybrid* vectors in Testkit/")

        var successTotal = 0
        var successMatched = 0
        var diffs: [String] = []
        for v in vectors {
            let ck = Self.cryptoKitOutcome(v)
            if v.expect == "success" {
                successTotal += 1
                let fk = v.fileKey ?? Data()
                let matched = !fk.isEmpty && ck.opened.contains(fk) && ck.opened.allSatisfy { $0 == fk }
                if matched {
                    successMatched += 1
                } else {
                    XCTFail("S1a \(v.name): CryptoKit did not open the stanza to the file key: \(ck.summary)")
                }
            } else {
                diffs.append("S1a-diff: \(v.name) [expect \(v.expect)] CryptoKit: \(ck.summary) | AgePony: \(Self.agePonyOutcome(v))")
            }
        }
        for d in diffs { print(d) }
        print("S1a: \(successMatched)/\(successTotal) success vectors open to the CCTV file key with CryptoKit "
              + "X-Wing HPKE (HKDF-SHA256, ChaChaPoly); \(diffs.count) non-success vectors recorded as S1a-diff lines; "
              + "\(Self.osVersion)")
        XCTAssertEqual(successMatched, successTotal)
    }

    // MARK: - S1b: AgePony opens what CryptoKit seals

    func testS1b_AgePonyOpensWhatCryptoKitSeals() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S1b", "HPKE.Sender with XWingMLKEM768X25519")
        }
        let rounds = 8
        var ok = 0
        for i in 0..<rounds {
            let identity = try HybridIdentity.generate()
            let ckPublic = try XWingMLKEM768X25519.PublicKey(rawRepresentation: identity.publicKey)
            let fileKey = Self.randomData(16)
            let (enc, body) = try CKXWing.seal(publicKey: ckPublic, plaintext: fileKey, info: Self.hybridInfo)
            XCTAssertEqual(enc.count, HpkeMlkem768X25519.encSize, "CryptoKit enc size")
            XCTAssertEqual(body.count, 32, "CryptoKit sealed body size")

            // Stanza level: AgePony's HybridIdentity.unwrap.
            let stanza = Stanza(type: Self.hybridStanzaType, args: [Stanza.base64NoPad(enc)], body: body)
            let unwrapped = try identity.unwrap(stanza: stanza)

            // File level: an age file whose header carries CryptoKit's stanza, through Age.decrypt.
            let plaintext = Data("S1b round \(i) \(UUID().uuidString)".utf8)
            let payload = try AgePayload.encrypt(plaintext: plaintext, fileKey: fileKey)
            let file = AgeHeader.serialize(stanzas: [stanza], fileKey: fileKey) + payload
            let decrypted = try Age.decrypt(ciphertext: file, identities: [identity])

            if unwrapped == fileKey && decrypted == plaintext {
                ok += 1
            } else {
                XCTFail("S1b round \(i): unwrap \(unwrapped.map(Self.hex) ?? "nil") vs \(Self.hex(fileKey)), "
                        + "file \(decrypted == plaintext ? "ok" : "differs")")
            }
        }
        print("S1b: \(ok)/\(rounds) stanzas sealed by CryptoKit to AgePony age1pq1 keys open in AgePony "
              + "(HybridIdentity.unwrap and Age.decrypt)")
    }

    // MARK: - S1c: CryptoKit opens what AgePony seals

    func testS1c_CryptoKitOpensWhatAgePonySeals() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S1c", "XWingMLKEM768X25519.PrivateKey and HPKE.Recipient")
        }
        let rounds = 8
        var stanzaOK = 0
        var fileOK = 0
        for i in 0..<rounds {
            let ckKey = try XWingMLKEM768X25519.PrivateKey.generate()
            let publicKey = ckKey.publicKey.rawRepresentation
            XCTAssertEqual(publicKey.count, HpkeMlkem768X25519.publicKeySize, "CryptoKit X-Wing public key size")

            // CryptoKit key -> age1pq1 string -> AgePony recipient.
            let ageString = try HybridRecipient(publicKey: publicKey).ageRecipient
            let recipient = try HybridRecipient(ageRecipient: ageString)
            XCTAssertEqual(recipient.publicKey, publicKey)

            // Stanza level, known file key.
            let fileKey = Self.randomData(16)
            let stanza = try recipient.wrap(fileKey: fileKey)
            let opened = try CKXWing.open(privateKey: ckKey,
                                          enc: try Stanza.base64Decode(stanza.args[0]),
                                          body: stanza.body, info: Self.hybridInfo)
            if opened == fileKey { stanzaOK += 1 } else { XCTFail("S1c round \(i): stanza opened to \(Self.hex(opened))") }

            // File level: Age.encrypt, CryptoKit unwraps the file key, AgePony checks the MAC
            // and decrypts the payload with it.
            let plaintext = Data("S1c round \(i) \(UUID().uuidString)".utf8)
            let file = try Age.encrypt(plaintext: plaintext, to: [recipient])
            let (header, payloadOffset) = try AgeHeader.parse(bytes: file)
            let s = try XCTUnwrap(header.stanzas.first { $0.type == Self.hybridStanzaType })
            let fk = try CKXWing.open(privateKey: ckKey, enc: try Stanza.base64Decode(s.args[0]),
                                      body: s.body, info: Self.hybridInfo)
            try header.verifyMAC(fileKey: fk)
            let out = try AgePayload.decrypt(bytes: Data(file.dropFirst(payloadOffset)), fileKey: fk)
            if out == plaintext { fileOK += 1 } else { XCTFail("S1c round \(i): payload differs") }
        }
        print("S1c: \(stanzaOK)/\(rounds) AgePony stanzas and \(fileOK)/\(rounds) Age.encrypt files to "
              + "CryptoKit-generated X-Wing keys open in CryptoKit (via age1pq1 string round trip)")
    }

    // MARK: - S1d: KEM level, X-Wing shared secret

    func testS1d_XWingKEMSharedSecretMatches() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S1d", "XWingMLKEM768X25519.PrivateKey.decapsulate")
        }
        let rounds = 8
        var ok = 0
        for _ in 0..<rounds {
            let identity = try HybridIdentity.generate()
            let (ss, enc) = try HpkeMlkem768X25519.encap(publicKey: identity.publicKey)
            let ckKey = try CKXWing.privateKey(seed: identity.seed)
            let ckSS = SpikeKit.bytes(try ckKey.decapsulate(enc))
            if ckSS == ss { ok += 1 } else { XCTFail("S1d: shared secret \(Self.hex(ckSS)) != \(Self.hex(ss))") }
        }
        print("S1d: \(ok)/\(rounds) X-Wing shared secrets equal (AgePony encap, CryptoKit decapsulate)")
    }

    // MARK: - S1e: encrypt-side input checks (recorded, not asserted)

    /// AgePony refuses to encrypt to an ML-KEM key that fails the FIPS 203 modulus check and
    /// to an age1pq1 key whose X25519 half is low order. Does CryptoKit refuse them too, or
    /// must those checks stay in front of it?
    func testS1e_EncryptSideInputChecks() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S1e", "MLKEM768.PublicKey and HPKE.Sender with XWingMLKEM768X25519")
        }
        let good = try HybridIdentity.generate().publicKey
        var badEK = Data(good.prefix(AgePonyCore.MLKEM768.encapsulationKeySize))
        badEK[badEK.startIndex] = 0xFF
        badEK[badEK.startIndex + 1] |= 0x0F            // first 12-bit coefficient = 4095 >= q
        XCTAssertFalse(AgePonyCore.MLKEM768.isValidEncapsulationKey(badEK))
        let basePoint = Data([9] + [UInt8](repeating: 0, count: 31))
        let zeroPoint = Data(repeating: 0, count: 32)  // low order: all-zero shared secret

        var notes: [String] = []
        do {
            let pk = try CryptoKit.MLKEM768.PublicKey(rawRepresentation: badEK)
            do {
                _ = try pk.encapsulate()
                notes.append("MLKEM768 bad-modulus key: accepted, encapsulate() ran")
            } catch {
                notes.append("MLKEM768 bad-modulus key: accepted, encapsulate() threw \(type(of: error)).\(error)")
            }
        } catch {
            notes.append("MLKEM768 bad-modulus key: PublicKey(rawRepresentation:) threw \(type(of: error)).\(error)")
        }
        notes.append("X-Wing bad-modulus key: " + Self.cryptoKitSealProbe(badEK + basePoint))
        notes.append("X-Wing low-order X25519 half: "
                     + Self.cryptoKitSealProbe(Data(good.prefix(AgePonyCore.MLKEM768.encapsulationKeySize)) + zeroPoint))
        var agePony: [String] = []
        for (label, key) in [("bad-modulus", badEK + basePoint),
                             ("low-order", Data(good.prefix(AgePonyCore.MLKEM768.encapsulationKeySize)) + zeroPoint)] {
            do {
                _ = try HybridRecipient(publicKey: key).wrap(fileKey: Self.randomData(16))
                agePony.append("\(label) accepted")
            } catch {
                agePony.append("\(label) refused (\(error))")
            }
        }
        print("S1e: CryptoKit: " + notes.joined(separator: "; ") + " | AgePony wrap: " + agePony.joined(separator: ", "))
    }

    @available(macOS 26, iOS 26, *)
    static func cryptoKitSealProbe(_ publicKey: Data) -> String {
        let pk: XWingMLKEM768X25519.PublicKey
        do {
            pk = try XWingMLKEM768X25519.PublicKey(rawRepresentation: publicKey)
        } catch {
            return "PublicKey(rawRepresentation:) threw \(type(of: error)).\(error)"
        }
        do {
            _ = try CKXWing.seal(publicKey: pk, plaintext: randomData(16), info: hybridInfo)
            return "accepted, HPKE seal ran"
        } catch {
            return "accepted, HPKE seal threw \(type(of: error)).\(error)"
        }
    }

    // MARK: - S2: X-Wing seeds

    func testS2_XWingSeedRepresentationMatchesAgeIdentity() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S2", "XWingMLKEM768X25519.PrivateKey(seedRepresentation:publicKey:)")
        }
        var seeds: [(label: String, seed: Data)] = []
        for v in try Self.loadHybridVectors() {
            for s in v.pqSeeds where !seeds.contains(where: { $0.seed == s }) {
                seeds.append(("CCTV \(v.name)", s))
            }
        }
        let cctvCount = seeds.count
        seeds.append(("fixed 00..1f (HybridTests)", Data((0..<32).map { UInt8($0) })))
        let fresh = 8
        for i in 0..<fresh { seeds.append(("fresh #\(i)", try HybridIdentity.generate().seed)) }

        var forward = 0
        for (label, seed) in seeds {
            let ap = try HybridIdentity(seed: seed)
            let ck = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)
            XCTAssertEqual(ck.seedRepresentation, seed, "S2 \(label): seedRepresentation round trip")
            // The consistency-check form must accept AgePony's public key.
            let apPublic = try XWingMLKEM768X25519.PublicKey(rawRepresentation: ap.publicKey)
            _ = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: apPublic)
            if ck.publicKey.rawRepresentation == ap.publicKey {
                forward += 1
            } else {
                XCTFail("S2 \(label): CryptoKit public key differs from AgePony's age1pq1 key")
            }
        }

        // A mismatched publicKey should be refused (documents the check; not asserted).
        var wrongRefused = "no"
        do {
            let other = try XWingMLKEM768X25519.PublicKey(rawRepresentation: try HybridIdentity.generate().publicKey)
            _ = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seeds[0].seed, publicKey: other)
        } catch {
            wrongRefused = "yes (\(type(of: error)).\(error))"
        }

        // Reverse: CryptoKit-generated seeds into AgePony.
        let reverseRounds = 8
        var reverse = 0
        for _ in 0..<reverseRounds {
            let ck = try XWingMLKEM768X25519.PrivateKey.generate()
            let seed = ck.seedRepresentation
            XCTAssertEqual(seed.count, HpkeMlkem768X25519.seedSize, "CryptoKit X-Wing seed size")
            let ap = try HybridIdentity(seed: seed)
            XCTAssertEqual(try HybridIdentity(ageIdentity: ap.ageIdentityString).seed, seed)
            if ap.publicKey == ck.publicKey.rawRepresentation {
                reverse += 1
            } else {
                XCTFail("S2 reverse: AgePony public key from a CryptoKit seed differs")
            }
        }
        print("S2: \(forward)/\(seeds.count) AGE-SECRET-KEY-PQ-1 seeds (\(cctvCount) CCTV, 1 fixed, \(fresh) fresh) "
              + "give the same age1pq1 public key in CryptoKit; \(reverse)/\(reverseRounds) CryptoKit seeds "
              + "round-trip into HybridIdentity; mismatched publicKey refused: \(wrongRefused)")
    }

    // MARK: - S3: ML-KEM-768 from the 64-byte vault seed

    func testS3_MLKEM768SeedAndKEMInterop() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S3", "MLKEM768.PrivateKey(seedRepresentation:publicKey:)")
        }
        var seeds: [Data] = []
        // As GenerateIdentityView makes them for secureEnclaveTagPQ: 64 random bytes.
        for _ in 0..<6 { seeds.append(Self.randomData(AgePonyCore.MLKEM768.seedSize)) }
        // As TagIdentity.softwareHybrid derives them: the age-plugin-tagtest key and two random seeds.
        seeds.append(try HpkeP256.hybridExpandSeed(HpkeP256.hybridDeriveSeed(ikm: Data("age-plugin-tagtest".utf8))).mlkemSeed)
        for _ in 0..<2 { seeds.append(try HpkeP256.hybridExpandSeed(Self.randomData(32)).mlkemSeed) }

        var keyMatch = 0, apToCK = 0, ckToAP = 0, rejectMatch = 0
        for (i, seed) in seeds.enumerated() {
            let ap = try AgePonyCore.MLKEM768.keyPairFromSeed(seed)
            let ck = try CryptoKit.MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil)
            XCTAssertEqual(ck.seedRepresentation, seed, "S3 #\(i): seedRepresentation round trip")
            let apPublic = try CryptoKit.MLKEM768.PublicKey(rawRepresentation: ap.encapsulationKey)
            _ = try CryptoKit.MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: apPublic)
            if ck.publicKey.rawRepresentation == ap.encapsulationKey {
                keyMatch += 1
            } else {
                XCTFail("S3 #\(i): encapsulation keys differ")
            }

            // AgePony encapsulates, CryptoKit decapsulates.
            let (ss1, ct1) = try AgePonyCore.MLKEM768.encapsulate(encapsulationKey: ap.encapsulationKey)
            let ck1 = SpikeKit.bytes(try ck.decapsulate(ct1))
            if ck1 == ss1 { apToCK += 1 } else { XCTFail("S3 #\(i): AgePony -> CryptoKit secret differs") }

            // CryptoKit encapsulates to AgePony's key bytes, AgePony decapsulates.
            let r = try apPublic.encapsulate()
            let ap2 = try AgePonyCore.MLKEM768.decapsulate(decapsulationKey: ap.decapsulationKey,
                                                           ciphertext: r.encapsulated)
            if ap2 == SpikeKit.bytes(r.sharedSecret) { ckToAP += 1 } else { XCTFail("S3 #\(i): CryptoKit -> AgePony secret differs") }

            // FIPS 203 implicit rejection: a corrupted ciphertext gives the same J(z || c).
            var bad = ct1
            bad[bad.startIndex] ^= 0x01
            let apBad = try AgePonyCore.MLKEM768.decapsulate(decapsulationKey: ap.decapsulationKey, ciphertext: bad)
            let ckBad = SpikeKit.bytes(try ck.decapsulate(bad))
            if apBad == ckBad { rejectMatch += 1 } else { XCTFail("S3 #\(i): implicit rejection secrets differ") }
        }
        let n = seeds.count
        print("S3: \(keyMatch)/\(n) 64-byte d||z seeds give the same ML-KEM-768 encapsulation key; shared secrets "
              + "AgePony->CryptoKit \(apToCK)/\(n), CryptoKit->AgePony \(ckToAP)/\(n); implicit rejection equal \(rejectMatch)/\(n)")
    }

    // MARK: - S3b: the MLKEM768-P256 combiner with CryptoKit's ML-KEM secret

    func testS3b_TagCombinerTakesCryptoKitMLKEMSecret() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S3b", "MLKEM768.PrivateKey.decapsulate")
        }
        let rounds = 6
        var ok = 0
        for i in 0..<rounds {
            let (mlkemSeed, scalar) = try HpkeP256.hybridExpandSeed(Self.randomData(32))
            let p256 = try P256SoftwareKey(scalar: scalar)
            let identity = try TagIdentity.hybrid(mlkemSeed: mlkemSeed, p256PublicKey: p256.publicUncompressed, p256: p256)
            let ck = try CryptoKit.MLKEM768.PrivateKey(seedRepresentation: mlkemSeed, publicKey: nil)

            let fileKey = Self.randomData(16)
            let stanza = try identity.recipient.wrap(fileKey: fileKey)
            let viaCryptoKit = try SpikeKit.unwrapTagPQ(stanza: stanza, recipient: identity.recipient,
                                                    decapsulate: { SpikeKit.bytes(try ck.decapsulate($0)) },
                                                    p256: p256)
            let viaAgePony = try identity.unwrap(stanza: stanza)
            if viaCryptoKit == fileKey && viaAgePony == fileKey {
                ok += 1
            } else {
                XCTFail("S3b round \(i): CryptoKit-backed unwrap \(viaCryptoKit.map(Self.hex) ?? "nil"), "
                        + "AgePony \(viaAgePony.map(Self.hex) ?? "nil"), want \(Self.hex(fileKey))")
            }
        }
        print("S3b: \(ok)/\(rounds) mlkem768p256tag stanzas open with the ML-KEM half decapsulated by CryptoKit "
              + "and fed to HpkeP256.hybridCombine (no Sources change)")
    }

    // MARK: - S4: Secure Enclave ML-KEM-768

    func testS4_SecureEnclaveMLKEM768() throws {
        guard #available(macOS 26, iOS 26, *) else {
            throw Self.needs26("S4", "SecureEnclave.MLKEM768")
        }
        guard SecureEnclave.isAvailable else {
            print("S4: SKIPPED, SecureEnclave.isAvailable is false on this machine (\(Self.osVersion))")
            throw XCTSkip("no Secure Enclave on this machine (SecureEnclave.isAvailable == false)")
        }

        // S4a: default access control.
        let defaultKey: SecureEnclave.MLKEM768.PrivateKey
        do {
            defaultKey = try SecureEnclave.MLKEM768.PrivateKey.generate()
        } catch {
            print("S4: SKIPPED, SecureEnclave.MLKEM768.PrivateKey.generate() threw \(type(of: error)).\(error) "
                  + "in this test process (\(Self.osVersion))")
            throw XCTSkip("Secure Enclave ML-KEM key creation failed in a CLI test process: \(error)")
        }
        let a = try Self.exerciseEnclaveKey(defaultKey, authenticationContext: nil)
        print("S4a: default access control: \(a.summary)")
        XCTAssertTrue(a.allOK, "S4a: \(a.summary)")

        // S4b: [.privateKeyUsage] only, as SecureEnclaveKeyProtection.noPrompt, with an LAContext.
        guard let noPrompt = Self.accessControl(.noPrompt) else {
            XCTFail("S4b: SecAccessControlCreateWithFlags returned nil")
            return
        }
        let acKey: SecureEnclave.MLKEM768.PrivateKey
        do {
            acKey = try SecureEnclave.MLKEM768.PrivateKey(accessControl: noPrompt, authenticationContext: LAContext())
        } catch {
            print("S4b: SecureEnclave.MLKEM768.PrivateKey(accessControl: [.privateKeyUsage]) threw \(type(of: error)).\(error)")
            XCTFail("S4b: key creation with [.privateKeyUsage] failed: \(error)")
            return
        }
        let b = try Self.exerciseEnclaveKey(acKey, authenticationContext: LAContext())
        print("S4b: [.privateKeyUsage] + LAContext: \(b.summary)")
        XCTAssertTrue(b.allOK, "S4b: \(b.summary)")

        // S4c: the Enclave accepts each SecureEnclaveKeyProtection's flags for an ML-KEM key.
        // Creation only: nothing is decapsulated, so nothing prompts.
        var flags: [String] = []
        for p in SecureEnclaveKeyProtection.allCases {
            guard let ac = Self.accessControl(p) else {
                flags.append("\(p.rawValue): SecAccessControl nil")
                continue
            }
            do {
                let k = try SecureEnclave.MLKEM768.PrivateKey(accessControl: ac)
                flags.append("\(p.rawValue): created (\(k.dataRepresentation.count)-byte blob)")
            } catch {
                flags.append("\(p.rawValue): threw \(type(of: error)).\(error)")
            }
        }
        print("S4c: ML-KEM key creation with the P-256 key's flags: " + flags.joined(separator: "; "))

        // S4d: an age1tagpq1 recipient with the ML-KEM half from S4b and a P-256 Enclave key;
        // Age.encrypt to it, Age.decrypt with a test-local identity that runs both halves in
        // the Enclave through the existing MLKEM768-P256 combiner.
        let p256Key: (dataRepresentation: Data, publicUncompressed: Data)
        do {
            p256Key = try SecureEnclaveKeyAgreement.generate(protection: .noPrompt)
        } catch {
            print("S4d: not run, SecureEnclaveKeyAgreement.generate threw \(error)")
            print("S4: ML-KEM in the Enclave: S4a \(a.allOK ? "ok" : "FAILED"), S4b \(b.allOK ? "ok" : "FAILED"); "
                  + "S4d not run (P-256 Enclave key unavailable in this process)")
            return
        }
        let p256Blob = p256Key.dataRepresentation
        let recipient = try TagRecipient(publicKey: acKey.publicKey.rawRepresentation + p256Key.publicUncompressed)
        let reparsed = try TagRecipient(ageRecipient: recipient.toBech32())   // includes the FIPS 203 modulus check
        XCTAssertEqual(reparsed, recipient)
        let plaintext = Data("S4d \(UUID().uuidString)".utf8)
        let file = try Age.encrypt(plaintext: plaintext, to: [reparsed])
        let identity = EnclaveTagPQIdentitySketch(
            recipient: recipient,
            mlkemDataRepresentation: acKey.dataRepresentation,
            p256: SecureEnclaveKeyAgreement(dataRepresentation: p256Blob),
            authenticationContext: nil
        )
        let decrypted = try Age.decrypt(ciphertext: file, identities: [identity])
        let d = decrypted == plaintext
        XCTAssertTrue(d, "S4d: Enclave-only age1tagpq1 file did not round trip")
        print("S4d: age1tagpq1 file with ML-KEM and P-256 both in the Enclave: \(d ? "opened" : "FAILED") "
              + "(\(recipient.toBech32().count)-char recipient)")
        print("S4: ML-KEM in the Enclave: S4a \(a.allOK ? "ok" : "FAILED"), S4b \(b.allOK ? "ok" : "FAILED"), "
              + "S4d \(d ? "ok" : "FAILED"); ML-KEM blob \(b.blobSize) bytes, P-256 blob \(p256Blob.count) bytes")
    }

    // MARK: - S5: AgePony's own path on the same vectors

    func testS5_AgePonyOwnPathOnSameVectors() throws {
        let vectors = try Self.loadHybridVectors()
        var agree = 0
        var notes: [String] = []
        for v in vectors {
            guard case .vector(let cv) = CCTVTestkitTests.parse(name: v.name, raw: v.raw) else {
                notes.append("\(v.name): runner skipped it")
                continue
            }
            let o = CCTVTestkitTests.run(cv)
            let aliased = cv.expect == .headerFailure && o.category == .noMatch
            if o.category == cv.expect || aliased {
                agree += 1
            } else {
                notes.append("\(v.name): expected \(cv.expect.rawValue), got \(o.category.rawValue)")
            }
        }
        for n in notes { print("S5-note: \(n)") }
        print("S5: \(agree)/\(vectors.count) *hybrid* vectors give the expected CCTV result through AgePony's own "
              + "code (category only; the authoritative check with hashes, alias and divergence rules is "
              + "CCTVTestkitTests.testCCTVVectors)")
    }

    // MARK: - CCTV hybrid vector loading

    struct HybridVector {
        let name: String
        let raw: Data
        let expect: String
        let fileKey: Data?
        let pqSeeds: [Data]
        /// The age file after zlib and armor, nil if that step failed.
        let file: Data?
        let prepError: String?
    }

    struct LooseStanza {
        let type: String
        let args: [String]
        /// nil if a body line isn't base64 even when read leniently.
        let body: Data?
        var enc: Data? { args.first.flatMap { SpikeKit.lenientBase64($0) } }
    }

    enum SpikeError: Error {
        case malformedVector(String)
    }

    /// Every Testkit vector with "hybrid" in its name (the 18 hybrid* plus armor_hybrid).
    static func loadHybridVectors() throws -> [HybridVector] {
        let root = try XCTUnwrap(
            Bundle.module.url(forResource: "Testkit", withExtension: nil),
            "Testkit folder missing from the test bundle (check resources in Package.swift)"
        )
        let urls = try FileManager.default
            .contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.contains("hybrid") }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        return try urls.map { try parseHybridVector(name: $0.lastPathComponent, raw: try Data(contentsOf: $0)) }
    }

    /// The CCTV header keys this spike needs, including `file key`, which CCTVTestkitTests ignores.
    static func parseHybridVector(name: String, raw: Data) throws -> HybridVector {
        guard let sep = raw.range(of: Data([0x0A, 0x0A])) else { throw SpikeError.malformedVector(name) }
        let headerText = String(decoding: raw[raw.startIndex..<sep.lowerBound], as: UTF8.self)
        var expect = ""
        var fileKey: Data?
        var identities: [String] = []
        var armored = false
        var compressed = false
        for line in headerText.split(separator: "\n") {
            guard let colon = line.range(of: ": ") else { continue }
            let key = String(line[line.startIndex..<colon.lowerBound])
            let value = String(line[colon.upperBound...])
            switch key {
            case "expect": expect = value
            case "file key": fileKey = hexDecode(value)
            case "identity": identities.append(value)
            case "armored": armored = value == "yes"
            case "compressed": compressed = value == "zlib"
            default: break
            }
        }
        let pqSeeds = identities
            .filter { $0.uppercased().hasPrefix("AGE-SECRET-KEY-PQ-1") }
            .compactMap { try? HybridIdentity(ageIdentity: $0).seed }

        var body = Data(raw[sep.upperBound...])
        var file: Data?
        var prepError: String?
        do {
            if compressed { body = try CCTVTestkitTests.inflateZlib(body) }
            if armored { body = try AgeArmor.decode(String(decoding: body, as: UTF8.self)) }
            file = body
        } catch {
            prepError = "\(type(of: error)).\(error)"
        }
        return HybridVector(name: name, raw: raw, expect: expect, fileKey: fileKey, pqSeeds: pqSeeds,
                            file: file, prepError: prepError)
    }

    /// Header stanzas read leniently (padding and non-canonical base64 accepted, any
    /// argument count), so CryptoKit can be shown the bytes of vectors age refuses.
    static func looseStanzas(in file: Data) -> [LooseStanza] {
        let lines = String(decoding: file, as: UTF8.self).components(separatedBy: "\n")
        var out: [LooseStanza] = []
        var i = 0
        while i < lines.count {
            let line = lines[i]
            if line.hasPrefix("---") { break }
            guard line.hasPrefix("-> ") else { i += 1; continue }
            let parts = line.dropFirst(3).split(separator: " ", omittingEmptySubsequences: false).map(String.init)
            i += 1
            var body = Data()
            var bodyOK = true
            while i < lines.count {
                let l = lines[i]
                if l.hasPrefix("->") || l.hasPrefix("---") { break }
                i += 1
                guard let d = SpikeKit.lenientBase64(l) else { bodyOK = false; break }
                body.append(d)
                if d.count < 48 { break }
            }
            out.append(LooseStanza(type: parts.first ?? "", args: Array(parts.dropFirst()), body: bodyOK ? body : nil))
        }
        return out
    }

    // MARK: - What each side does with a vector

    @available(macOS 26, iOS 26, *)
    static func cryptoKitOutcome(_ v: HybridVector) -> (opened: [Data], summary: String) {
        guard let file = v.file else { return ([], "n/a, file prep failed: \(v.prepError ?? "?")") }
        let stanzas = looseStanzas(in: file).filter { $0.type.lowercased() == hybridStanzaType }
        guard !stanzas.isEmpty else { return ([], "n/a, no mlkem768x25519 stanza in the header") }
        var opened: [Data] = []
        var notes: [String] = []
        for seed in v.pqSeeds {
            let key: XWingMLKEM768X25519.PrivateKey
            do {
                key = try CKXWing.privateKey(seed: seed)
            } catch {
                notes.append("key from seed threw \(type(of: error)).\(error)")
                continue
            }
            for (idx, s) in stanzas.enumerated() {
                guard let enc = s.enc, let body = s.body else {
                    notes.append("#\(idx) base64 unreadable")
                    continue
                }
                do {
                    let pt = try CKXWing.open(privateKey: key, enc: enc, body: body, info: hybridInfo)
                    opened.append(pt)
                    let what = pt == v.fileKey ? "= file key" : hex(pt)
                    notes.append("#\(idx) opened \(pt.count) bytes (\(what)), enc \(enc.count), args \(s.args.count)")
                } catch {
                    notes.append("#\(idx) threw \(type(of: error)).\(error) (enc \(enc.count) bytes)")
                }
            }
        }
        return (opened, notes.joined(separator: "; "))
    }

    /// AgePony on the same lenient stanzas (HybridIdentity.unwrap), then the whole file
    /// through CCTVTestkitTests' runner, which is AgePony's real decrypt path.
    static func agePonyOutcome(_ v: HybridVector) -> String {
        var parts: [String] = []
        if let file = v.file {
            let stanzas = looseStanzas(in: file).filter { $0.type.lowercased() == hybridStanzaType }
            for seed in v.pqSeeds {
                guard let id = try? HybridIdentity(seed: seed) else { continue }
                for (idx, s) in stanzas.enumerated() {
                    guard let body = s.body else { continue }
                    do {
                        if let k = try id.unwrap(stanza: Stanza(type: s.type, args: s.args, body: body)) {
                            parts.append("#\(idx) unwrap -> \(k.count) bytes")
                        } else {
                            parts.append("#\(idx) unwrap -> nil")
                        }
                    } catch {
                        parts.append("#\(idx) unwrap threw \(error)")
                    }
                }
            }
        }
        if case .vector(let cv) = CCTVTestkitTests.parse(name: v.name, raw: v.raw) {
            let o = CCTVTestkitTests.run(cv)
            parts.append("file: \(o.category.rawValue) (\(o.detail))")
        }
        return parts.joined(separator: "; ")
    }

    // MARK: - Secure Enclave helpers

    struct EnclaveResult {
        var ekSize = 0
        var ekValid = false
        var blobSize = 0
        var agePonyEncap = false
        var cryptoKitEncap = false
        var reloadSamePublic = false
        var reloadDecap = false

        var allOK: Bool {
            ekSize == AgePonyCore.MLKEM768.encapsulationKeySize && ekValid
                && agePonyEncap && cryptoKitEncap && reloadSamePublic && reloadDecap
        }
        var summary: String {
            "ek \(ekSize) bytes (FIPS 203 check \(ekValid ? "ok" : "FAILED")), blob \(blobSize) bytes; "
                + "AgePony encap -> Enclave decap \(agePonyEncap ? "equal" : "DIFFERS"); "
                + "CryptoKit encap -> Enclave decap \(cryptoKitEncap ? "equal" : "DIFFERS"); "
                + "dataRepresentation reload: public \(reloadSamePublic ? "same" : "DIFFERS"), "
                + "decap \(reloadDecap ? "equal" : "DIFFERS")"
        }
    }

    @available(macOS 26, iOS 26, *)
    static func exerciseEnclaveKey(_ key: SecureEnclave.MLKEM768.PrivateKey,
                                   authenticationContext: LAContext?) throws -> EnclaveResult {
        var r = EnclaveResult()
        let ek = key.publicKey.rawRepresentation
        r.ekSize = ek.count
        r.ekValid = AgePonyCore.MLKEM768.isValidEncapsulationKey(ek)
        r.blobSize = key.dataRepresentation.count

        let (ss1, ct1) = try AgePonyCore.MLKEM768.encapsulate(encapsulationKey: ek)
        let enclave1 = SpikeKit.bytes(try key.decapsulate(ct1))
        r.agePonyEncap = enclave1 == ss1

        let res = try key.publicKey.encapsulate()
        let enclave2 = SpikeKit.bytes(try key.decapsulate(res.encapsulated))
        r.cryptoKitEncap = enclave2 == SpikeKit.bytes(res.sharedSecret)

        let reloaded = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: key.dataRepresentation,
                                                             authenticationContext: authenticationContext)
        r.reloadSamePublic = reloaded.publicKey.rawRepresentation == ek
        let enclave3 = SpikeKit.bytes(try reloaded.decapsulate(ct1))
        r.reloadDecap = enclave3 == ss1
        return r
    }

    /// The same SecAccessControl SecureEnclaveKeyAgreement.generate(protection:) builds.
    static func accessControl(_ p: SecureEnclaveKeyProtection) -> SecAccessControl? {
        SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                        p.accessControlFlags, nil)
    }

    // MARK: - Small helpers

    static func randomData(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &g) })
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    static func hexDecode(_ s: String) -> Data? {
        let chars = Array(s.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data()
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(decoding: chars[i..<(i + 2)], as: UTF8.self), radix: 16) else { return nil }
            out.append(b)
            i += 2
        }
        return out
    }
}

// MARK: - Helpers outside the test class

/// Kept out of the XCTestCase subclass so the test-local identity below can call them
/// from any context.
enum SpikeKit {
    static func bytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    static func lenientBase64(_ s: String) -> Data? {
        let t = s.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "=", with: "")
        let pad = (4 - t.utf8.count % 4) % 4
        if pad == 3 { return nil }
        return Data(base64Encoded: t + String(repeating: "=", count: pad))
    }

    /// MLKEM768-P256 unwrap where the ML-KEM decapsulation is a closure: the shape
    /// TagIdentity.unwrap would have with a pluggable ML-KEM half (RC3 doc, S4 design).
    /// Same order as TagIdentity: tag check first, so hardware only acts for its stanzas.
    static func unwrapTagPQ(stanza: Stanza, recipient: TagRecipient,
                            decapsulate: (Data) throws -> Data,
                            p256: any P256KeyAgreement) throws -> Data? {
        guard recipient.isHybrid, stanza.type == TagRecipient.hybridStanzaType,
              stanza.args.count == 2, stanza.body.count == TagRecipient.bodySize,
              let tag = try? Stanza.base64Decode(stanza.args[0]),
              let enc = try? Stanza.base64Decode(stanza.args[1]),
              enc.count == HpkeP256.hybridEncSize,
              tag == recipient.tag(enc: enc)
        else { return nil }
        let ctPQ = Data(enc.prefix(AgePonyCore.MLKEM768.ciphertextSize))
        let ctT = Data(enc.suffix(P256Curve.uncompressedSize))
        _ = try P256Curve.decode(ctT)
        let ssPQ = try decapsulate(ctPQ)
        let ssT = try p256.sharedX(peerUncompressed: ctT)
        let ss = HpkeP256.hybridCombine(ssPQ: ssPQ, ssT: ssT, ctT: ctT, ekT: recipient.p256Part)
        return try? HpkeP256.open(kemID: HpkeP256.kemMLKEM768P256, sharedSecret: ss,
                                  info: TagRecipient.hybridLabel, ciphertext: stanza.body)
    }
}

// MARK: - CryptoKit X-Wing HPKE, age's mlkem768x25519 suite

/// HPKE base mode with KEM X-Wing (MLKEM768-X25519, 0x647A), HKDF-SHA256, ChaCha20Poly1305:
/// the suite age's mlkem768x25519 stanza uses. CryptoKit's built-in
/// XWingMLKEM768X25519_SHA256_AES_GCM_256 is AES-GCM, so the suite is built by hand.
@available(macOS 26, iOS 26, *)
enum CKXWing {
    static var suite: HPKE.Ciphersuite {
        HPKE.Ciphersuite(kem: .XWingMLKEM768X25519, kdf: .HKDF_SHA256, aead: .chaChaPoly)
    }

    static func privateKey(seed: Data) throws -> XWingMLKEM768X25519.PrivateKey {
        try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil)
    }

    /// Single-shot open: the first message of a context uses base_nonce, as age does. Empty AAD.
    static func open(privateKey: XWingMLKEM768X25519.PrivateKey, enc: Data, body: Data, info: Data) throws -> Data {
        var recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: suite, info: info, encapsulatedKey: enc)
        return try recipient.open(body, authenticating: Data())
    }

    static func seal(publicKey: XWingMLKEM768X25519.PublicKey, plaintext: Data, info: Data) throws -> (enc: Data, ciphertext: Data) {
        var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: suite, info: info)
        let ciphertext = try sender.seal(plaintext, authenticating: Data())
        return (sender.encapsulatedKey, ciphertext)
    }
}

// MARK: - S4 sketch: an age1tagpq1 identity with both halves in the Secure Enclave

/// Test-local stand-in for the new stored identity kind (RC3 doc, S4 design): no ML-KEM
/// seed, two Enclave handles. Not in Sources; the real one would make TagIdentity take a
/// pluggable ML-KEM half instead.
@available(macOS 26, iOS 26, *)
struct EnclaveTagPQIdentitySketch: AgeIdentity {
    let recipient: TagRecipient
    let mlkemDataRepresentation: Data
    let p256: SecureEnclaveKeyAgreement
    let authenticationContext: LAContext?

    func unwrap(stanza: Stanza) throws -> Data? {
        try SpikeKit.unwrapTagPQ(
            stanza: stanza,
            recipient: recipient,
            decapsulate: { ctPQ in
                let key = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: mlkemDataRepresentation,
                                                                authenticationContext: authenticationContext)
                return SpikeKit.bytes(try key.decapsulate(ctPQ))
            },
            p256: p256
        )
    }
}
#elseif os(macOS) || os(iOS)
import XCTest

final class CryptoKitSpikeTests: XCTestCase {
    func testS0_NeedsXcode26() throws {
        print("S1-S5: SKIPPED, this toolchain predates Swift 6.2 and the macOS 26 SDK, so CryptoKit's "
              + "post-quantum types don't exist at compile time")
        throw XCTSkip("needs Xcode 26 (Swift 6.2, macOS 26 SDK) to compile the CryptoKit post-quantum spike")
    }
}
#endif
