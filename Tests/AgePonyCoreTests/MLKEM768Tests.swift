//
//  MLKEM768Tests.swift
//  AgePonyCoreTests
//
//  Known-answer tests for the from-scratch FIPS 203 ML-KEM-768.
//
//  The vectors come from the same source as the Android suite: a deterministic
//  identity seed run through the filippo.io/hpke reference, which is the code the
//  `age` CLI v1.3.0+ uses. The 32-byte seed below is the AgePony post-quantum
//  identity seed from HybridRecipientTests.kt; expanding it with SHAKE256 yields
//  the 64-byte ML-KEM seed used here, so these tests pin exactly the key
//  derivation path a real age1pq identity takes.
//
//  Large values are pinned by SHA3-256 digest plus their leading bytes, which is
//  strict without embedding a kilobyte of hex; the full-length byte comparison
//  lives in HybridTests against the reference public key and encapsulation.
//
//  If `publicKeyMatchesReferenceDigest` fails, the lattice math or the FIPS 203
//  final domain separation (G(d || k)) is wrong — not the age layer above it.
//

import XCTest
@testable import AgePonyCore

final class MLKEM768Tests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return d
    }

    private func hexString(_ d: Data) -> String {
        d.map { String(format: "%02x", $0) }.joined()
    }

    /// SHAKE256(identitySeed, 96)[0..<64] — the ML-KEM seed for the reference identity.
    private var mlkemSeed: Data {
        hex("69f07c8840ce80024db30939882c3d5bbc9c98b3e31e4513ebd2ca9b4503cdd3"
            + "c9c90742452c7173d4a75ac49163e14ee0cc24ef7035b272d19a7af1099b333f")
    }

    /// The 32 bytes of encapsulation randomness from the reference vector.
    private var message: Data {
        hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    }

    // MARK: - Sizes

    func testParameterSizes() {
        XCTAssertEqual(MLKEM768.encapsulationKeySize, 1184)
        XCTAssertEqual(MLKEM768.decapsulationKeySize, 2400)
        XCTAssertEqual(MLKEM768.ciphertextSize, 1088)
        XCTAssertEqual(MLKEM768.seedSize, 64)
    }

    // MARK: - Deterministic key generation

    func testPublicKeyMatchesReferenceDigest() throws {
        let kp = try MLKEM768.keyPairFromSeed(mlkemSeed)
        XCTAssertEqual(kp.encapsulationKey.count, 1184)
        XCTAssertEqual(
            hexString(Data(kp.encapsulationKey.prefix(32))),
            "6f54098a0a0e641146614b6960ba60d8603d62f447f9ab499b47bd6906cc40b0"
        )
        XCTAssertEqual(
            hexString(Data(kp.encapsulationKey.suffix(32))),
            "f6fdeef57e399b808b7f3aa2b5740aaded90163dc5d775c9faf7f1fbd075dab3"
        )
        XCTAssertEqual(
            hexString(SHA3.sha3_256(kp.encapsulationKey)),
            "1de7bd22b6d15a2b54990d6019ce30ad3773dc810e4058a38ef00637eafcdddc"
        )
    }

    func testDecapsulationKeyMatchesReferenceDigest() throws {
        let kp = try MLKEM768.keyPairFromSeed(mlkemSeed)
        XCTAssertEqual(kp.decapsulationKey.count, 2400)
        XCTAssertEqual(
            hexString(SHA3.sha3_256(kp.decapsulationKey)),
            "50427ce818096fa38e3190b3dcb5b6a0c67272775d0db3131dd1e04b314055c7"
        )
    }

    func testKeyGenerationIsDeterministic() throws {
        let a = try MLKEM768.keyPairFromSeed(mlkemSeed)
        let b = try MLKEM768.keyPairFromSeed(mlkemSeed)
        XCTAssertEqual(a.encapsulationKey, b.encapsulationKey)
        XCTAssertEqual(a.decapsulationKey, b.decapsulationKey)
    }

    // MARK: - Deterministic encapsulation

    func testEncapsulationMatchesReference() throws {
        let kp = try MLKEM768.keyPairFromSeed(mlkemSeed)
        let (sharedSecret, ciphertext) = try MLKEM768.encapsulate(
            encapsulationKey: kp.encapsulationKey,
            message: message
        )
        XCTAssertEqual(ciphertext.count, 1088)
        XCTAssertEqual(
            hexString(sharedSecret),
            "0aa063e9cb8ea4d7551c5b5ddd10531251287f1039eeeac2d3d8cc56a54324b2"
        )
        XCTAssertEqual(
            hexString(Data(ciphertext.prefix(32))),
            "9af7658f5c013bae036cdc68e1438eeb76c2759ce252c2828d1e474b9276ae94"
        )
        XCTAssertEqual(
            hexString(SHA3.sha3_256(ciphertext)),
            "c14965d9d4e695428218a9c7bf9873d5938348011ed31bc9ce39891d32cfa5d9"
        )
    }

    func testDecapsulationRecoversReferenceSecret() throws {
        let kp = try MLKEM768.keyPairFromSeed(mlkemSeed)
        let (_, ciphertext) = try MLKEM768.encapsulate(
            encapsulationKey: kp.encapsulationKey,
            message: message
        )
        let recovered = try MLKEM768.decapsulate(
            decapsulationKey: kp.decapsulationKey,
            ciphertext: ciphertext
        )
        XCTAssertEqual(
            hexString(recovered),
            "0aa063e9cb8ea4d7551c5b5ddd10531251287f1039eeeac2d3d8cc56a54324b2"
        )
    }

    // MARK: - Round trip and implicit rejection

    func testRandomEncapsulationRoundTrips() throws {
        let seed = MLKEM768.randomBytes(64)
        let kp = try MLKEM768.keyPairFromSeed(seed)
        let (shared, ciphertext) = try MLKEM768.encapsulate(encapsulationKey: kp.encapsulationKey)
        let recovered = try MLKEM768.decapsulate(
            decapsulationKey: kp.decapsulationKey,
            ciphertext: ciphertext
        )
        XCTAssertEqual(shared, recovered)
    }

    /// FIPS 203 rejects implicitly: a tampered ciphertext yields a deterministic
    /// pseudorandom secret rather than an error, so nothing leaks about the failure.
    func testImplicitRejectionIsDeterministicAndWrong() throws {
        let kp = try MLKEM768.keyPairFromSeed(mlkemSeed)
        let (shared, ciphertext) = try MLKEM768.encapsulate(
            encapsulationKey: kp.encapsulationKey,
            message: message
        )
        var tampered = Array(ciphertext)
        tampered[0] ^= 1

        let first = try MLKEM768.decapsulate(
            decapsulationKey: kp.decapsulationKey,
            ciphertext: Data(tampered)
        )
        let second = try MLKEM768.decapsulate(
            decapsulationKey: kp.decapsulationKey,
            ciphertext: Data(tampered)
        )

        XCTAssertNotEqual(first, shared, "a tampered ciphertext must not recover the real secret")
        XCTAssertEqual(first, second, "implicit rejection must be deterministic")
        XCTAssertEqual(
            hexString(first),
            "95e4b4b21e5807a027c24bb13d7390625a7cf60c94e69b7588fb47a95484c8da"
        )
    }

    // MARK: - Input validation

    func testRejectsWrongLengths() {
        XCTAssertThrowsError(try MLKEM768.keyPairFromSeed(Data(repeating: 0, count: 63)))
        XCTAssertThrowsError(try MLKEM768.encapsulate(encapsulationKey: Data(repeating: 0, count: 100)))
        XCTAssertThrowsError(
            try MLKEM768.decapsulate(
                decapsulationKey: Data(repeating: 0, count: 2400),
                ciphertext: Data(repeating: 0, count: 10)
            )
        )
    }

    // MARK: - NTT self-consistency

    func testNTTRoundTrips() {
        var poly = [Int32](repeating: 0, count: 256)
        for i in 0..<256 { poly[i] = Int32((i * 37 + 11) % 3329) }
        XCTAssertEqual(MLKEM768.nttInverse(MLKEM768.ntt(poly)), poly)
    }

    func testByteEncodeRoundTrips() {
        for d in [1, 4, 10, 12] {
            var poly = [Int32](repeating: 0, count: 256)
            let bound = Int32(1) << Int32(d)
            for i in 0..<256 {
                poly[i] = Int32(i % Int(min(bound, 3329)))
            }
            let encoded = MLKEM768.byteEncode(d, poly)
            XCTAssertEqual(encoded.count, 32 * d, "d = \(d)")
            XCTAssertEqual(MLKEM768.byteDecode(d, encoded), poly, "d = \(d)")
        }
    }
}
