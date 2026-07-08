//
//  AgeStreamingTests.swift
//  AgePonyCoreTests
//
//  Tests for the streaming encrypt/decrypt API (Age.encryptStream / decryptStream).
//  The streamed output uses the same age v1 format as the buffered path, so the key
//  guarantees here are: a streamed file decrypts with the buffered API and vice versa,
//  and the chunk look-ahead flags the final chunk correctly at every size boundary.
//

import XCTest
@testable import AgePonyCore

final class AgeStreamingTests: XCTestCase {

    // MARK: - Helpers

    private func streamEncrypt(_ plaintext: Data, to recipients: [AgeRecipient]) throws -> Data {
        let input = InputStream(data: plaintext)
        let output = OutputStream.toMemory()
        try Age.encryptStream(plaintext: input, to: recipients, into: output)
        output.close()
        return output.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
    }

    private func streamDecrypt(_ ciphertext: Data, identities: [AgeIdentity]) throws -> Data {
        let input = InputStream(data: ciphertext)
        let output = OutputStream.toMemory()
        try Age.decryptStream(ciphertext: input, identities: identities, into: output)
        output.close()
        return output.property(forKey: .dataWrittenToMemoryStreamKey) as? Data ?? Data()
    }

    private func pattern(_ size: Int) -> Data {
        Data((0..<size).map { UInt8($0 % 256) })
    }

    private func newPair() throws -> (X25519Identity, X25519Recipient) {
        let id = X25519Identity.generate()
        let r = try X25519Recipient(ageRecipient: id.ageRecipient)
        return (id, r)
    }

    // MARK: - Streaming round-trip across every chunk boundary

    func testStreamRoundTrip_acrossSizes() throws {
        let (id, r) = try newPair()
        let sizes = [
            0,
            1,
            AgePayload.chunkSize - 1,
            AgePayload.chunkSize,
            AgePayload.chunkSize + 1,
            AgePayload.chunkSize * 2,
            AgePayload.chunkSize * 3 + 257,
        ]
        for size in sizes {
            let pt = pattern(size)
            let ct = try streamEncrypt(pt, to: [r])
            let back = try streamDecrypt(ct, identities: [id])
            XCTAssertEqual(back, pt, "stream round-trip failed at size \(size)")
        }
    }

    // MARK: - Cross-path equivalence (the interop guarantee)

    func testStreamEncrypt_decryptsWithBufferedAPI() throws {
        let (id, r) = try newPair()
        for size in [0, 5, AgePayload.chunkSize, AgePayload.chunkSize + 1, AgePayload.chunkSize * 3 + 9] {
            let pt = pattern(size)
            let ct = try streamEncrypt(pt, to: [r])
            let back = try Age.decrypt(ciphertext: ct, identities: [id])
            XCTAssertEqual(back, pt, "streamed ciphertext failed buffered decrypt at size \(size)")
        }
    }

    func testBufferedEncrypt_decryptsWithStreamingAPI() throws {
        let (id, r) = try newPair()
        for size in [0, 5, AgePayload.chunkSize, AgePayload.chunkSize + 1, AgePayload.chunkSize * 3 + 9] {
            let pt = pattern(size)
            let ct = try Age.encrypt(plaintext: pt, to: [r])
            let back = try streamDecrypt(ct, identities: [id])
            XCTAssertEqual(back, pt, "buffered ciphertext failed streaming decrypt at size \(size)")
        }
    }

    // MARK: - Output length matches the buffered path

    func testStreamedCiphertextLength_matchesBuffered() throws {
        let (_, r) = try newPair()
        // Ciphertext length is determined by plaintext size and recipient count, not by
        // the random file key or nonce, so the streamed and buffered lengths must agree.
        for size in [0, 1, AgePayload.chunkSize, AgePayload.chunkSize + 1, AgePayload.chunkSize * 2] {
            let pt = pattern(size)
            let streamed = try streamEncrypt(pt, to: [r])
            let buffered = try Age.encrypt(plaintext: pt, to: [r])
            XCTAssertEqual(streamed.count, buffered.count, "length mismatch at size \(size)")
        }
    }

    // MARK: - Multi-recipient and access control

    func testStream_multiRecipient_eachCanDecrypt() throws {
        let (idA, _) = try newPair()
        let (idB, _) = try newPair()
        let (idC, _) = try newPair()
        let recipients = try [idA, idB, idC].map { try X25519Recipient(ageRecipient: $0.ageRecipient) }
        let pt = pattern(AgePayload.chunkSize + 1234)
        let ct = try streamEncrypt(pt, to: recipients)
        XCTAssertEqual(try streamDecrypt(ct, identities: [idA]), pt)
        XCTAssertEqual(try streamDecrypt(ct, identities: [idB]), pt)
        XCTAssertEqual(try streamDecrypt(ct, identities: [idC]), pt)
    }

    func testStream_strangerCannotDecrypt() throws {
        let (_, r) = try newPair()
        let (stranger, _) = try newPair()
        let ct = try streamEncrypt(pattern(100), to: [r])
        XCTAssertThrowsError(try streamDecrypt(ct, identities: [stranger])) { error in
            XCTAssertEqual(error as? AgeError, .noMatchingIdentity)
        }
    }

    func testStream_noRecipientsRejected() {
        let input = InputStream(data: Data())
        let output = OutputStream.toMemory()
        XCTAssertThrowsError(try Age.encryptStream(plaintext: input, to: [], into: output)) { error in
            XCTAssertEqual(error as? AgeError, .noRecipients)
        }
    }

    // MARK: - Tamper detection

    func testStream_payloadTamperRejected() throws {
        let (id, r) = try newPair()
        var ct = try streamEncrypt(pattern(50), to: [r])
        ct[ct.count - 1] ^= 0x01  // flip a tag bit of the final chunk
        XCTAssertThrowsError(try streamDecrypt(ct, identities: [id])) { error in
            switch error {
            case AgeError.payloadError, AgeError.noMatchingIdentity, AgeError.headerError:
                break
            default:
                XCTFail("expected an Age error rejection, got \(error)")
            }
        }
    }
}
