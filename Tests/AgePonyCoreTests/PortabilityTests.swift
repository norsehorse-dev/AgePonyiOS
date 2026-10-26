//
//  PortabilityTests.swift
//  AgePonyCoreTests
//
//  Key transfer (`agepony.com/transfer v1`), its two codes, the LAN wire format, and
//  paper backups. The transfer-code vector is the one Android's TransferHardeningTest
//  pins; the confirmation-code vector was computed independently in Python.
//

import XCTest
import Foundation
import CryptoKit
@testable import AgePonyCore

final class PortabilityTests: XCTestCase {

    let codePattern = "^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$"

    // MARK: - Codes

    func test_transferCode_matchesAndroidPinnedVector() {
        let sealed = Data("age-encryption.org/v1\n-> X25519 abc\n".utf8)
        XCTAssertEqual(sealed.count, 36)
        XCTAssertEqual(TransferCode.of(sealed: sealed), "QNED-DFQW-8WY0")
        XCTAssertNotEqual(KeyTransfer.code60(Data(SHA256.hash(data: sealed))), "QNED-DFQW-8WY0")
    }

    func test_confirmationCode_vectorAndNormalisation() {
        let r = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        XCTAssertEqual(KeyTransfer.confirmationCode(recipient: r), "SXZ5-D0HH-6586")
        XCTAssertEqual(KeyTransfer.confirmationCode(recipient: " \(r.uppercased()) "), "SXZ5-D0HH-6586")
        XCTAssertNotNil(KeyTransfer.confirmationCode(recipient: r).range(of: codePattern, options: .regularExpression))
    }

    func test_transferCode_changesWithAnyByte() {
        var a = Data((0..<5000).map { _ in UInt8.random(in: 0...255) })
        let before = TransferCode.of(sealed: a)
        a[4321] &+= 1
        XCTAssertNotEqual(TransferCode.of(sealed: a), before)
    }

    func test_armoredAndBinaryTransfers_giveTheSameCode() throws {
        let receiver = try HybridIdentity.generate()
        let sealed = try KeyTransfer.seal(KeyTransfer.Bundle(identitiesTxt: "AGE-SECRET-KEY-1TEST\n", metadataJSON: "{}"), to: try receiver.recipient())
        let armored = AgeArmor.encode(sealed)
        XCTAssertEqual(TransferCode.of(sealed: Data(armored.utf8)), TransferCode.of(sealed: sealed))
        let crlf = armored.replacingOccurrences(of: "\n", with: "\r\n").trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(TransferCode.of(sealed: Data(crlf.utf8)), TransferCode.of(sealed: sealed))
    }

    // MARK: - Bundle

    func test_transfer_roundTrip_andPlainAgeShape() throws {
        let x = X25519Identity.generate()
        let pq = try HybridIdentity.generate()
        let ids = KeyTransfer.identityFile([
            .init(name: "laptop", publicKey: x.ageRecipient, secretKey: x.ageIdentityString, createdISO: "2026-10-01T00:00:00Z"),
            .init(name: "pq key", publicKey: try pq.recipient().ageRecipient, secretKey: pq.ageIdentityString, createdISO: nil),
        ])
        let bundle = KeyTransfer.Bundle(identitiesTxt: ids, sshKeys: ["work key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n", "work_key": "y"],
                                        metadataJSON: "{\"v\":1}")
        let receiver = try HybridIdentity.generate()
        let sealed = try KeyTransfer.seal(bundle, to: try KeyTransfer.parseRecipient(try receiver.recipient().ageRecipient.uppercased()))
        let back = try KeyTransfer.open(sealed, with: receiver)
        XCTAssertEqual(back.identitiesTxt, ids)
        XCTAssertEqual(back.metadataJSON, "{\"v\":1}")
        XCTAssertEqual(Set(back.sshKeys.keys), ["work_key", "work_key-2"])

        // Armored (the paste route) opens too; a different session refuses.
        XCTAssertEqual(try KeyTransfer.open(Data(AgeArmor.encode(sealed).utf8), with: receiver), back)
        XCTAssertThrowsError(try KeyTransfer.open(sealed, with: try HybridIdentity.generate())) {
            XCTAssertEqual($0 as? KeyTransferError, .wrongSession)
        }

        // The tar is plain: FORMAT first, identities.txt a working age identity file.
        let tar = try Age.decrypt(ciphertext: sealed, identities: [receiver])
        let entries = try TarArchive.extract(tar)
        XCTAssertEqual(entries.first?.name, "FORMAT")
        XCTAssertEqual(PaperBackup.secretKeys(identityFile: ids), [x.ageIdentityString.uppercased(), pq.ageIdentityString.uppercased()])
        XCTAssertEqual(PaperBackup.namesByKey(identityFile: ids)[pq.ageIdentityString.uppercased()], "pq key")
    }

    func test_unpack_rejectsWrongFormatAndJunk() throws {
        let other = try TarArchive.create([TarArchive.Entry(name: "FORMAT", data: Data("agepony.com/transfer v9\n".utf8))])
        XCTAssertThrowsError(try KeyTransfer.unpack(other)) {
            XCTAssertEqual($0 as? KeyTransferError, .unsupportedFormat("agepony.com/transfer v9"))
        }
        XCTAssertThrowsError(try KeyTransfer.unpack(Data("not a tar".utf8)))
        XCTAssertThrowsError(try KeyTransfer.unpack(try TarArchive.create([TarArchive.Entry(name: "x", data: Data())])))
        XCTAssertThrowsError(try KeyTransfer.parseRecipient("ssh-ed25519 AAAA"))
    }

    // MARK: - LAN wire format

    func test_invite_roundTrip_isUppercaseAndParses() throws {
        let receiver = try HybridIdentity.generate()
        let invite = try LanTransfer.Invite(recipient: try receiver.recipient().ageRecipient, token: LanTransfer.newToken(),
                                            port: 49152, hosts: ["192.168.1.20", "172.20.10.1"])
        let s = invite.encode()
        XCTAssertEqual(s, s.uppercased())
        XCTAssertTrue(LanTransfer.Invite.isInvite(s))
        XCTAssertEqual(try LanTransfer.Invite.decode(s), invite)
        XCTAssertEqual((try KeyTransfer.parseRecipient(try LanTransfer.Invite.decode(s).recipient) as? HybridRecipient)?.ageRecipient,
                       try receiver.recipient().ageRecipient)
        XCTAssertThrowsError(try LanTransfer.Invite.decode("AGEPONY:XFER1/X/ZZ/1/H"))
        XCTAssertThrowsError(try LanTransfer.Invite.decode("hello"))
    }

    func test_lan_senderToReceiver_inRandomPieces() throws {
        let token = LanTransfer.newToken()
        let sealed = Data((0..<200_000).map { _ in UInt8.random(in: 0...255) })
        let wire = try LanTransfer.senderStream(sealed: sealed, deviceName: "iPhone", token: token)
        var parser = LanTransfer.ReceiveParser(token: token)
        var offset = 0
        var sawReceiving = false
        while offset < wire.count {
            let n = min(Int.random(in: 1...9000), wire.count - offset)
            let state = try parser.feed(wire.subdata(in: offset..<(offset + n)))
            if state == .receiving { sawReceiving = true }
            offset += n
        }
        XCTAssertTrue(sawReceiving)
        XCTAssertEqual(parser.state, .complete(sealed))
        XCTAssertEqual(TransferCode.of(sealed: sealed), TransferCode.of(sealed: { if case .complete(let d) = parser.state { return d }; return Data() }()))

        var ack = LanTransfer.SenderAckParser()
        let frame = LanTransfer.ackFrame(accepted: true)
        XCTAssertNil(try ack.feed(frame.prefix(3)))
        XCTAssertEqual(try ack.feed(frame.dropFirst(3)), true)
        var nack = LanTransfer.SenderAckParser()
        XCTAssertEqual(try nack.feed(LanTransfer.ackFrame(accepted: false)), false)
    }

    func test_lan_refusesWrongToken_oversize_andTampering() throws {
        let token = LanTransfer.newToken()
        let sealed = Data(repeating: 7, count: 1000)

        var wrong = LanTransfer.ReceiveParser(token: LanTransfer.newToken())
        XCTAssertThrowsError(try wrong.feed(try LanTransfer.senderStream(sealed: sealed, deviceName: "A", token: token))) {
            XCTAssertEqual($0 as? LanTransferError, .wrongToken)
        }

        var small = LanTransfer.ReceiveParser(token: token, maxBytes: 999)
        XCTAssertThrowsError(try small.feed(try LanTransfer.senderStream(sealed: sealed, deviceName: "A", token: token))) {
            XCTAssertEqual($0 as? LanTransferError, .tooLarge)
        }

        var wire = try LanTransfer.senderStream(sealed: sealed, deviceName: "A", token: token)
        let chunkStart = wire.count - (5 + 32) - 5 - 1000 // last byte region of the chunk payload
        wire[chunkStart + 10] ^= 1
        var tampered = LanTransfer.ReceiveParser(token: token)
        XCTAssertThrowsError(try tampered.feed(wire)) {
            XCTAssertEqual($0 as? LanTransferError, .protocolError("checksum mismatch"))
        }

        // A HELLO claiming a huge length is refused before it is buffered.
        var huge = LanTransfer.ReceiveParser(token: token)
        XCTAssertThrowsError(try huge.feed(Data([0x01, 0x7F, 0xFF, 0xFF, 0xFF])))
        XCTAssertThrowsError(try LanTransfer.senderStream(sealed: Data(count: LanTransfer.maxBytes + 1), deviceName: "A", token: token))
    }

    // MARK: - Paper backup

    func test_paper_sealOpen_andWrongPassphrase() throws {
        let x = X25519Identity.generate()
        let file = KeyTransfer.identityFile([.init(name: "safe", publicKey: x.ageRecipient, secretKey: x.ageIdentityString, createdISO: nil)],
                                            includePublicKey: false)
        XCTAssertFalse(file.contains("# public key:"))
        let page = try PaperBackup.seal(identityFile: file, passphrase: "correct horse", workFactor: 10)
        XCTAssertTrue(PaperBackup.isSealed(page))
        XCTAssertEqual(try PaperBackup.open(armored: "scanned junk before\n" + page, passphrase: "correct horse"), file)
        XCTAssertThrowsError(try PaperBackup.open(armored: page, passphrase: "wrong")) {
            XCTAssertEqual($0 as? PaperBackupError, .wrongPassphrase)
        }
        XCTAssertThrowsError(try PaperBackup.open(armored: x.ageIdentityString, passphrase: "x")) {
            XCTAssertEqual($0 as? PaperBackupError, .notSealed)
        }
        XCTAssertThrowsError(try PaperBackup.seal(identityFile: file, passphrase: ""))
        XCTAssertEqual(PaperBackup.secretKeys(identityFile: "  \(x.ageIdentityString.lowercased())  "), [x.ageIdentityString.uppercased()])
    }

    func test_paper_transcriptionGroups() {
        XCTAssertEqual(PaperBackup.transcriptionGroups("ABCDEFGHIJ", perLine: 2), ["ABCD EFGH", "IJ"])
        XCTAssertEqual(PaperBackup.transcriptionGroups(""), [])
    }
}
