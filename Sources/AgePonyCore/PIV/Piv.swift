//
//  Piv.swift
//  AgePonyCore
//
//  The slice of the PIV card interface (NIST SP 800-73-4, plus YubiKey's GET SERIAL)
//  that decrypting with an age-plugin-yubikey key needs: select the applet, read a
//  slot's certificate for its public key, verify the PIN, and have the card do a P-256
//  ECDH.
//
//  Transport-free: this builds APDUs and parses responses, and `PivCard` is whatever
//  carries them (CoreNFC `NFCISO7816Tag` in the app). Response chaining (SW 61xx) is
//  handled in `transceive`, with caps so a broken or hostile card can't hang or exhaust
//  the app (audit L-11).
//
//  Mirrors Android agepony-core `piv/Piv.kt`.
//

import Foundation

/// Carries one APDU to the card and returns response data followed by SW1 SW2.
public protocol PivCard {
    func transmit(_ apdu: Data) throws -> Data
}

public enum PivError: Error, Equatable {
    case notPIV(sw: UInt16)
    /// Wrong PIN; `retriesLeft` is 0 when the PIN is now blocked.
    case wrongPIN(retriesLeft: Int)
    case pinRequired
    case pinLength
    case noKeyInSlot(slot: UInt8, sw: UInt16)
    case notP256(slot: UInt8)
    case refused(sw: UInt16)
    case malformedResponse(String)
}

public enum Piv {
    public static let swOK: UInt16 = 0x9000
    public static let swSecurityStatus: UInt16 = 0x6982
    public static let swAuthBlocked: UInt16 = 0x6983
    static let algECCP256: UInt8 = 0x11

    /// Caps on 61xx GET RESPONSE chaining (audit L-11).
    public static let maxResponseBytes = 64 * 1024
    public static let maxChainedResponses = 256

    /// PIV applet AID. Must also be listed under
    /// `com.apple.developer.nfc.readersession.iso7816.select-identifiers` in Info.plist.
    public static let aid = Data([0xA0, 0x00, 0x00, 0x03, 0x08])

    public static func select(_ card: PivCard) throws {
        let (_, sw) = try transceive(card, apdu(ins: 0xA4, p1: 0x04, p2: 0x00, data: aid, le: true))
        guard sw == swOK else { throw PivError.notPIV(sw: sw) }
    }

    /// YubiKey serial number (YubiKey 5 firmware); nil when the key doesn't answer.
    public static func serial(_ card: PivCard) throws -> UInt32? {
        let (data, sw) = try transceive(card, apdu(ins: 0xF8, p1: 0x00, p2: 0x00, data: Data(), le: true))
        guard sw == swOK, data.count == 4 else { return nil }
        return data.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    /// Verify `pin` (6 to 8 characters on a YubiKey). Throws `.wrongPIN` with the tries left.
    public static func verifyPIN(_ card: PivCard, pin: String) throws {
        let bytes = Array(pin.utf8)
        guard (1...8).contains(bytes.count) else { throw PivError.pinLength }
        var padded = [UInt8](repeating: 0xFF, count: 8)
        padded.replaceSubrange(0..<bytes.count, with: bytes)
        defer { for i in padded.indices { padded[i] = 0 } }
        let (_, sw) = try transceive(card, apdu(ins: 0x20, p1: 0x00, p2: 0x80, data: Data(padded), le: false))
        if sw == swOK { return }
        if sw & 0xFFF0 == 0x63C0 { throw PivError.wrongPIN(retriesLeft: Int(sw & 0x0F)) }
        if sw == swAuthBlocked { throw PivError.wrongPIN(retriesLeft: 0) }
        throw PivError.refused(sw: sw)
    }

    /// The public key in `slot`'s certificate, as a 33-byte compressed point.
    public static func readPublicKey(_ card: PivCard, slot: UInt8) throws -> Data {
        let data = Data([0x5C, 0x03]) + (try certObjectID(slot: slot))
        let (resp, sw) = try transceive(card, apdu(ins: 0xCB, p1: 0x3F, p2: 0xFF, data: data, le: true))
        guard sw == swOK else { throw PivError.noKeyInSlot(slot: slot, sw: sw) }
        guard let outer = try Tlv.find(resp, tag: 0x53) else { throw PivError.malformedResponse("unexpected certificate object layout") }
        guard let der = try Tlv.find(outer, tag: 0x70) else { throw PivError.noKeyInSlot(slot: slot, sw: sw) }
        guard let point = try X509P256.publicKey(fromCertificate: der) else { throw PivError.notP256(slot: slot) }
        do {
            return try P256Curve.compressed(point)
        } catch {
            throw PivError.notP256(slot: slot)
        }
    }

    /// P-256 ECDH on the card with the key in `slot`. `peerUncompressed` is 65 bytes.
    /// Returns the 32-byte shared x-coordinate. Throws `.pinRequired` when the slot's
    /// PIN policy wants the PIN first.
    public static func ecdh(_ card: PivCard, slot: UInt8, peerUncompressed: Data) throws -> Data {
        guard peerUncompressed.count == 65, peerUncompressed.first == 0x04 else {
            throw PivError.malformedResponse("peer point must be uncompressed")
        }
        let inner = Tlv.encode(tag: 0x82, value: Data()) + Tlv.encode(tag: 0x85, value: peerUncompressed)
        let (resp, sw) = try transceive(card, apdu(ins: 0x87, p1: algECCP256, p2: slot, data: Tlv.encode(tag: 0x7C, value: inner), le: true))
        switch sw {
        case swOK: break
        case swSecurityStatus: throw PivError.pinRequired
        default: throw PivError.refused(sw: sw)
        }
        guard let template = try Tlv.find(resp, tag: 0x7C),
              let secret = try Tlv.find(template, tag: 0x82) else {
            throw PivError.malformedResponse("ECDH response had no shared secret")
        }
        guard secret.count == 32 else { throw PivError.malformedResponse("unexpected shared secret size \(secret.count)") }
        return secret
    }

    /// Object id of a retired key-management slot's certificate: 82 -> 5FC10D ... 95 -> 5FC120.
    public static func certObjectID(slot: UInt8) throws -> Data {
        guard (0x82...0x95).contains(slot) else { throw PivError.malformedResponse("not a retired slot") }
        return Data([0x5F, 0xC1, 0x0D + (slot - 0x82)])
    }

    /// Send `command`, following 61xx GET RESPONSE chaining. Returns (data, SW).
    public static func transceive(_ card: PivCard, _ command: Data) throws -> (Data, UInt16) {
        var (acc, sw) = try split(card.transmit(command))
        var rounds = 0
        while sw >> 8 == 0x61 {
            rounds += 1
            guard rounds <= maxChainedResponses else { throw PivError.malformedResponse("the card kept chaining its response") }
            let (more, next) = try split(card.transmit(Data([0x00, 0xC0, 0x00, 0x00, UInt8(sw & 0xFF)])))
            acc.append(more)
            sw = next
            guard acc.count <= maxResponseBytes else { throw PivError.malformedResponse("the card's response is too large") }
        }
        guard acc.count <= maxResponseBytes else { throw PivError.malformedResponse("the card's response is too large") }
        return (acc, sw)
    }

    /// Short APDU (CLA 00). PIV commands here stay under 256 bytes of data.
    static func apdu(ins: UInt8, p1: UInt8, p2: UInt8, data: Data, le: Bool) -> Data {
        precondition(data.count <= 255)
        var out = Data([0x00, ins, p1, p2])
        if !data.isEmpty { out.append(UInt8(data.count)); out.append(data) }
        if le { out.append(0x00) }
        return out
    }

    static func split(_ r: Data) throws -> (Data, UInt16) {
        guard r.count >= 2 else { throw PivError.malformedResponse("short response from the card") }
        let b = Array(r)
        return (Data(b[0..<(b.count - 2)]), UInt16(b[b.count - 2]) << 8 | UInt16(b[b.count - 1]))
    }
}

/// BER-TLV with single-byte tags and short/long lengths, as PIV uses.
public enum Tlv {
    public static func encode(tag: UInt8, value: Data) -> Data {
        var out = Data([tag])
        switch value.count {
        case ..<0x80: out.append(UInt8(value.count))
        case ...0xFF: out.append(contentsOf: [0x81, UInt8(value.count)])
        default: out.append(contentsOf: [0x82, UInt8(value.count >> 8), UInt8(value.count & 0xFF)])
        }
        out.append(value)
        return out
    }

    /// Value of the first top-level `tag` in `data`, or nil. Malformed lengths throw
    /// instead of reading out of bounds (audit L-11).
    public static func find(_ data: Data, tag: UInt8) throws -> Data? {
        let b = Array(data)
        var i = 0
        while i < b.count {
            let t = b[i]; i += 1
            guard i < b.count else { throw PivError.malformedResponse("TLV with no length") }
            var len = Int(b[i]); i += 1
            if len == 0x81 {
                guard i + 1 <= b.count else { throw PivError.malformedResponse("truncated TLV length") }
                len = Int(b[i]); i += 1
            } else if len == 0x82 {
                guard i + 2 <= b.count else { throw PivError.malformedResponse("truncated TLV length") }
                len = Int(b[i]) << 8 | Int(b[i + 1]); i += 2
            } else if len >= 0x80 {
                throw PivError.malformedResponse("unsupported TLV length form")
            }
            guard len <= b.count - i else { throw PivError.malformedResponse("TLV runs past the end") }
            if t == tag { return Data(b[i..<(i + len)]) }
            i += len
        }
        return nil
    }
}

/// Just enough X.509 to pull a named-curve P-256 public key out of a certificate.
///
/// Walks Certificate -> tbsCertificate -> subjectPublicKeyInfo and accepts only
/// id-ecPublicKey with the prime256v1 curve OID. Explicit curve parameters are refused,
/// so another 256-bit curve can't be misread as P-256.
enum X509P256 {
    static let oidECPublicKey: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]       // 1.2.840.10045.2.1
    static let oidPrime256v1: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] // 1.2.840.10045.3.1.7

    struct Element { let tag: UInt8; let value: ArraySlice<UInt8> }

    /// The 65-byte uncompressed point, or nil if this isn't a P-256 certificate.
    static func publicKey(fromCertificate der: Data) throws -> Data? {
        let bytes = Array(der)
        guard let cert = try read(bytes[...]).first, cert.tag == 0x30,
              let tbs = try read(cert.value).first, tbs.tag == 0x30 else { return nil }
        var fields = try read(tbs.value)
        if fields.first?.tag == 0xA0 { fields.removeFirst() } // [0] version
        // serial, signature, issuer, validity, subject, subjectPublicKeyInfo
        guard fields.count >= 6 else { return nil }
        let spki = fields[5]
        guard spki.tag == 0x30 else { return nil }
        let parts = try read(spki.value)
        guard parts.count == 2, parts[0].tag == 0x30, parts[1].tag == 0x03 else { return nil }
        let alg = try read(parts[0].value)
        guard alg.count == 2, alg[0].tag == 0x06, Array(alg[0].value) == oidECPublicKey,
              alg[1].tag == 0x06, Array(alg[1].value) == oidPrime256v1 else { return nil }
        let bits = Array(parts[1].value)
        guard bits.count == 66, bits[0] == 0x00, bits[1] == 0x04 else { return nil }
        return Data(bits[1...])
    }

    /// Read consecutive DER elements from `s`.
    static func read(_ s: ArraySlice<UInt8>) throws -> [Element] {
        var out: [Element] = []
        var i = s.startIndex
        while i < s.endIndex {
            let tag = s[i]; i += 1
            guard i < s.endIndex else { throw PivError.malformedResponse("truncated certificate") }
            var len = Int(s[i]); i += 1
            if len & 0x80 != 0 {
                let n = len & 0x7F
                guard n >= 1, n <= 3, i + n <= s.endIndex else { throw PivError.malformedResponse("bad certificate length") }
                len = 0
                for _ in 0..<n { len = len << 8 | Int(s[i]); i += 1 }
            }
            guard len <= s.endIndex - i else { throw PivError.malformedResponse("certificate runs past the end") }
            out.append(Element(tag: tag, value: s[i..<(i + len)]))
            i += len
        }
        return out
    }
}
