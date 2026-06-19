//
//  AuthenticatorData.swift
//  AgePonyCore — FIDO support
//
//  authenticatorData is the fixed-layout blob a FIDO authenticator signs over
//  (alongside the client-data hash). Layout (WebAuthn §6.1):
//
//    rpIdHash    32 bytes   SHA-256 of the RP id ("ssh:" for SSH keys)
//    flags        1 byte    bit0 UP, bit2 UV, bit6 AT, bit7 ED
//    signCount    4 bytes   big-endian counter
//    [attested credential data]   present iff AT (0x40) is set:
//        aaguid              16 bytes
//        credentialIdLength   2 bytes  big-endian
//        credentialId         L bytes
//        credentialPublicKey  COSE_Key (CBOR)
//    [extensions]                 present iff ED (0x80) is set: CBOR map
//
//  For SSHSIG signing we only need flags + signCount (they get folded into the
//  signed message — see SSHSig.skAuthenticatorMessage). Enrolment (a
//  makeCredential response) carries the attested credential data, from which we
//  pull the credentialId and public key.
//

import Foundation

public enum AuthenticatorDataError: Error, Equatable {
    case tooShort
    case truncatedAttestedData
}

public struct AttestedCredentialData: Equatable {
    public let aaguid: Data
    public let credentialId: Data
    public let credentialPublicKey: COSEPublicKey
}

public struct AuthenticatorData: Equatable {
    public let rpIdHash: Data
    public let flags: UInt8
    public let signCount: UInt32
    public let attestedCredentialData: AttestedCredentialData?
    /// The full authenticatorData bytes exactly as received.
    public let raw: Data

    public var userPresent: Bool { flags & 0x01 != 0 }
    public var userVerified: Bool { flags & 0x04 != 0 }
    public var hasAttestedCredentialData: Bool { flags & 0x40 != 0 }
    public var hasExtensions: Bool { flags & 0x80 != 0 }

    public init(_ data: Data) throws {
        guard data.count >= 37 else { throw AuthenticatorDataError.tooShort }

        // Index into a zero-based view so slicing is predictable regardless of
        // the incoming Data's startIndex.
        let bytes = Data(data)
        self.raw = bytes
        self.rpIdHash = bytes.prefix(32)
        let flagsByte = bytes[32]
        self.flags = flagsByte
        self.signCount =
            (UInt32(bytes[33]) << 24) |
            (UInt32(bytes[34]) << 16) |
            (UInt32(bytes[35]) << 8) |
            UInt32(bytes[36])

        guard flagsByte & 0x40 != 0 else {
            self.attestedCredentialData = nil
            return
        }

        // Attested credential data begins at offset 37.
        guard bytes.count >= 37 + 16 + 2 else {
            throw AuthenticatorDataError.truncatedAttestedData
        }
        let aaguid = bytes[37 ..< 53]
        let credLen = (Int(bytes[53]) << 8) | Int(bytes[54])
        let credStart = 55
        guard bytes.count >= credStart + credLen else {
            throw AuthenticatorDataError.truncatedAttestedData
        }
        let credId = bytes[credStart ..< credStart + credLen]

        // The COSE public key is the next CBOR item; decode from credId end and
        // let the reader find its extent (extensions, if any, follow it).
        let coseStart = credStart + credLen
        var reader = CBORReader(Data(bytes[coseStart...]))
        let coseCBOR = try reader.decode()
        let publicKey = try COSEKey.decode(coseCBOR)

        self.attestedCredentialData = AttestedCredentialData(
            aaguid: Data(aaguid),
            credentialId: Data(credId),
            credentialPublicKey: publicKey
        )
    }
}
