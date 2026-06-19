//
//  COSEKey.swift
//  AgePonyCore — FIDO support
//
//  A FIDO authenticator returns its public key as a COSE_Key (RFC 8152): a CBOR
//  map keyed by integer label. We only need the two algorithms SSH security
//  keys use:
//
//    Ed25519 (OKP):  { 1: 1, 3: -8, -1: 6, -2: x(32) }
//    P-256   (EC2):  { 1: 2, 3: -7, -1: 1, -2: x(32), -3: y(32) }
//
//  where 1=kty, 3=alg, -1=crv, -2=x, -3=y.
//
//  We convert each into the raw form the rest of AgePony already speaks: the
//  32-byte Ed25519 public key, or the 65-byte uncompressed P-256 point
//  (0x04 || x || y) that feeds P256.Signing.PublicKey(x963Representation:) and
//  SSHSig.skEcdsaP256PublicKeyWire(x963Q:).
//

import Foundation

public enum COSEKeyError: Error, Equatable {
    case notAMap
    case missingField(Int)
    case unsupportedKeyType(Int?)
    case unsupportedCurve(Int?)
    case wrongCoordinateLength
}

public enum COSEPublicKey: Equatable {
    /// Raw 32-byte Ed25519 public key.
    case ed25519(rawPublicKey: Data)
    /// Uncompressed P-256 point, `0x04 || X || Y` (65 bytes).
    case p256(x963: Data)
}

public enum COSEKey {

    private static let kty = 1
    private static let alg = 3
    private static let crv = -1
    private static let xCoord = -2
    private static let yCoord = -3

    /// Decode a COSE_Key from its raw CBOR bytes.
    public static func decode(_ data: Data) throws -> COSEPublicKey {
        let cbor = try CBORReader.decode(data)
        return try decode(cbor)
    }

    /// Decode from an already-parsed CBOR map (used when the key is embedded,
    /// e.g. inside authenticatorData's attested credential data).
    public static func decode(_ cbor: CBOR) throws -> COSEPublicKey {
        guard case .map = cbor else { throw COSEKeyError.notAMap }
        let keyType = cbor.value(forIntKey: kty)?.intValue

        switch keyType {
        case 1:   // OKP
            guard let crvValue = cbor.value(forIntKey: crv)?.intValue, crvValue == 6 else {
                throw COSEKeyError.unsupportedCurve(cbor.value(forIntKey: crv)?.intValue)
            }
            guard let x = cbor.value(forIntKey: xCoord)?.bytesValue else {
                throw COSEKeyError.missingField(xCoord)
            }
            guard x.count == 32 else { throw COSEKeyError.wrongCoordinateLength }
            return .ed25519(rawPublicKey: x)

        case 2:   // EC2
            guard let crvValue = cbor.value(forIntKey: crv)?.intValue, crvValue == 1 else {
                throw COSEKeyError.unsupportedCurve(cbor.value(forIntKey: crv)?.intValue)
            }
            guard let x = cbor.value(forIntKey: xCoord)?.bytesValue else {
                throw COSEKeyError.missingField(xCoord)
            }
            guard let y = cbor.value(forIntKey: yCoord)?.bytesValue else {
                throw COSEKeyError.missingField(yCoord)
            }
            guard x.count == 32, y.count == 32 else { throw COSEKeyError.wrongCoordinateLength }
            var q = Data([0x04])
            q.append(x)
            q.append(y)
            return .p256(x963: q)

        default:
            throw COSEKeyError.unsupportedKeyType(keyType)
        }
    }

    /// Encode a P-256 public key (X9.63 `0x04 || X || Y`, 65 bytes) as a COSE_Key
    /// EC2 map — used to hand the platform's ephemeral key-agreement key to the
    /// authenticator inside a clientPin `getPinToken` request. The default
    /// algorithm is ECDH-ES + HKDF-256 (-25), which is what CTAP2's PIN/UV auth
    /// protocols use for key agreement.
    public static func encodeEC2(x963: Data, algorithm: Int = -25) throws -> CBOR {
        let q = Data(x963)
        guard q.count == 65, q.first == 0x04 else {
            throw COSEKeyError.wrongCoordinateLength
        }
        let x = q.subdata(in: 1 ..< 33)
        let y = q.subdata(in: 33 ..< 65)
        return .map([
            (.int(kty), .int(2)),
            (.int(alg), .int(algorithm)),
            (.int(crv), .int(1)),
            (.int(xCoord), .bytes(x)),
            (.int(yCoord), .bytes(y)),
        ])
    }
}
