//
//  SSHSigRSATests.swift
//  AgePonyCoreTests
//
//  D0: rsa-sha2-512 SSHSIG signing and verification.
//
//  Two kinds of coverage:
//    1. Interop — a signature produced by the real `ssh-keygen -Y sign` (an
//       ssh-rsa key, namespace "agepony") verifies through SSHSigVerifier.
//       This is the byte-for-byte contract with OpenSSH, the RSA analogue of
//       the Ed25519 golden vector in SSHSigTests.
//    2. Round trip — sign with SSHSigner.signRSA, verify with SSHSigVerifier,
//       confirm the inner algorithm is rsa-sha2-512, and that tampering fails.
//
//  RSA signing/verification go through SecKey, so these run on Apple platforms
//  (macOS via `swift test`, iOS via the app). The wire format and the
//  PKCS1-v1.5-SHA512-over-signed-data contract were cross-checked against
//  ssh-keygen and openssl during development.
//

import XCTest
import Security
@testable import AgePonyCore

final class SSHSigRSATests: XCTestCase {

    // Message that was signed by ssh-keygen to produce `goldenSignature`.
    private let goldenMessage = "sign me with rsa for agepony"

    // The signer's ssh-rsa public-key wire blob (base64), from id_rsa.pub.
    private let goldenPubWireB64 =
        "AAAAB3NzaC1yc2EAAAADAQABAAABAQC8PCknO1Jp9ly4oL77+9UvbRSRnwWi4oXk3kzAW1NaEMs16cyNQuvGlZQsFTkGnM6HdXfiqINP46WLe/NW5O+X7lRbVxza2GH+t+4z3XWJ/iGWIw9h4dBTIQh/3EbzUfpjzuNJEQsp/pG/LUpTDYylRIZKdSl4HQ95DjahJyw+8kXKuAmhQWJCmNuSZu9347gO/F3acWqcfyMHvcSrmpQ5TdYttczzXV3H/Ci1bqWU5d+i7YFZPTS1I1ZipWvh8iqZJfwPdgKKMKHCq0KDURe8VNGnimp7fTrQrvVZUUN6QtlWGwHeCmxlgpdiVOZXOcx1hwTCua899qCsvIcSOOPF"

    // Detached signature produced by: ssh-keygen -Y sign -f id_rsa -n agepony msg.txt
    private let goldenSignature = """
    -----BEGIN SSH SIGNATURE-----
    U1NIU0lHAAAAAQAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBALw8KSc7Umn2XLigvvv71S
    9tFJGfBaLiheTeTMBbU1oQyzXpzI1C68aVlCwVOQaczod1d+Kog0/jpYt781bk75fuVFtX
    HNrYYf637jPddYn+IZYjD2Hh0FMhCH/cRvNR+mPO40kRCyn+kb8tSlMNjKVEhkp1KXgdD3
    kONqEnLD7yRcq4CaFBYkKY25Jm73fjuA78Xdpxapx/Iwe9xKualDlN1i21zPNdXcf8KLVu
    pZTl36LtgVk9NLUjVmKla+HyKpkl/A92AoowocKrQoNRF7xU0aeKant9OtCu9VlRQ3pC2V
    YbAd4KbGWCl2JU5lc5zHWHBMK5rz32oKy8hxI448UAAAAHYWdlcG9ueQAAAAAAAAAGc2hh
    NTEyAAABFAAAAAxyc2Etc2hhMi01MTIAAAEACJPDQZRJRr9lzpHdTD/5TSb1F64kwO/K1j
    FtZc4LZJoePov7pFjhksmaa3jWfXfObrSV2MDn1HRnyP/yYCd8moaAqMXF6iZ5jI+5ZLEK
    8+rEzfHQ7MPrfMv0yg6RbOsUBSXhH3Y9KRIU9SwnlvuOzCFSYoqME72u8l+Xj3KmTUP3HF
    GsjX3+41oqnG/fFk56EoPRrwIyo+qlurlg1RFno/STa1mD4lafjGQvxWnWHl1NLLBia4o/
    8sGY4kc1psY2E71mlHRi9mW97nzopOgER75fAKikzVVFxlH8zFs9GjHazpgVecv6eqfQ48
    DcPVOIx3rDn3UhDXQwRYqhBRLvUg==
    -----END SSH SIGNATURE-----
    """

    // The matching unencrypted OpenSSH private key, for the round-trip test.
    private let goldenPrivatePEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
    NhAAAAAwEAAQAAAQEAvDwpJztSafZcuKC++/vVL20UkZ8FouKF5N5MwFtTWhDLNenMjULr
    xpWULBU5BpzOh3V34qiDT+Oli3vzVuTvl+5UW1cc2thh/rfuM911if4hliMPYeHQUyEIf9
    xG81H6Y87jSRELKf6Rvy1KUw2MpUSGSnUpeB0PeQ42oScsPvJFyrgJoUFiQpjbkmbvd+O4
    Dvxd2nFqnH8jB73Eq5qUOU3WLbXM811dx/wotW6llOXfou2BWT00tSNWYqVr4fIqmSX8D3
    YCijChwqtCg1EXvFTRp4pqe3060K71WVFDekLZVhsB3gpsZYKXYlTmVznMdYcEwrmvPfag
    rLyHEjjjxQAAA8Bv9Q60b/UOtAAAAAdzc2gtcnNhAAABAQC8PCknO1Jp9ly4oL77+9UvbR
    SRnwWi4oXk3kzAW1NaEMs16cyNQuvGlZQsFTkGnM6HdXfiqINP46WLe/NW5O+X7lRbVxza
    2GH+t+4z3XWJ/iGWIw9h4dBTIQh/3EbzUfpjzuNJEQsp/pG/LUpTDYylRIZKdSl4HQ95Dj
    ahJyw+8kXKuAmhQWJCmNuSZu9347gO/F3acWqcfyMHvcSrmpQ5TdYttczzXV3H/Ci1bqWU
    5d+i7YFZPTS1I1ZipWvh8iqZJfwPdgKKMKHCq0KDURe8VNGnimp7fTrQrvVZUUN6QtlWGw
    HeCmxlgpdiVOZXOcx1hwTCua899qCsvIcSOOPFAAAAAwEAAQAAAQAJ2gQ1X29yyEgWCaO1
    QHrp3oWjEXWUDtL/JXtS3fTA0/wuuCvSgNwiKpX0sK+pXu+YO1eo7zTgK4Pwhu43cAfyJb
    EYjrid45FNaYb4A/Ew5bIQT4lwkAb9Ms9lEbxM4899BcjzfAbfjclG/jHTovPnemyk3Pjs
    pmi25z2ItaolKSXVdC9NyCkHM09pAqcciJ5lgDoRNnMlTgFAe8qPATMaYAUMGiwfKulNdD
    vD3U5BSDnznm2bHsvvQpMUqRnIt+pFxna2V0HOQWWc1yuZhtIoG+3SO2GaRagZnCgim99B
    DF9SXGCcbJYTaaFdF15goc9t0+jo+TI4y2TOf/TorxZJAAAAgGzbb88eZtKyOBTLqBvalC
    yppM9Z9r37Dpx08GF41+GXpAjkkjyA+VX1Fb6VkjvA7kowIzfMyiqSeoy+AL3ipX2ZHBhV
    nPwmaMKO7+wubBxmgmxIJmOXB7VPf4hMoDnoiMFzopFa8BDb1s0cMFhkE5Pcs2gntXxiPo
    imfZWqIC7BAAAAgQDxMgShI9CZZBXWU6VA78iPMUICZMds5/Hy7g1ZY7H/+VF1e4GSqm3v
    C7IJ6rlBUEoDK2m99+vK9CGXMlSNDe/wUXp/xn8k+smfDEvwjF7qaVMxs+PxE9c/mFszck
    NbG4ogaC9ykHaub6jwbefQU2RWu/h8AkWs6U/fHRLgiexfCwAAAIEAx8n1eo3mf8YnxS8U
    EgHIPqaZsvlujetlvSAHqjbCp/xIQCVZrZJMsSJGvs2dM2mXlusFr9v9JTv33pe/TEHlC7
    sAYmar66DHAHSidZaifWnWo9Ifsdrw4z369cqxOHW8uZ76ahMfbCjsQMyqU6n1ZjpHIKTU
    f5HhmUQTFH9Xym8AAAALcnNhLWQwLXRlc3Q=
    -----END OPENSSH PRIVATE KEY-----
    """

    // MARK: - Interop with ssh-keygen

    func testGoldenRSAVectorVerifies() throws {
        let result = try SSHSigVerifier.verify(
            message: Data(goldenMessage.utf8),
            armoredSignature: goldenSignature,
            expectedNamespace: "agepony"
        )
        XCTAssertEqual(result.keyType, "ssh-rsa")
        XCTAssertEqual(result.namespace, "agepony")
        XCTAssertEqual(result.hash, .sha512)
        XCTAssertEqual(result.publicKeyWire, Data(base64Encoded: goldenPubWireB64))
    }

    func testGoldenRSAVectorWrongMessageFails() throws {
        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                message: Data("not the signed message".utf8),
                armoredSignature: goldenSignature,
                expectedNamespace: "agepony"
            )
        )
    }

    func testGoldenRSAVectorWrongNamespaceRejected() throws {
        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                message: Data(goldenMessage.utf8),
                armoredSignature: goldenSignature,
                expectedNamespace: "git"
            )
        ) { error in
            guard case SSHSigError.namespaceMismatch = error else {
                return XCTFail("expected namespaceMismatch, got \(error)")
            }
        }
    }

    // MARK: - Sign / verify round trip

    func testRSASignVerifyRoundTrip() throws {
        let identity = try SSHRSAIdentity(openSSHPrivateKey: goldenPrivatePEM)
        let message = Data("round trip rsa over agepony".utf8)

        let armored = try SSHSigner.signRSA(
            message: message,
            privateSecKey: identity.privateSecKey,
            publicKeyWire: identity.wireBlob
        )

        let result = try SSHSigVerifier.verify(
            message: message,
            armoredSignature: armored,
            expectedNamespace: SSHSig.defaultNamespace
        )
        XCTAssertEqual(result.keyType, "ssh-rsa")
        XCTAssertEqual(result.publicKeyWire, identity.wireBlob)
        XCTAssertEqual(result.namespace, "agepony")
    }

    func testRSASignedInnerAlgorithmIsRSASHA512() throws {
        let identity = try SSHRSAIdentity(openSSHPrivateKey: goldenPrivatePEM)
        let armored = try SSHSigner.signRSA(
            message: Data("inner algo check".utf8),
            privateSecKey: identity.privateSecKey,
            publicKeyWire: identity.wireBlob
        )
        let blob = try SSHSig.parseArmored(armored)
        let (innerType, raw) = try SSHSig.parseInnerSignature(blob.signature)
        XCTAssertEqual(innerType, "rsa-sha2-512")
        // 2048-bit key → 256-byte signature.
        XCTAssertEqual(raw.count, 256)
    }

    func testRSARoundTripTamperedMessageFails() throws {
        let identity = try SSHRSAIdentity(openSSHPrivateKey: goldenPrivatePEM)
        let armored = try SSHSigner.signRSA(
            message: Data("original".utf8),
            privateSecKey: identity.privateSecKey,
            publicKeyWire: identity.wireBlob
        )
        XCTAssertThrowsError(
            try SSHSigVerifier.verify(
                message: Data("tampered".utf8),
                armoredSignature: armored,
                expectedNamespace: SSHSig.defaultNamespace
            )
        )
    }

    func testRSAComponentsRoundTripThroughWire() throws {
        let wire = Data(base64Encoded: goldenPubWireB64)!
        let (e, n) = try SSHSig.rsaComponents(fromWire: wire)
        let rebuilt = SSHSig.rsaPublicKeyWire(e: e, n: n)
        XCTAssertEqual(rebuilt, wire)
    }
}
