#!/usr/bin/env python3
# piv-p256 (age-plugin-yubikey / age1yubikey1...) recipient reference.
#
# Structural mirror of the intended Swift P256Stanza.swift and of Android's
# agepony-core P256.kt, so the Swift transliteration is mechanical. Pins golden
# vectors the Swift KAT must reproduce byte-for-byte.
#
# Algorithm (from str4d/age-plugin-yubikey src/piv_p256.rs + recipient.rs, as
# implemented and on-device-verified in Android P256.kt):
#
#   recipient = compressed SEC1 P-256 point (33 bytes)
#   ephemeral (e, E), E = compressed 33-byte point
#   shared  = ECDH(e, recipientPub) x-coordinate (32 bytes, big-endian)
#   salt    = E || recipientPub                 (33 + 33 = 66)
#   wrapKey = HKDF-SHA256(ikm=shared, salt=salt, info="piv-p256", L=32)
#   body    = ChaCha20Poly1305(wrapKey, nonce=0*12, aad="", fileKey)  (fileKey+16 tag)
#   tag     = SHA-256(recipientPub)[0..4]
#   stanza  = type "piv-p256", args [b64nopad(tag), b64nopad(E)], body
#
import base64, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

P = ec.SECP256R1()

def b64np(b):  # base64, no padding, like Stanza.base64NoPad
    return base64.b64encode(b).decode().rstrip("=")

def compressed_pub(pub):
    return pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.CompressedPoint)

def priv_from_scalar(scalar_int):
    return ec.derive_private_key(scalar_int, P)

def pub_from_compressed(b):
    return ec.EllipticCurvePublicKey.from_encoded_point(P, b)

def ecdh_x(priv, pub_compressed):
    peer = pub_from_compressed(pub_compressed)
    return priv.exchange(ec.ECDH(), peer)   # returns 32-byte x-coord, big-endian

def hkdf_sha256(ikm, salt, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

def wrap(recipient_pub_compressed, file_key, ephemeral_scalar):
    assert len(recipient_pub_compressed) == 33 and recipient_pub_compressed[0] in (2, 3)
    e = priv_from_scalar(ephemeral_scalar)
    E = compressed_pub(e.public_key())
    shared = ecdh_x(e, recipient_pub_compressed)
    salt = E + recipient_pub_compressed
    wrap_key = hkdf_sha256(shared, salt, b"piv-p256", 32)
    body = ChaCha20Poly1305(wrap_key).encrypt(b"\x00" * 12, file_key, b"")
    tag = hashlib.sha256(recipient_pub_compressed).digest()[:4]
    return {"type": "piv-p256", "args": [b64np(tag), b64np(E)], "body": body,
            "epk": E, "shared": shared, "wrap_key": wrap_key, "tag": tag}

def unwrap_as_yubikey(recipient_priv, stanza):
    # What the YubiKey does: ECDH(recipient_priv, E) -> same shared, re-derive, open.
    E = base64.b64decode(stanza["args"][1] + "==")
    recipient_pub = compressed_pub(recipient_priv.public_key())
    shared = ecdh_x(recipient_priv, E)
    salt = E + recipient_pub
    wrap_key = hkdf_sha256(shared, salt, b"piv-p256", 32)
    return ChaCha20Poly1305(wrap_key).decrypt(b"\x00" * 12, stanza["body"], b"")

# ---- Deterministic golden vector (fixed recipient key, fixed ephemeral, fixed file key) ----
# Fixed scalars chosen < n, nonzero. These pin exact bytes for the Swift KAT.
RECIPIENT_SCALAR = 0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEE01
EPHEMERAL_SCALAR = 0x0FEDCBA987654321FEDCBA9876543210FEDCBA9876543210FEDCBA9876543201
FILE_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # 16-byte age file key

recipient_priv = priv_from_scalar(RECIPIENT_SCALAR)
recipient_pub = compressed_pub(recipient_priv.public_key())

st = wrap(recipient_pub, FILE_KEY, EPHEMERAL_SCALAR)
recovered = unwrap_as_yubikey(recipient_priv, st)
assert recovered == FILE_KEY, "round-trip failed"

# bech32 (age variant) so we can print the age1yubikey1 recipient string
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk
def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
def convertbits(data, frm, to, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value; bits += frm
        while bits >= to:
            bits -= to; ret.append((acc >> bits) & maxv)
    if pad and bits: ret.append((acc << (to - bits)) & maxv)
    return ret
def bech32_encode(hrp, data5):
    values = hrp_expand(hrp) + data5
    poly = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data5 + checksum)

age_yubikey = bech32_encode("age1yubikey", convertbits(list(recipient_pub), 8, 5))

print("=== piv-p256 golden vector ===")
print("recipient_scalar   :", hex(RECIPIENT_SCALAR))
print("recipient_pub (33) :", recipient_pub.hex())
print("age1yubikey string :", age_yubikey)
print("ephemeral_scalar   :", hex(EPHEMERAL_SCALAR))
print("file_key (16)      :", FILE_KEY.hex())
print("--- derived ---")
print("epk E (33)         :", st["epk"].hex())
print("shared x (32)      :", st["shared"].hex())
print("wrap_key (32)      :", st["wrap_key"].hex())
print("tag (4)            :", st["tag"].hex())
print("body (32)          :", st["body"].hex())
print("--- stanza ---")
print("type               :", st["type"])
print("arg[0] b64(tag)    :", st["args"][0])
print("arg[1] b64(E)      :", st["args"][1])
print("body b64           :", b64np(st["body"]))
print("round-trip         : OK (recovered file key matches)")
