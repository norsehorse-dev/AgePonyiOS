#!/usr/bin/env python3
# PasswordKeyBlob reference — sanity-checks the app-owned password/PIN + duress
# scheme before the Swift is written. Mirrors Android security/PasswordVault.kt.
#
# Blob layout (real and duress identical shape):
#   version(1) || logN(1) || salt(16) || sealed
#   sealed = AEAD(KEK, plaintext)  [iOS uses ChaCha20Poly1305: nonce12||ct||tag16]
#   KEK    = scrypt(secret, salt, N=2^logN, r=8, p=1, dkLen=32)
#   real blob seals the 32-byte vault key; duress blob seals 32 random bytes
#   (its content is never used — a successful open IS the duress signal).
#
# tryUnlock always derives against BOTH blobs (dummy salt when absent) and always
# attempts both opens, so wrong/real/duress cost the same work (no-tell timing).
import os, hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

VERSION, LOG_N, R, P, SALT_LEN, KEY_LEN = 1, 15, 8, 1, 16, 32

def derive(secret: str, salt: bytes, logN: int) -> bytes:
    return hashlib.scrypt(secret.encode(), salt=salt, n=1 << logN, r=R, p=P, dklen=KEY_LEN, maxmem=64*1024*1024)

def seal(kek: bytes, pt: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(kek).encrypt(nonce, pt, b"")

def open_sealed(kek: bytes, sealed: bytes) -> bytes:
    nonce, ct = sealed[:12], sealed[12:]
    return ChaCha20Poly1305(kek).decrypt(nonce, ct, b"")   # raises on wrong key/tamper

def build_blob(secret: str, plaintext: bytes) -> bytes:
    salt = os.urandom(SALT_LEN)
    kek = derive(secret, salt, LOG_N)
    return bytes([VERSION, LOG_N]) + salt + seal(kek, plaintext)

def wrap_vault_key(secret, vk): return build_blob(secret, vk)
def duress_blob(secret):        return build_blob(secret, os.urandom(KEY_LEN))

def attempt_open(secret: str, blob):
    if blob is None:
        derive(secret, bytes(SALT_LEN), LOG_N)  # dummy work, constant shape
        return None
    assert len(blob) >= 2 + SALT_LEN + 12 + 16, "blob too short"
    assert blob[0] == VERSION, f"unknown version {blob[0]}"
    logN = blob[1]
    assert 10 <= logN <= 22, f"implausible logN {logN}"
    salt = blob[2:2+SALT_LEN]
    sealed = blob[2+SALT_LEN:]
    kek = derive(secret, salt, logN)
    try:
        return open_sealed(kek, sealed)
    except Exception:
        return None

def try_unlock(secret, real_blob, duress_blob_):
    real = attempt_open(secret, real_blob)
    duress = attempt_open(secret, duress_blob_)
    if real is not None:   return ("real", real)
    if duress is not None: return ("duress", None)
    return ("wrong", None)

# ---- checks ----
VK = os.urandom(32)
real = wrap_vault_key("correct horse", VK)
dur  = duress_blob("battery staple")

# real password recovers exactly the vault key
kind, vk = try_unlock("correct horse", real, dur); assert kind == "real" and vk == VK
# duress password signals duress, never leaks a key
assert try_unlock("battery staple", real, dur)[0] == "duress"
# wrong password
assert try_unlock("nope", real, dur)[0] == "wrong"
# no duress configured: real still works, wrong still wrong, no crash
assert try_unlock("correct horse", real, None)[0] == "real"
assert try_unlock("whatever", real, None)[0] == "wrong"
# tamper any byte of the sealed region -> wrong, not a crash
t = bytearray(real); t[-1] ^= 1
assert try_unlock("correct horse", bytes(t), dur)[0] == "wrong"
# blob sizes
print(f"real blob: {len(real)} bytes, duress blob: {len(dur)} bytes (expect 78 each)")
print("ALL CHECKS PASS")
