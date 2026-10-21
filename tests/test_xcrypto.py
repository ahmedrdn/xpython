import xcrypto

print("version:", xcrypto.version())
assert xcrypto.selftest(), "self-test failed"

# SHA-256
assert xcrypto.sha256(b"abc").hex() == \
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

# Random: right length, and two calls never match
r1 = xcrypto.random(16)
r2 = xcrypto.random(16)
assert len(r1) == 16 and r1 != r2

# AES-GCM: encrypt then decrypt gives the original back
key = xcrypto.random(32)
iv = xcrypto.random(12)
ct, tag = xcrypto.aes_gcm_encrypt(key, iv, b"hello xpython", b"header")
assert ct != b"hello xpython" and len(tag) == 16
assert xcrypto.aes_gcm_decrypt(key, iv, ct, tag, b"header") == b"hello xpython"

# AES-GCM: changing one bit of the ciphertext must be detected
bad = bytes([ct[0] ^ 1]) + ct[1:]
try:
    xcrypto.aes_gcm_decrypt(key, iv, bad, tag, b"header")
    raise AssertionError("tampered data was accepted")
except ValueError:
    pass

# HMAC-SHA256, RFC 4231 test case 2
assert xcrypto.hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex() == \
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

# HKDF-SHA256, RFC 5869 test case 1
okm = xcrypto.hkdf_sha256(b"\x0b" * 22, bytes(range(13)), bytes(range(0xf0, 0xfa)), 42)
assert okm.hex() == \
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

# ECDSA P-256: sign, verify, and reject changed data or a wrong key
priv, pub = xcrypto.ecdsa_keygen()
assert len(priv) == 32 and len(pub) == 65
sig = xcrypto.ecdsa_sign(priv, b"firmware v1.0")
assert len(sig) == 64
assert xcrypto.ecdsa_verify(pub, b"firmware v1.0", sig)
assert not xcrypto.ecdsa_verify(pub, b"firmware v1.1", sig)
_, pub2 = xcrypto.ecdsa_keygen()
assert not xcrypto.ecdsa_verify(pub2, b"firmware v1.0", sig)
caps = xcrypto.capabilities()
print("capabilities:", caps)
assert "aes_gcm" in caps["algorithms"] and "ecdsa_p256" in caps["algorithms"]
print("xcrypto: all tests passed")