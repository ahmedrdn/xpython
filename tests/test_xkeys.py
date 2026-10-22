import xkeys, xcrypto

print("xkeys version:", xkeys.version())
for label in ("t_aes", "t_ecc"):          # clean up after an earlier failed run
    if xkeys.exists(label):
        xkeys.delete(label)

xkeys.generate("t_aes", xkeys.AES256)
xkeys.generate("t_ecc", xkeys.ECC_P256)
assert xkeys.exists("t_aes") and xkeys.exists("t_ecc")
labels = xkeys.list()
assert "t_aes" in labels and "t_ecc" in labels

# An existing key can't be overwritten
try:
    xkeys.generate("t_aes", xkeys.AES256)
    raise AssertionError("duplicate key accepted")
except ValueError:
    pass

# AES: encrypt and decrypt with a key Python never sees
iv = xcrypto.random(12)
ct, tag = xkeys.encrypt("t_aes", iv, b"secret data")
assert xkeys.decrypt("t_aes", iv, ct, tag) == b"secret data"

# ECC: sign inside the device, verify with the public key only
pub = xkeys.public("t_ecc")
sig = xkeys.sign("t_ecc", b"hello")
assert xcrypto.ecdsa_verify(pub, b"hello", sig)

# A key can only be used for its own type
try:
    xkeys.sign("t_aes", b"hello")
    raise AssertionError("AES key used for signing")
except ValueError:
    pass

xkeys.delete("t_aes")
xkeys.delete("t_ecc")
assert not xkeys.exists("t_aes")
print("xkeys: all tests passed")