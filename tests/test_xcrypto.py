import xcrypto

print("version:", xcrypto.version())
assert xcrypto.selftest(), "self-test failed"
assert xcrypto.sha256(b"abc").hex() == \
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
print("xcrypto: all tests passed")