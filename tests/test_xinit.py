import sys, xinit, xkeys, xcrypto

PIN = "123456"
print("xinit version:", xinit.version())
assert xinit.state() != "LOCKED", "device is LOCKED: erase the flash to start over"

# Start from BLANK with the test PIN
if not xinit.has_pin():
    xinit.set_pin(PIN)
if xinit.state() != "BLANK":
    xinit.reset(PIN)
assert xinit.state() == "BLANK" and xinit.device_id() is None

# An existing PIN can't be replaced without the old one
try:
    xinit.set_pin("999999")
    raise AssertionError("PIN replaced without the old PIN")
except ValueError:
    pass

# --- init: identity + device key ---
dev_id, pub = xinit.init(PIN)
assert len(dev_id) == 16 and len(pub) == 65
assert xinit.state() == "PERSONALIZED"
assert xinit.device_id() == dev_id
assert xkeys.public("device") == pub
assert xcrypto.ecdsa_verify(pub, b"hello", xkeys.sign("device", b"hello"))

# --- 0.2: trust anchors, certificate, finalize ---
# The test plays the vendor: it makes the organization's keys itself
vendor_priv, vendor_pub = xcrypto.ecdsa_keygen()
_, app_pub = xcrypto.ecdsa_keygen()
_, fw_pub = xcrypto.ecdsa_keygen()

# finalize is refused while anything is missing
try:
    xinit.finalize(PIN)
    raise AssertionError("finalize accepted without anchors")
except ValueError:
    pass

# An invalid public key is refused, and doesn't use up a PIN try
try:
    xinit.install_anchor(PIN, "vendor", b"\x04" + bytes(64))
    raise AssertionError("invalid public key accepted")
except ValueError:
    pass
assert xinit.tries_left() == 5

xinit.install_anchor(PIN, "vendor", vendor_pub)
xinit.install_anchor(PIN, "app", app_pub)
xinit.install_anchor(PIN, "fw", fw_pub)
assert xinit.anchor("app") == app_pub

# The certificate: the vendor signs "xpy-devcert-v1" + device ID + device public key
msg = b"xpy-devcert-v1" + dev_id + pub
wrong_priv, _ = xcrypto.ecdsa_keygen()
try:
    xinit.set_certificate(PIN, xcrypto.ecdsa_sign(wrong_priv, msg))
    raise AssertionError("certificate from the wrong key accepted")
except ValueError:
    pass
xinit.set_certificate(PIN, xcrypto.ecdsa_sign(vendor_priv, msg))
cid, cpub, csig = xinit.certificate()
assert cid == dev_id and cpub == pub
assert xcrypto.ecdsa_verify(vendor_pub, msg, csig)

xinit.finalize(PIN)
assert xinit.state() == "OPERATIONAL"

# In OPERATIONAL, anchors are frozen and init is refused
try:
    xinit.install_anchor(PIN, "app", fw_pub)
    raise AssertionError("anchor changed while OPERATIONAL")
except ValueError:
    pass
try:
    xinit.init(PIN)
    raise AssertionError("second init accepted")
except ValueError:
    pass

# --- PIN tries and reset ---
try:
    xinit.reset("000000")
    raise AssertionError("wrong PIN accepted")
except ValueError:
    pass
assert xinit.tries_left() == 4
xinit.reset(PIN)
assert xinit.tries_left() == 5
assert xinit.state() == "BLANK" and not xkeys.exists("device")
assert xinit.anchor("vendor") is None and xinit.certificate() is None

# Lock-out test, PC only (on the board, LOCKED would need a flash erase to undo)
if sys.platform != "esp32":
    for _ in range(5):
        try:
            xinit.reset("000000")
        except ValueError:
            pass
    assert xinit.state() == "LOCKED"
    try:
        xinit.reset(PIN)
        raise AssertionError("locked device accepted the PIN")
    except ValueError:
        pass

print("xinit: all tests passed")