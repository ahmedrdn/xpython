import sys, os, json, struct, xinit, xcrypto, xloader, xpolicy, xexec

PIN = "123456"
ESP = sys.platform == "esp32"
ROOT = "/apps_etest" if ESP else "/tmp/xexec_test"
LOG = "/xexec_test.log" if ESP else "/tmp/xexec_test.log"
PKG = ROOT + ".xpk"
print("xexec version:", xexec.version())

def rmtree(p):
    try:
        for e in os.ilistdir(p):
            q = p + "/" + e[0]
            if e[1] == 0x4000:
                rmtree(q)
            else:
                os.remove(q)
        os.rmdir(p)
    except OSError:
        pass

# --- Provision (the test plays the vendor) ---
assert xinit.state() != "LOCKED", "device is LOCKED"
if not xinit.has_pin():
    xinit.set_pin(PIN)
if xinit.state() != "BLANK":
    xinit.reset(PIN)
dev_id, dev_pub = xinit.init(PIN)
vendor_priv, vendor_pub = xcrypto.ecdsa_keygen()
app_priv, app_pub = xcrypto.ecdsa_keygen()
_, fw_pub = xcrypto.ecdsa_keygen()
xinit.install_anchor(PIN, "vendor", vendor_pub)
xinit.install_anchor(PIN, "app", app_pub)
xinit.install_anchor(PIN, "fw", fw_pub)
xinit.set_certificate(PIN, xcrypto.ecdsa_sign(vendor_priv, b"xpy-devcert-v1" + dev_id + dev_pub))
xinit.finalize(PIN)

def install(app_id, source, permissions=None):
    files = {"main.py": source}
    m = {"app_id": app_id, "version": "1.0.0", "entry": "main.py",
         "permissions": permissions or {},
         "files": {n: xcrypto.sha256(d).hex() for n, d in files.items()}}
    manifest = json.dumps(m).encode()
    sig = xcrypto.ecdsa_sign(app_priv, b"xpy-app-v1" + manifest)
    out = b"XPK1" + struct.pack("<I", len(manifest)) + manifest + sig
    for n, d in files.items():
        nb = n.encode()
        out += struct.pack("<H", len(nb)) + nb + struct.pack("<I", len(d)) + d
    with open(PKG, "wb") as f:
        f.write(out)
    xloader.install(PKG)

rmtree(ROOT)
try:
    os.remove(LOG)
except OSError:
    pass
xloader.set_root(ROOT)
xexec.set_log(LOG)

install("good", b"def main():\n    return 42\n")
install("crash", b"def main():\n    return 1 / 0\n")
install("loop", b"def main():\n    while True:\n        pass\n", {"time_ms": 300})
install("hog", b"def main():\n    x = []\n    while True:\n        x.append(bytearray(1024))\n")

# 1. A normal app
r = xexec.run_app("good")
print(r)
assert r["status"] == "ok" and r["result"] == 42

# 2. A crashing app: logged, the device carries on
r = xexec.run_app("crash")
print(r)
assert r["status"].startswith("crash: ZeroDivisionError")

# 3. An endless loop: stopped by its 300 ms time limit
r = xexec.run_app("loop")
print(r)
assert r["status"] == "timeout" and 250 <= r["ms"] < 3000

# 4. An app that eats all memory: stopped, and the memory comes back
r = xexec.run_app("hog")
print(r)
assert r["status"] == "out of memory"

# 5. After all that, everything still works normally
assert xpolicy.active() is None
assert xexec.run_app("good")["result"] == 42
statuses = [e["status"].split(":")[0] for e in xexec.log()]
assert statuses == ["ok", "crash", "timeout", "out of memory", "ok"], statuses

# 6. Development mode needs the PIN
xinit.set_dev_mode(PIN, True)
assert xinit.dev_mode()
try:
    xinit.set_dev_mode("000000", False)
    raise AssertionError("wrong PIN accepted")
except ValueError:
    pass
xinit.set_dev_mode(PIN, False)
assert not xinit.dev_mode()

# Clean up
for app in xloader.list():
    xloader.remove(app)
rmtree(ROOT)
os.remove(PKG)
os.remove(LOG)
xinit.reset(PIN)
print("xexec: all tests passed")