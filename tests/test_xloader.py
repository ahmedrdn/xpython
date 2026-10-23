import sys, os, json, struct, xinit, xcrypto, xloader

PIN = "123456"
ROOT = "/apps_test" if sys.platform == "esp32" else "/tmp/xloader_test"
PKG = ROOT + ".xpk"
print("xloader version:", xloader.version())

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

# --- Provision the device (the test plays the vendor) ---
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

# --- A tiny packer: the same format xpy-pack makes ---
def pack(app_id, ver, files, key=None, entry="main.py", tamper=None):
    m = {"app_id": app_id, "version": ver, "entry": entry, "permissions": {},
         "files": {n: xcrypto.sha256(d).hex() for n, d in files.items()}}
    manifest = json.dumps(m).encode()
    sig = xcrypto.ecdsa_sign(key or app_priv, b"xpy-app-v1" + manifest)
    if tamper:                                   # change a file AFTER signing
        files = dict(files)
        files[tamper] = files[tamper] + b"\n# evil"
    out = b"XPK1" + struct.pack("<I", len(manifest)) + manifest + sig
    for n, d in files.items():
        nb = n.encode()
        out += struct.pack("<H", len(nb)) + nb + struct.pack("<I", len(d)) + d
    with open(PKG, "wb") as f:
        f.write(out)
    return PKG

def refused(path):
    try:
        xloader.install(path)
        raise AssertionError("bad package accepted")
    except ValueError:
        pass

rmtree(ROOT)
xloader.set_root(ROOT)
V1 = {"main.py": b"def main():\n    return 'hello v1'\n"}
V2 = {"main.py": b"import helper\ndef main():\n    return helper.msg()\n",
      "helper.py": b"def msg():\n    return 'hello v2'\n"}

# 1. Install and run a signed app
assert xloader.install(pack("demo", "1.0.0", V1)) == "demo"
assert xloader.list() == ["demo"]
assert xloader.info("demo")["version"] == "1.0.0"
assert xloader.run("demo") == "hello v1"

# 2. Bad packages are refused
refused(pack("demo", "1.1.0", V1, tamper="main.py"))          # file changed after signing
wrong_priv, _ = xcrypto.ecdsa_keygen()
refused(pack("demo", "1.1.0", V1, key=wrong_priv))            # not signed by our app key
refused(pack("demo", "0.9.0", V1))                            # older version
refused(pack("demo", "1.0.0", V1))                            # same version
refused(pack("evil", "1.0.0", {"../boot.py": b"x"}, entry="../boot.py"))   # path escape
assert xloader.info("demo")["version"] == "1.0.0"             # nothing changed

# 3. Upgrade to a two-file version
xloader.install(pack("demo", "1.1.0", V2))
assert xloader.run("demo") == "hello v2"

# 4. A file changed in flash after install is caught at run time
with open(ROOT + "/demo/helper.py", "ab") as f:
    f.write(b"\n# evil")
try:
    xloader.run("demo")
    raise AssertionError("modified app ran")
except ValueError:
    pass

# 5. Remove
xloader.remove("demo")
assert xloader.list() == []

# Clean up: leave the device BLANK like the other tests
rmtree(ROOT)
os.remove(PKG)
xinit.reset(PIN)
print("xloader: all tests passed")