import sys, os, json, struct, xinit, xcrypto, xkeys, xloader, xpolicy

PIN = "123456"
ESP = sys.platform == "esp32"
ROOT = "/apps_ptest" if ESP else "/tmp/xpolicy_test"
SHARED = "/shared_ptest" if ESP else "/tmp/xpolicy_shared"
PKG = ROOT + ".xpk"
print("xpolicy version:", xpolicy.version())

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

def pack(app_id, files, permissions):
    m = {"app_id": app_id, "version": "1.0.0", "entry": "main.py", "permissions": permissions,
         "files": {n: xcrypto.sha256(d).hex() for n, d in files.items()}}
    manifest = json.dumps(m).encode()
    sig = xcrypto.ecdsa_sign(app_priv, b"xpy-app-v1" + manifest)
    out = b"XPK1" + struct.pack("<I", len(manifest)) + manifest + sig
    for n, d in files.items():
        nb = n.encode()
        out += struct.pack("<H", len(nb)) + nb + struct.pack("<I", len(d)) + d
    with open(PKG, "wb") as f:
        f.write(out)
    return PKG

# --- The test app: tries things, reports "allowed" or "denied" ---
APP = """
SHARED = %r
OTHER_DATA = %r

def attempt(f):
    try:
        f()
        return "allowed"
    except (OSError, ImportError) as e:
        return "denied (" + type(e).__name__ + ": " + str(e) + ")"

def use_data():
    with open("/data/note.txt", "w") as f:
        f.write("private")
    with open("/data/note.txt") as f:
        assert f.read() == "private"

def main():
    return {
        "import json": attempt(lambda: __import__("json")),
        "import sys": attempt(lambda: __import__("sys")),
        "import uos": attempt(lambda: __import__("uos")),
        "import xinit": attempt(lambda: __import__("xinit")),
        "import machine": attempt(lambda: __import__("machine")),
        "write /evil.txt": attempt(lambda: open("/evil.txt", "w")),
        "os.listdir /": attempt(lambda: __import__("os").listdir("/")),
        "own /data": attempt(use_data),
        "other app's data": attempt(lambda: open(OTHER_DATA).read()),
        "read shared": attempt(lambda: open(SHARED + "/info.txt").read()),
        "write shared": attempt(lambda: open(SHARED + "/new.txt", "w")),
        "key t_shared": attempt(lambda: __import__("xkeys").encrypt("t_shared", bytes(12), b"x")),
        "key t_other": attempt(lambda: __import__("xkeys").encrypt("t_other", bytes(12), b"x")),
    }
""" % (SHARED, ROOT + "/.data/plain/note.txt")

def check(app, expected):
    result = xloader.run(app)
    for k in sorted(result):
        print("  " + app + " / " + k + ": " + result[k])
    for k, v in expected.items():
        assert result[k].split(" ")[0] == v, app + " / " + k + ": expected " + v + ", got " + result[k]

# --- Setup (system code: no policy active) ---
rmtree(ROOT)
rmtree(SHARED)
os.mkdir(SHARED)
with open(SHARED + "/info.txt", "w") as f:
    f.write("shared info")
for label in ("t_shared", "t_other"):
    if not xkeys.exists(label):
        xkeys.generate(label, xkeys.AES256)
xloader.set_root(ROOT)

files = {"main.py": APP.encode()}
xloader.install(pack("plain", files, {}))
xloader.install(pack("granted", files, {"fs": {"read": [SHARED]}, "keys": ["t_shared"]}))

D, A = "denied", "allowed"
always = {"import json": A, "import sys": D, "import uos": D, "import xinit": D,
          "import machine": D, "write /evil.txt": D, "os.listdir /": D,
          "own /data": A, "other app's data": D, "write shared": D, "key t_other": D}

# 1. No permissions: only the defaults and its own /data
check("plain", dict(always, **{"read shared": D, "key t_shared": D}))

# 2. Granted: plus reading the shared folder and using key t_shared
#    (plain's note.txt now exists, so "other app's data" is denied by the policy, not a missing file)
assert xloader.info("plain") is not None
check("granted", dict(always, **{"read shared": A, "key t_shared": A}))

# 3. After the app ends, the policy is off again
assert xpolicy.active() is None
with open(SHARED + "/after.txt", "w") as f:
    f.write("system code works normally")

# --- Clean up ---
xloader.remove("plain")
xloader.remove("granted")
rmtree(ROOT)
rmtree(SHARED)
os.remove(PKG)
xinit.reset(PIN)
print("xpolicy: all tests passed")