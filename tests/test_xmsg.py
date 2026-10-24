import sys, os, json, struct, xinit, xcrypto, xloader, xpolicy, xmsg

PIN = "123456"
ROOT = "/apps_mtest" if sys.platform == "esp32" else "/tmp/xmsg_test"
PKG = ROOT + ".xpk"

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

def install(app_id, source, permissions):
    files = {"main.py": source}
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
    xloader.install(PKG)

# --- A fake network service that records what it is asked to send ---
sent = []
def fake_publisher(app, sub, payload):
    sent.append((app, sub, payload))
    return "xpy/test/" + app + "/" + sub
xpolicy.set_publisher(fake_publisher)

APP = b"""
def attempt(f):
    try:
        f()
        return "allowed"
    except (OSError, ValueError, ImportError):
        return "denied"

def main():
    import xmsg
    return {
        "telemetry": attempt(lambda: xmsg.publish("telemetry", "t=24.5")),
        "alerts/high": attempt(lambda: xmsg.publish("alerts/high", "hot")),
        "alerts": attempt(lambda: xmsg.publish("alerts", "check")),
        "config": attempt(lambda: xmsg.publish("config", "evil")),
        "wildcard": attempt(lambda: xmsg.publish("alerts/#", "x")),
        "escape": attempt(lambda: xmsg.publish("../other/x", "x")),
        "import socket": attempt(lambda: __import__("socket")),
    }
"""
NOPUB = b"""
def main():
    try:
        import xmsg
        return "allowed"
    except ImportError:
        return "denied"
"""

rmtree(ROOT)
xloader.set_root(ROOT)
install("pub", APP, {"publish": ["telemetry", "alerts/#"]})
install("nopub", NOPUB, {})

# 1. An app with publish permissions: only its listed topics go through
r = xloader.run("pub")
for k in sorted(r):
    print("  pub /", k + ":", r[k])
expected = {"telemetry": "allowed", "alerts/high": "allowed", "alerts": "allowed",
            "config": "denied", "wildcard": "denied", "escape": "denied", "import socket": "denied"}
for k, v in expected.items():
    assert r[k] == v, k + ": expected " + v + ", got " + r[k]
assert sent == [("pub", "telemetry", "t=24.5"), ("pub", "alerts/high", "hot"),
                ("pub", "alerts", "check")], sent

# 2. An app without publish permissions can't even import xmsg
assert xloader.run("nopub") == "denied"

# 3. System code can't call it outside an app (there is no app to publish for)
try:
    xmsg.publish("telemetry", "x")
    raise AssertionError("xmsg worked outside an app")
except OSError:
    pass

# Clean up
for app in xloader.list():
    xloader.remove(app)
rmtree(ROOT)
os.remove(PKG)
xinit.reset(PIN)
print("xmsg: all tests passed")