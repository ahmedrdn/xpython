import sys, os, json, struct, xinit, xcrypto, xloader, xnet, xmsg

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
def fake_app_publish(app, sub, payload, service=None):
    sent.append((app, sub, payload))
    return "xpy/test/" + app + "/" + sub
xnet.app_publish = fake_app_publish

APP = b"""
import xmsg
def attempt(f):
    try:
        f()
        return "ok"
    except (ValueError, TypeError):
        return "refused"
def main():
    r = {}
    r["telemetry"] = attempt(lambda: xmsg.publish("telemetry", "t=24.5"))
    r["alerts/high"] = attempt(lambda: xmsg.publish("alerts/high", b"hot"))
    r["empty"] = attempt(lambda: xmsg.publish("", "x"))
    r["wildcard"] = attempt(lambda: xmsg.publish("alerts/#", "x"))
    r["escape"] = attempt(lambda: xmsg.publish("../other", "x"))
    r["number"] = attempt(lambda: xmsg.publish("telemetry", 42))
    return r
"""

rmtree(ROOT)
xloader.set_root(ROOT)
install("pub", APP, {})

# 1. The app publishes; xnet is told WHICH app sent it (the topic is the system's choice)
r = xloader.run("pub")
for k in sorted(r):
    print("  pub /", k + ":", r[k])
expected = {"telemetry": "ok", "alerts/high": "ok", "empty": "refused",
            "wildcard": "refused", "escape": "refused", "number": "refused"}
for k, v in expected.items():
    assert r[k] == v, k + ": expected " + v + ", got " + r[k]
assert sent == [("pub", "telemetry", "t=24.5"), ("pub", "alerts/high", b"hot")], sent

# 2. Outside an app, the sender is "-"
xmsg.publish("telemetry", "x")
assert sent[-1] == ("-", "telemetry", "x")

rmtree(ROOT)
os.remove(PKG)
print("xmsg: all tests passed")
