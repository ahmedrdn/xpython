# PC test of app updates over the air and of fw/app announcements (CPython).
# The real update server (tools/xpy-ota serve) runs here with plain TCP standing in for
# mutual TLS; the board side is the real xota + xloader with small stubs for the C modules.
# Run: python3 tests/pc_test_app_ota.py
import hashlib, json, os, shutil, socket, ssl, struct, sys, tempfile, threading, time, types
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="xpy_app_ota_"))

# ---------- stubs for the board's C modules (MicroPython things CPython lacks) ----------
time.ticks_ms = lambda: int(time.monotonic() * 1000)
time.ticks_diff = lambda a, b: a - b
time.ticks_add = lambda a, b: a + b
os.ilistdir = lambda p: ((e.name, 0x4000 if e.is_dir() else 0x8000, 0) for e in os.scandir(p))
app_key = ec.generate_private_key(ec.SECP256R1())
other_key = ec.generate_private_key(ec.SECP256R1())
PUB = app_key.public_key()


def raw_sign(key, data):
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(pub, data, sig):
    try:
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                   data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def mod(name, **kw):
    m = types.ModuleType(name)
    m.__dict__.update(kw)
    sys.modules[name] = m
    return m


mod("xcrypto", sha256=lambda d: hashlib.sha256(d).digest(), ecdsa_verify=verify, random=os.urandom)
mod("xinit", state=lambda: "OPERATIONAL", anchor=lambda k: PUB if k == "app" else None,
    device_id=lambda: bytes(16), verify_pin=lambda p: None)
mod("xkeys", exists=lambda k: False)
mod("xsfs")
mod("xwatch")
mod("xfw", VERSION="1.5.6", BOARD="XPY_ESP32C6", SELF_TEST_FAIL=False)
sys.path[:0] = [str(ROOT / d) for d in ("modules/xcomm", "modules/xloader", "modules/xfota", "tools/xpy-ota")]
import xnet, xloader, xota, xpy_ota

# ---------- the real update server, with plain TCP instead of TLS ----------
class PlainContext:
    def __init__(self, *a): pass
    def load_cert_chain(self, *a): pass
    def load_verify_locations(self, *a): pass
    def wrap_socket(self, sock, **kw): return sock

ssl.SSLContext = PlainContext
OTA = TMP / "ota"
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); PORT = srv.getsockname()[1]; srv.close()
import argparse
threading.Thread(target=xpy_ota.cmd_serve, args=(argparse.Namespace(dir=str(OTA), ota_port=PORT),),
                 daemon=True).start()
time.sleep(0.5)


class S:                                         # what xnet.tls_connect gives xota
    def __init__(self, s): self.s = s
    def write(self, b): self.s.sendall(b)
    def read(self, n):
        out = b""
        while len(out) < n:
            c = self.s.recv(n - len(out))
            if not c: break
            out += c
        return out
    def readinto(self, buf):
        c = self.s.recv(len(buf))
        buf[:len(c)] = c
        return len(c)
    def readline(self):
        out = b""
        while not out.endswith(b"\n"):
            c = self.s.recv(1)
            if not c: break
            out += c
        return out
    def close(self): self.s.close()

xnet.tls_connect = lambda port, cloud=None: S(socket.create_connection(("127.0.0.1", PORT)))
xnet.online = lambda: None
xloader.set_root(str(TMP / "board_apps"))


def package(app, version, key=app_key, files=None):
    files = files or {"main.py": ("def main():\n    return %r\n" % version).encode()}
    m = json.dumps({"app_id": app, "version": version, "entry": "main.py", "permissions": {},
                    "files": {n: hashlib.sha256(d).hexdigest() for n, d in files.items()}}).encode()
    out = b"XPK1" + struct.pack("<I", len(m)) + m + raw_sign(key, b"xpy-app-v1" + m)
    for n, d in files.items():
        out += struct.pack("<H", len(n)) + n.encode() + struct.pack("<I", len(d)) + d
    p = TMP / f"{app}-{version}.xpk"
    p.write_bytes(out)
    return p


def version_on_board(app):
    m = xloader.info(app)
    return m and m["version"]

def code_on_board(app):
    return (TMP / "board_apps" / app / "main.py").read_text().strip().split()[-1]

ok = True
def check(n, text, cond):
    global ok
    ok &= bool(cond)
    print(f"{n:2d} {'OK  ' if cond else 'FAIL'} {text}")

# ---------- app updates ----------
xloader.install(str(package("dht11", "1.0.0")))
os.makedirs(TMP / "board_apps" / ".data" / "dht11", exist_ok=True)
(TMP / "board_apps" / ".data" / "dht11" / "state.json").write_text("{}")       # the app's data
check(1, "nothing published: no update", xota.app_updates() == [] and version_on_board("dht11") == "1.0.0")
xpy_ota.publish_app(package("dht11", "1.1.0"), OTA)
xpy_ota.publish_app(package("blink", "2.0.0"), OTA)                              # board doesn't have it
r = xota.app_updates()
check(2, f"newer version installed: {r}", r == [("dht11", "installed 1.1.0")] and code_on_board("dht11") == "'1.1.0'")
check(3, "app data kept", (TMP / "board_apps" / ".data" / "dht11" / "state.json").exists())
check(4, "app the board doesn't have is NOT added", "blink" not in xloader.list())
check(5, "again: up to date", xota.app_updates() == [])
xpy_ota.publish_app(package("dht11", "1.2.0", key=other_key), OTA)              # wrong signing key
r = xota.app_updates()
check(6, f"wrong key refused, old version stays: {r}", "refused" in r[0][1] and version_on_board("dht11") == "1.1.0")
(OTA / "apps" / "dht11.xpk").write_bytes(package("dht11", "1.0.5").read_bytes())  # older version
check(7, "older version not offered as newer", xota.app_updates() == [])
bad = bytearray(package("dht11", "1.3.0").read_bytes()); bad[-3] ^= 1             # changed after signing
(OTA / "apps" / "dht11.xpk").write_bytes(bytes(bad))
r = xota.app_updates()
check(8, f"changed file refused: {r}", "hash mismatch" in r[0][1] and version_on_board("dht11") == "1.1.0")
(OTA / "apps" / "dht11.xpk").write_bytes(package("blink", "9.0.0").read_bytes())  # another app under dht11's name
check(9, "a package of another app under the wrong name: server skips it",
      "dht11" not in xpy_ota.app_index(OTA / "apps") and xota.app_updates() == [])
try:
    xloader.install(str(package("blink", "9.0.0")), expect="dht11")
    check(10, "install(expect=) refuses another app", False)
except ValueError as e:
    check(10, f"install(expect=) refuses another app: {e}", "not dht11" in str(e))
for f in list(TMP.glob("board_apps/.download.xpk")):
    check(11, "download file cleaned up", False)
else:
    check(11, "download file cleaned up", True)

# ---------- server: serves nothing else ----------
def get(path):
    s = S(socket.create_connection(("127.0.0.1", PORT)))
    s.write(b"GET " + path + b" HTTP/1.0\r\n\r\n")
    line = s.readline(); s.close()
    return int(line.split()[1])
(OTA / "secret.txt").write_text("x")
check(12, "server refuses other files", get(b"/secret.txt") == 404 and get(b"/apps/../secret.txt") == 404)
check(13, "server index", get(b"/apps/index.json") == 200)

# ---------- power cut between the two renames in install() ----------
apps = TMP / "board_apps"
os.rename(apps / "dht11", apps / ".old")
check(14, "power cut: old version put back", "dht11" in xloader.list() and not (apps / ".old").exists())

# ---------- announcements: which kind changed ----------
seen = {}
c = xnet._changes
check(15, "ThingsBoard MQTT fw_update -> fw", c(b'{"fw_update": 7}', seen) == {"fw"})
check(16, "ThingsBoard MQTT app_update -> app", c(b'{"app_update": 3}', seen) == {"app"})
check(17, "same value again -> nothing", c(b'{"app_update": 3}', seen) == set())
check(18, "other attribute -> ignored", c(b'{"led": "red"}', seen) == set())
check(19, "ThingsBoard HTTP answer", c(b'{"shared": {"fw_update": 8, "app_update": 3}}', seen) == {"fw"})
ts = {}
c(b'{"entry_id": 1, "field1": "1", "field2": null}', ts)
check(20, "ThingSpeak: field2 written, field1 empty -> app only",
      c(b'{"entry_id": 2, "field1": null, "field2": "1"}', ts) == {"app"})
check(21, "plain text change -> both", c(b"5", {}) == {"fw", "app"})

shutil.rmtree(TMP, ignore_errors=True)
print("ALL OK" if ok else "SOME FAILED")
