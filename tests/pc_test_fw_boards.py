# PC test of per-board firmware files on the update server (CPython).
# The real update server (tools/xpy-ota serve) runs here with plain TCP standing in for
# mutual TLS; the board side is the real xota + xloader with small stubs for the C modules.
# Run: python3 tests/pc_test_fw_boards.py
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
mod("xinit", state=lambda: "OPERATIONAL", anchor=lambda k: PUB,
    device_id=lambda: bytes(16), verify_pin=lambda p: None)
mod("xkeys", exists=lambda k: False)
mod("xsfs")
mod("xwatch")
mod("xfw", VERSION="1.6.0", BOARD="XPY_ESP32C6", SELF_TEST_FAIL=False)
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

def get(path):
    s = S(socket.create_connection(("127.0.0.1", PORT)))
    s.write(b"GET " + path + b" HTTP/1.0\r\n\r\n")
    line = s.readline(); s.close()
    return int(line.split()[1])

def fw(board, version):
    header = json.dumps({"version": version, "board": board, "size": 4, "sha256": "0" * 64}).encode()
    p = TMP / f"{board}-{version}.xfw"
    p.write_bytes(b"XFW1" + struct.pack("<I", len(header)) + header + raw_sign(app_key, b"xpy-fw-v1" + header) + b"IMG!")
    return p

check(1, "nothing published -> 'nothing published' (not an error)", xota.update()[0] == "nothing published")
xpy_ota.publish_firmware(fw("XPY_ESP32C3", "1.6.2"), OTA)
try:
    xota.update(); r = "no error"
except ValueError as e:
    r = str(e)
check(2, f"only a C3 firmware: the C6 refuses it ({r})", "another board" in r)
xpy_ota.publish_firmware(fw("XPY_ESP32C6", "1.6.0"), OTA)
check(3, "both published: C3 file NOT overwritten", xpy_ota.xfw_header(OTA / "firmware" / "XPY_ESP32C3.xfw")["version"] == "1.6.2")
check(4, "C6 fetches its own file: up to date", xota.update() == ("up to date", "1.6.0"))
xpy_ota.publish_firmware(fw("XPY_ESP32C6", "1.6.3"), OTA)
xpy_ota.publish_firmware(fw("XPY_ESP32C3", "1.6.4"), OTA)       # last published = the shared old file
check(5, "C6 gets its newer one even though the last publish was a C3", xota.update(skip="1.6.3") == ("skipped", "1.6.3"))
check(6, "shared file for older boards = last published", xpy_ota.xfw_header(OTA / "firmware.xfw")["board"] == "XPY_ESP32C3")
check(7, "server refuses other paths", get(b"/firmware/../firmware.xfw") == 404 and get(b"/firmware/x.bin") == 404)
shutil.rmtree(TMP, ignore_errors=True)
print("ALL OK" if ok else "SOME FAILED")
