#!/usr/bin/env python3
"""xpy-ota: build, serve and push signed xPython firmware updates.

  build    package build-XPY_ESP32/micropython.bin as build/ota/firmware.xfw (signed)
  serve    HTTPS update server on port 8443 (mutual TLS: devices with a CA certificate only):
           /firmware/<BOARD>.xfw (one per board type, from build/ota/firmware), /firmware.xfw
           (boards with older firmware), /apps/index.json and /apps/<app>.xpk (from build/ota/apps)
  publish-app  copy a signed .xpk into build/ota/apps (the boards update apps they already have)
  push     tell a USB-connected device to update now, reboot it, and confirm the result
  status   show the device's firmware version and slots
"""
import argparse
import functools
import hashlib
import http.server
import json
import os
import re
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# The xPython folder (keys/, server/, apps/, build/ ...). XPY_ROOT is set by the packed
# Windows app (xpython.exe), whose data folder is the folder of the .exe.
ROOT = Path(os.environ.get("XPY_ROOT") or Path(__file__).resolve().parents[2])
# How to run mpremote: the command, or (packed app) the .exe itself with --mpremote
MPREMOTE = json.loads(os.environ.get("XPY_MPREMOTE", '["mpremote"]'))
TEXT = {"text": True, "encoding": "utf-8", "errors": "replace"}     # same on Windows and Linux
IMAGE = ROOT / "micropython/ports/esp32/build-XPY_ESP32/micropython.bin"
XFW = ROOT / "modules/xfota/xfw.py"
OTA_DIR = ROOT / "build/ota"
FW_KEY = ROOT / "keys/fw_sign.pem"
SERVER = ROOT / "server"


def sign_raw(priv, data):
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def device(port, code):
    p = subprocess.run([*MPREMOTE, "connect", port, "exec", "import json\n" + code],
                       capture_output=True, **TEXT)
    out = p.stdout + p.stderr
    for line in out.splitlines():
        if line.startswith("XPY:"):
            return json.loads(line[4:])
    sys.exit("Device error: " + (out.strip().splitlines() or ["no response"])[-1])


# def cmd_build(args):
#     text = XFW.read_text()
#     version = re.search(r'VERSION\s*=\s*"([^"]+)"', text).group(1)
#     board = re.search(r'BOARD\s*=\s*"([^"]+)"', text).group(1)
#     image = IMAGE.read_bytes()
#     header = json.dumps({"version": version, "board": board, "size": len(image),
#                          "sha256": hashlib.sha256(image).hexdigest()},
#                         separators=(",", ":")).encode()
#     priv = serialization.load_pem_private_key(FW_KEY.read_bytes(), password=None)
#     sig = sign_raw(priv, b"xpy-fw-v1" + header)
#     OTA_DIR.mkdir(parents=True, exist_ok=True)
#     out = OTA_DIR / "firmware.xfw"
#     out.write_bytes(b"XFW1" + struct.pack("<I", len(header)) + header + sig + image)
#     print(f"Built {out}: firmware {version} for {board}, {len(image)} bytes, signed")
def firmware_tag(image_bytes):
    """(board, version) from the label the firmware carries (xfw.TAG), or None."""
    m = re.search(rb"XPY-FW:([A-Za-z0-9_]+):([0-9]+\.[0-9]+\.[0-9]+)", image_bytes)
    return (m.group(1).decode(), m.group(2).decode()) if m else None


def source_tag():
    """(board, version) from modules/xfota/xfw.py, or None if the source is not here."""
    try:
        text = XFW.read_text()
    except OSError:
        return None
    m = re.search(r'"XPY-FW:([A-Za-z0-9_]+):([0-9.]+)"', text)          # current xfw.py
    if m:
        return m.group(1), m.group(2)
    v = re.search(r'VERSION\s*=\s*"([^"]+)"', text)                       # older xfw.py
    b = re.search(r'BOARD\s*=\s*"([^"]+)"', text)
    return (b.group(1), v.group(1)) if v and b else None


def cmd_build(args):
    image_bytes = IMAGE.read_bytes()
    tag = (getattr(args, "board", None), getattr(args, "version", None))
    if not all(tag):
        tag = firmware_tag(image_bytes) or source_tag()     # the .bin's own label first
    if not tag:
        sys.exit("No version found: the firmware has no XPY-FW label and xfw.py is not here.")
    board, version = tag
    image = bytearray(IMAGE.read_bytes())
    if args.tamper_before:          # attacker who stole the fw key: change, THEN hash and sign
        image[len(image) // 2] ^= 1
    header = json.dumps({"version": version, "board": board, "size": len(image),
                         "sha256": hashlib.sha256(image).hexdigest()},
                        separators=(",", ":")).encode()
    priv = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
    sig = sign_raw(priv, b"xpy-fw-v1" + header)
    blob = bytearray(b"XFW1" + struct.pack("<I", len(header)) + header + sig + image)
    if args.tamper_after:           # attacker on the network: change AFTER signing
        blob[-100] ^= 1
    OTA_DIR.mkdir(parents=True, exist_ok=True)
    out = OTA_DIR / "firmware.xfw"
    out.write_bytes(blob)
    notes = [n for n, on in [("tampered after signing", args.tamper_after),
                             ("tampered before signing", args.tamper_before),
                             ("signed with " + args.key, args.key != str(FW_KEY))] if on]
    print(f"Built {out}: firmware {version} for {board}, {len(image)} bytes"
          + (" [" + "; ".join(notes) + "]" if notes else ", signed"))


# def cmd_serve(args):
#     handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(OTA_DIR))
#     httpd = http.server.ThreadingHTTPServer(("0.0.0.0", args.ota_port), handler)
#     ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#     ctx.load_cert_chain(SERVER / "broker.crt", SERVER / "broker.key")
#     ctx.load_verify_locations(SERVER / "ca.crt")
#     ctx.verify_mode = ssl.CERT_REQUIRED          # mutual TLS: only CA-certified devices
#     httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
#     print(f"Serving {OTA_DIR} over HTTPS (mutual TLS) on port {args.ota_port}. Ctrl+C to stop.")
#     httpd.serve_forever()
def cmd_serve(args):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SERVER / "broker.crt", SERVER / "broker.key")
    ctx.load_verify_locations(SERVER / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED          # mutual TLS: only CA-certified devices

    class Server(http.server.ThreadingHTTPServer):
        def get_request(self):
            sock, addr = self.socket.accept()
            sock.settimeout(30)                  # a silent or dead client is dropped after 30 s
            # The TLS handshake happens later, in the connection's own thread,
            # so one stuck client can't block everyone else.
            return ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

        def handle_error(self, request, client_address):
            e = sys.exc_info()[1]
            if isinstance(e, (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError)):
                # normal: the board read the header, saw it already has this version
                # (or refused the package), and closed the connection
                print(f"{client_address[0]}: board stopped the download "
                      "(already up to date, or it refused the package)")
            elif isinstance(e, ssl.SSLError):
                print(f"{client_address[0]}: TLS refused ({e.reason}): "
                      "no valid device certificate from our CA?")
            else:
                super().handle_error(request, client_address)

    folder = Path(getattr(args, "dir", None) or OTA_DIR)     # where firmware.xfw is
    apps = folder / "apps"                                   # <app_id>.xpk files
    apps.mkdir(parents=True, exist_ok=True)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(folder), **k)

        def do_GET(self):
            if self.path == "/apps/index.json":              # made fresh at every request
                body = json.dumps(app_index(apps)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if not (self.path == "/firmware.xfw"
                    or re.fullmatch(r"/firmware/[A-Za-z0-9_]{1,32}\.xfw", self.path)
                    or re.fullmatch(r"/apps/[A-Za-z0-9_\-]{1,32}\.xpk", self.path)):
                self.send_error(404)                         # serve nothing else from the folder
                return
            super().do_GET()

    httpd = Server(("0.0.0.0", args.ota_port), Handler)
    print(f"Serving the firmware in {folder / 'firmware'} (one file per board type), "
          f"{folder / 'firmware.xfw'} (boards with older firmware) and the apps in {apps} over HTTPS (mutual TLS) "
          f"on port {args.ota_port}. Ctrl+C to stop.")
    print("Offered apps:", app_index(apps) or "none")
    httpd.serve_forever()


def xfw_header(path):
    """The signed header of a .xfw package: {"board", "version", "size", "sha256"}."""
    data = Path(path).read_bytes()[:1100]
    if data[:4] != b"XFW1":
        raise ValueError("not an xPython firmware package (.xfw)")
    n = struct.unpack("<I", data[4:8])[0]
    return json.loads(data[8:8 + n])


def publish_firmware(package, folder=None):
    """Offer a signed firmware to the boards of its type: build/ota/firmware/<BOARD>.xfw.
    Also copied to build/ota/firmware.xfw, the one file boards with OLDER firmware ask for
    (other board types refuse it from its signed header)."""
    import shutil
    h = xfw_header(package)
    folder = Path(folder or OTA_DIR)
    dest = folder / "firmware" / f"{h['board']}.xfw"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if Path(package).resolve() != dest.resolve():
        shutil.copyfile(package, dest)
    legacy = folder / "firmware.xfw"
    if Path(package).resolve() != legacy.resolve():
        shutil.copyfile(package, legacy)
    return h["board"], h["version"], dest


def read_xpk(path):
    """(app_id, version) from a package's manifest (the board checks the signature itself)."""
    data = Path(path).read_bytes()
    if data[:4] != b"XPK1":
        raise ValueError("not an xPython app package (.xpk)")
    n = struct.unpack("<I", data[4:8])[0]
    m = json.loads(data[8:8 + n])
    return m["app_id"], m["version"]


def app_index(apps):
    """{app_id: version} of the packages in the apps folder (file name = <app_id>.xpk)."""
    out = {}
    for f in sorted(Path(apps).glob("*.xpk")):
        try:
            app, version = read_xpk(f)
        except (OSError, ValueError, KeyError) as e:
            print(f"skipped {f.name}: {e}")
            continue
        if f.stem != app:
            print(f"skipped {f.name}: it contains the app '{app}' (name it {app}.xpk)")
            continue
        out[app] = version
    return out


def publish_app(package, folder=None):
    """Offer a signed app package to the boards: copy it into the server's apps folder."""
    import shutil
    app, version = read_xpk(package)
    dest = Path(folder or OTA_DIR) / "apps" / f"{app}.xpk"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(package, dest)
    return app, version, dest

def cmd_status(args):
    print(device(args.port, 'import xota\nprint("XPY:" + json.dumps(xota.status()))'))


def cmd_push(args):
    role = device(args.port, 'import xgate\nprint("XPY:" + json.dumps([xgate.role(), xgate.link()]))')
    if role == ["device", "espnow"]:
        print("This is a gateway DEVICE on ESP-NOW (no Wi-Fi): update it with 'Flash' over USB (Firmware tab).")
        return "gateway device: use Flash over USB"
    print("Before:", device(args.port, 'import xota\nprint("XPY:" + json.dumps(xota.status()))'))
    t0 = time.time()
    r = device(args.port, 'import xota\nprint("XPY:" + json.dumps(xota.update()))')
    print(f"Update: {r[0]} {r[1]} ({time.time() - t0:.1f} s)")
    if r[0] != "installed":
        return f"{r[0]} {r[1]}"

    print("Rebooting into the new firmware...")
    try:
        subprocess.run([*MPREMOTE, "connect", args.port, "reset"],
                       capture_output=True, timeout=15)
    except subprocess.TimeoutExpired:
        pass                             # the device reset; mpremote just lost it
    time.sleep(6)

    try:
        p = subprocess.run([*MPREMOTE, "connect", args.port, "exec",
                            'import json, xota\nprint("XPY:" + json.dumps(xota.confirm()))'],
                           capture_output=True, **TEXT, timeout=30)
        lines = [l for l in (p.stdout + p.stderr).splitlines() if l.startswith("XPY:")]
    except subprocess.TimeoutExpired:
        lines = []                       # the device reset itself during confirm
    if lines:
        c = json.loads(lines[-1][4:])
        print("Confirm:", c)
        result = f"updated to {c.get('confirmed')}"
    else:
        print("No confirmation: the self-test failed and the device rolled back.")
        time.sleep(8)                    # let it reboot into the previous firmware
        result = f"{r[1]} failed its self-test, rolled back"
    print("After:", device(args.port, 'import xota\nprint("XPY:" + json.dumps(xota.status()))'))
    return result
    

def main():
    parser = argparse.ArgumentParser(description="xPython OTA tool")
    parser.add_argument("--port", default=("COM3" if os.name == "nt" else "/dev/ttyUSB0"))
    parser.add_argument("--ota-port", type=int, default=8443)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn in [("push", cmd_push), ("status", cmd_status)]:
        sub.add_parser(name).set_defaults(fn=fn)
    sv = sub.add_parser("serve")
    sv.add_argument("--dir", help="folder that holds firmware.xfw (default: build/ota)")
    sv.set_defaults(fn=cmd_serve)
    pa = sub.add_parser("publish-app", help="offer a signed .xpk to the boards (copies it to build/ota/apps)")
    pa.add_argument("package")
    pa.set_defaults(fn=lambda a: print("Published %s %s -> %s" % publish_app(a.package)))
    b = sub.add_parser("build")
    b.add_argument("--key", default=str(FW_KEY), help="signing key (default: keys/fw_sign.pem)")
    b.add_argument("--tamper-after", action="store_true", help="test: change a byte after signing")
    b.add_argument("--tamper-before", action="store_true", help="test: change a byte, then sign")
    b.set_defaults(fn=cmd_build)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()