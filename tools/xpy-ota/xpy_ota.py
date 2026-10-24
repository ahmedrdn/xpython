#!/usr/bin/env python3
"""xpy-ota: build, serve and push signed xPython firmware updates.

  build    package build-XPY_ESP32/micropython.bin as build/ota/firmware.xfw (signed)
  serve    HTTPS update server on port 8443 (mutual TLS: devices with a CA certificate only)
  push     tell a USB-connected device to update now, reboot it, and confirm the result
  status   show the device's firmware version and slots
"""
import argparse
import functools
import hashlib
import http.server
import json
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

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ROOT / "micropython/ports/esp32/build-XPY_ESP32/micropython.bin"
XFW = ROOT / "frozen/xfw.py"
OTA_DIR = ROOT / "build/ota"
FW_KEY = ROOT / "keys/fw_sign.pem"
SERVER = ROOT / "server"


def sign_raw(priv, data):
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def device(port, code):
    p = subprocess.run(["mpremote", "connect", port, "exec", "import json\n" + code],
                       capture_output=True, text=True)
    out = p.stdout + p.stderr
    for line in out.splitlines():
        if line.startswith("XPY:"):
            return json.loads(line[4:])
    sys.exit("Device error: " + (out.strip().splitlines() or ["no response"])[-1])


def cmd_build(args):
    text = XFW.read_text()
    version = re.search(r'VERSION\s*=\s*"([^"]+)"', text).group(1)
    board = re.search(r'BOARD\s*=\s*"([^"]+)"', text).group(1)
    image = IMAGE.read_bytes()
    header = json.dumps({"version": version, "board": board, "size": len(image),
                         "sha256": hashlib.sha256(image).hexdigest()},
                        separators=(",", ":")).encode()
    priv = serialization.load_pem_private_key(FW_KEY.read_bytes(), password=None)
    sig = sign_raw(priv, b"xpy-fw-v1" + header)
    OTA_DIR.mkdir(parents=True, exist_ok=True)
    out = OTA_DIR / "firmware.xfw"
    out.write_bytes(b"XFW1" + struct.pack("<I", len(header)) + header + sig + image)
    print(f"Built {out}: firmware {version} for {board}, {len(image)} bytes, signed")


def cmd_serve(args):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(OTA_DIR))
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", args.ota_port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SERVER / "broker.crt", SERVER / "broker.key")
    ctx.load_verify_locations(SERVER / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED          # mutual TLS: only CA-certified devices
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"Serving {OTA_DIR} over HTTPS (mutual TLS) on port {args.ota_port}. Ctrl+C to stop.")
    httpd.serve_forever()


def cmd_status(args):
    print(device(args.port, 'import xota\nprint("XPY:" + json.dumps(xota.status()))'))


def cmd_push(args):
    print("Before:", device(args.port, 'import xota\nprint("XPY:" + json.dumps(xota.status()))'))
    t0 = time.time()
    r = device(args.port, 'import xota\nprint("XPY:" + json.dumps(xota.update()))')
    print(f"Update: {r[0]} {r[1]} ({time.time() - t0:.1f} s)")
    if r[0] != "installed":
        return
    print("Rebooting into the new firmware...")
    subprocess.run(["mpremote", "connect", args.port, "reset"], capture_output=True)
    time.sleep(6)
    p = subprocess.run(["mpremote", "connect", args.port, "exec",
                        'import json, xota\nprint("XPY:" + json.dumps(xota.confirm()))'],
                       capture_output=True, text=True)
    lines = [l for l in (p.stdout + p.stderr).splitlines() if l.startswith("XPY:")]
    if lines:
        print("Confirm:", json.loads(lines[-1][4:]))
    else:
        print("No confirmation: the self-test failed and the device rolled back.")
        time.sleep(6)
    print("After:", device(args.port, 'import xota\nprint("XPY:" + json.dumps(xota.status()))'))


def main():
    parser = argparse.ArgumentParser(description="xPython OTA tool")
    parser.add_argument("--port", default="/dev/ttyUSB0")
    parser.add_argument("--ota-port", type=int, default=8443)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn in [("build", cmd_build), ("serve", cmd_serve),
                     ("push", cmd_push), ("status", cmd_status)]:
        sub.add_parser(name).set_defaults(fn=fn)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()