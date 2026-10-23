#!/usr/bin/env python3
"""xpy-pack: build, sign and install xPython app packages (.xpk).

  build   <app_dir> [-o file.xpk] [--no-compile]   make a signed package
  install <file.xpk>                               copy it to the device and install it
  run     <app_id>                                 run an installed app on the device

An app folder holds app.json ({"app_id", "version", "entry", "permissions"})
and its .py files.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[2]
MPY_CROSS = ROOT / "micropython/mpy-cross/build/mpy-cross"
APP_KEY = ROOT / "keys/app_sign.pem"
MAGIC = b"XPK1"
SIG_LABEL = b"xpy-app-v1"


def sign_raw(priv, data):
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def mpremote(port, *args):
    p = subprocess.run(["mpremote", "connect", port, *args], capture_output=True, text=True)
    print((p.stdout + p.stderr).strip())
    if p.returncode != 0:
        sys.exit("Device error.")


def cmd_build(args):
    app_dir = Path(args.app_dir)
    meta = json.loads((app_dir / "app.json").read_text())
    files = {}
    for src in sorted(app_dir.glob("*.py")):
        if args.no_compile:
            files[src.name] = src.read_bytes()
        else:                                   # compile to .mpy bytecode: no source on the device
            with tempfile.TemporaryDirectory() as tmp:
                dst = Path(tmp) / (src.stem + ".mpy")
                subprocess.run([str(MPY_CROSS), "-o", str(dst), str(src)], check=True)
                files[dst.name] = dst.read_bytes()
    entry = meta["entry"]
    if not args.no_compile and entry.endswith(".py"):
        entry = entry[:-3] + ".mpy"
    manifest = json.dumps({
        "app_id": meta["app_id"],
        "version": meta["version"],
        "entry": entry,
        "files": {n: hashlib.sha256(d).hexdigest() for n, d in files.items()},
        "permissions": meta.get("permissions", {}),
    }, separators=(",", ":")).encode()

    if not APP_KEY.exists():
        sys.exit(f"missing {APP_KEY}: run 'xpy-officer keygen' first")
    priv = serialization.load_pem_private_key(APP_KEY.read_bytes(), password=None)
    blob = MAGIC + struct.pack("<I", len(manifest)) + manifest + sign_raw(priv, SIG_LABEL + manifest)
    for name, data in files.items():
        nb = name.encode()
        blob += struct.pack("<H", len(nb)) + nb + struct.pack("<I", len(data)) + data

    out = Path(args.output or f"{meta['app_id']}-{meta['version']}.xpk")
    out.write_bytes(blob)
    print(f"Built {out} ({len(blob)} bytes, {len(files)} files, signed)")


def cmd_install(args):
    mpremote(args.port, "cp", args.package, ":/upload.xpk", "+", "exec",
             "import os, xloader\n"
             "try:\n"
             "    print('Installed:', xloader.install('/upload.xpk'))\n"
             "finally:\n"
             "    os.remove('/upload.xpk')")


def cmd_run(args):
    mpremote(args.port, "exec", f"import xloader\nprint('Result:', xloader.run({args.app_id!r}))")


def main():
    parser = argparse.ArgumentParser(description="xPython app packer")
    parser.add_argument("--port", default="/dev/ttyUSB0")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("app_dir")
    b.add_argument("-o", "--output")
    b.add_argument("--no-compile", action="store_true")
    b.set_defaults(fn=cmd_build)
    i = sub.add_parser("install")
    i.add_argument("package")
    i.set_defaults(fn=cmd_install)
    r = sub.add_parser("run")
    r.add_argument("app_id")
    r.set_defaults(fn=cmd_run)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()