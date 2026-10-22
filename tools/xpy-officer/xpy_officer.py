#!/usr/bin/env python3
"""xpy-officer: the security officer's tool for xPython devices.

Commands:
  keygen     create the organization's key pairs in keys/
  status     show the device's state and check its anchors and certificate
  provision  set up a BLANK device: init, anchors, certificate, finalize
  reset      wipe a device back to BLANK
"""
import argparse
import datetime
import getpass
import json
import subprocess
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)

ROOT = Path(__file__).resolve().parents[2]          # ~/xpython
KEYS = ROOT / "keys"
DEVICES = ROOT / "devices"
KEY_FILES = {"vendor": "vendor_root.pem", "app": "app_sign.pem", "fw": "fw_sign.pem"}
CERT_LABEL = b"xpy-devcert-v1"


class DeviceError(Exception):
    pass


# ---------- Organization keys (on the PC only) ----------
def load_key(name):
    path = KEYS / KEY_FILES[name]
    if not path.exists():
        sys.exit(f"missing {path}: run 'keygen' first")
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def public_bytes(priv):
    """65-byte uncompressed public key, the same format the device uses."""
    return priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def sign_raw(priv, data):
    """Sign with ECDSA P-256 / SHA-256 and convert DER to raw r||s (64 bytes) for the device."""
    der = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw(pub65, data, sig64):
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub65)
    der = encode_dss_signature(int.from_bytes(sig64[:32], "big"),
                               int.from_bytes(sig64[32:], "big"))
    try:
        pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------- Talking to the device ----------
def run(port, code):
    """Run MicroPython code on the device and return the JSON it prints after 'XPY:'."""
    script = "import xinit, json\n" + code
    p = subprocess.run(["mpremote", "connect", port, "exec", script],
                       capture_output=True, text=True)
    out = p.stdout + p.stderr
    for line in out.splitlines():
        if line.startswith("XPY:"):
            return json.loads(line[4:])
    lines = [l for l in out.strip().splitlines() if l.strip()]
    raise DeviceError(lines[-1] if lines else "no response from the device")


def device_status(port):
    return run(port,
        'd = xinit.device_id()\n'
        'c = xinit.certificate()\n'
        'a = {}\n'
        'for n in ("vendor", "app", "fw"):\n'
        '    k = xinit.anchor(n)\n'
        '    a[n] = k.hex() if k else None\n'
        'print("XPY:" + json.dumps({"state": xinit.state(), "pin": xinit.has_pin(),\n'
        '    "tries": xinit.tries_left(), "id": d.hex() if d else None,\n'
        '    "anchors": a, "cert": [x.hex() for x in c] if c else None}))')


def ask_new_pin():
    while True:
        pin = getpass.getpass("New SO PIN (6-16 characters): ")
        if not 6 <= len(pin) <= 16:
            print("The PIN must be 6 to 16 characters.")
        elif pin != getpass.getpass("Repeat the PIN: "):
            print("The PINs don't match.")
        else:
            return pin


# ---------- Commands ----------
def cmd_keygen(args):
    KEYS.mkdir(exist_ok=True)
    for name, filename in KEY_FILES.items():
        path = KEYS / filename
        if path.exists():
            print(f"{filename}: exists, kept")
            continue
        priv = ec.generate_private_key(ec.SECP256R1())
        path.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        path.chmod(0o600)                       # readable by you only
        print(f"{filename}: created")
    print("Back up the keys/ folder outside this VM now.")


def cmd_status(args):
    st = device_status(args.port)
    print(f"state : {st['state']}")
    print(f"PIN   : {'set' if st['pin'] else 'not set'}, {st['tries']} tries left")
    print(f"id    : {st['id'] or '-'}")
    for name, filename in KEY_FILES.items():
        dev = st["anchors"][name]
        if dev is None:
            result = "not installed"
        elif (KEYS / filename).exists():
            mine = public_bytes(load_key(name)).hex()
            result = "matches your key" if dev == mine else "DOES NOT match your key"
        else:
            result = "installed (no local key to compare)"
        print(f"anchor {name:6}: {result}")
    if st["cert"]:
        dev_id, dev_pub, sig = (bytes.fromhex(x) for x in st["cert"])
        vendor = bytes.fromhex(st["anchors"]["vendor"])
        ok = verify_raw(vendor, CERT_LABEL + dev_id + dev_pub, sig)
        print(f"cert  : {'valid' if ok else 'INVALID'}")
    else:
        print("cert  : none")


def cmd_provision(args):
    keys = {name: load_key(name) for name in KEY_FILES}
    st = device_status(args.port)
    if st["state"] == "LOCKED":
        sys.exit("The device is LOCKED. Erase its flash to start over.")
    if st["state"] != "BLANK":
        sys.exit(f"The device is {st['state']}. Run 'reset' first.")

    if not st["pin"]:
        pin = ask_new_pin()
        run(args.port, f'xinit.set_pin({pin!r})\nprint("XPY:1")')
        print("SO PIN set.")
    else:
        pin = getpass.getpass("SO PIN: ")

    # 1. Identity and device key, made inside the device
    r = run(args.port, f'i, p = xinit.init({pin!r})\n'
                       f'print("XPY:" + json.dumps([i.hex(), p.hex()]))')
    dev_id, dev_pub = bytes.fromhex(r[0]), bytes.fromhex(r[1])
    print(f"Device ID: {dev_id.hex()}")

    # 2. Trust anchors: the organization's public keys
    for name, priv in keys.items():
        pub = public_bytes(priv).hex()
        run(args.port, f'xinit.install_anchor({pin!r}, {name!r}, bytes.fromhex({pub!r}))\n'
                       f'print("XPY:1")')
        print(f"Anchor '{name}' installed.")

    # 3. Device certificate, signed here with the vendor root key
    sig = sign_raw(keys["vendor"], CERT_LABEL + dev_id + dev_pub)
    run(args.port, f'xinit.set_certificate({pin!r}, bytes.fromhex({sig.hex()!r}))\n'
                   f'print("XPY:1")')
    print("Certificate installed.")

    # 4. Lock the configuration
    run(args.port, f'xinit.finalize({pin!r})\nprint("XPY:1")')

    DEVICES.mkdir(exist_ok=True)
    record = {
        "device_id": dev_id.hex(),
        "device_public_key": dev_pub.hex(),
        "certificate_signature": sig.hex(),
        "provisioned": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    (DEVICES / f"{dev_id.hex()}.json").write_text(json.dumps(record, indent=2))
    print(f"Done: the device is OPERATIONAL. Record saved in devices/{dev_id.hex()}.json")


def cmd_reset(args):
    pin = getpass.getpass("SO PIN: ")
    if input("This wipes the device's identity and keys. Type RESET to confirm: ") != "RESET":
        sys.exit("Cancelled.")
    run(args.port, f'xinit.reset({pin!r})\nprint("XPY:1")')
    print("The device is BLANK again.")


def main():
    parser = argparse.ArgumentParser(description="xPython security officer tool")
    parser.add_argument("--port", default="/dev/ttyUSB0", help="device serial port")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn in [("keygen", cmd_keygen), ("status", cmd_status),
                     ("provision", cmd_provision), ("reset", cmd_reset)]:
        sub.add_parser(name).set_defaults(fn=fn)
    args = parser.parse_args()
    try:
        args.fn(args)
    except DeviceError as e:
        sys.exit(f"Device error: {e}")


if __name__ == "__main__":
    main()