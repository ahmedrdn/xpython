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
        '    "tries": xinit.tries_left(), "dev": xinit.dev_mode(), "id": d.hex() if d else None,\n'
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
    print(f"dev   : {'on (REPL open)' if st['dev'] else 'off'}")
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

BOOT_PY = "import xexec\nxexec.start()\n"


def cmd_devmode(args):
    pin = getpass.getpass("SO PIN: ")
    on = args.value == "on"
    run(args.port, f'xinit.set_dev_mode({pin!r}, {on})\nprint("XPY:1")')
    print("Development mode ON: the REPL stays open." if on else
          "Development mode OFF: with autostart on, the REPL locks at the next boot.")


def cmd_autostart(args):
    text = BOOT_PY if args.value == "on" else "# xPython autostart off\n"
    run(args.port, f'with open("/boot.py", "w") as f:\n    f.write({text!r})\nprint("XPY:1")')
    print(f"Autostart {args.value}: takes effect at the next boot.")


def cmd_unlock(args):
    """Reset the device and send the unlock line during its 3-second window."""
    import time
    import serial
    pin = getpass.getpass("SO PIN: ")
    print("Resetting the device (if nothing happens, press its RESET/EN button)...")
    with serial.Serial(args.port, 115200, timeout=0.1) as s:
        s.dtr = False            # GPIO0 high: normal boot, not download mode
        s.rts = True             # EN low: hold the chip in reset
        time.sleep(0.2)
        s.rts = False            # release: the chip boots
        out, sent = b"", False
        end = time.time() + 15
        while time.time() < end:
            out += s.read(256)
            if not sent and b"XPY: unlock window open" in out:
                s.write(("XPY-UNLOCK " + pin + "\r\n").encode())   # sent ONCE
                sent = True
            if b"XPY: unlocked" in out:
                print("Unlocked: development mode is on, the REPL is available.")
                return
            if b"unlock failed" in out:
                line = [l for l in out.decode(errors="replace").splitlines() if "unlock failed" in l]
                sys.exit("Unlock refused: " + line[-1])
            if b"development mode, REPL available" in out:
                print("The device is not locked.")
                return
    sys.exit("No unlock window seen. Is autostart on and the device OPERATIONAL?")


def cmd_netconfig(args):
    from cryptography import x509
    pin = getpass.getpass("SO PIN: ")
    ssid = input("Wi-Fi name (SSID): ")
    password = getpass.getpass("Wi-Fi password: ")
    broker = input("Broker IP address: ")
    ca = x509.load_pem_x509_certificate((ROOT / "server" / "ca.crt").read_bytes())
    ca_der = ca.public_bytes(serialization.Encoding.DER).hex()
    run(args.port, "import xnet\n"
        f"xnet.configure({pin!r}, {ssid!r}, {password!r}, {broker!r}, 8883, bytes.fromhex({ca_der!r}))\n"
        'print("XPY:1")')
    print("Network settings saved on the device (sealed).")


def cmd_nettest(args):
    r = run(args.port, "import xnet\n"
        'ip, topic = xnet.test("hello from xPython over TLS")\n'
        'print("XPY:" + json.dumps([ip, topic]))')
    print(f"Device IP {r[0]}: published to {r[1]}")


def cmd_netcert(args):
    """Give the device a TLS certificate from the network CA (for mutual TLS)."""
    import datetime as dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    st = device_status(args.port)
    if not st["id"]:
        sys.exit("Provision the device first.")
    pin = getpass.getpass("SO PIN: ")
    name = "xpy-" + st["id"][:12]                       # also its MQTT name and topic prefix

    # 1. The device makes its TLS key pair and sends only the public key
    pub_hex = run(args.port, "import xnet\n"
                  f'print("XPY:" + json.dumps(xnet.tls_keygen({pin!r}).hex()))')
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pub_hex))

    # 2. The network CA signs a client certificate for that public key
    ca_key = serialization.load_pem_private_key((KEYS / "net_ca.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((ROOT / "server" / "ca.crt").read_bytes())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_cert.subject)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=730))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))

    # 3. Install it on the device; keep a copy in the register
    der = cert.public_bytes(serialization.Encoding.DER)
    run(args.port, "import xnet\n"
        f"xnet.set_tls_cert({pin!r}, bytes.fromhex({der.hex()!r}))\n"
        'print("XPY:1")')
    DEVICES.mkdir(exist_ok=True)
    (DEVICES / f"{st['id']}-tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"TLS certificate issued: CN={name}, valid 2 years (devices/{st['id']}-tls.crt)")
    

def main():
    parser = argparse.ArgumentParser(description="xPython security officer tool")
    parser.add_argument("--port", default="/dev/ttyUSB0", help="device serial port")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn in [("keygen", cmd_keygen), ("status", cmd_status),
                    ("provision", cmd_provision), ("reset", cmd_reset),
                    ("unlock", cmd_unlock), ("netconfig", cmd_netconfig),
                    ("nettest", cmd_nettest), ("netcert", cmd_netcert)]:
        sub.add_parser(name).set_defaults(fn=fn)
    for name, fn in [("devmode", cmd_devmode), ("autostart", cmd_autostart)]:
        p = sub.add_parser(name)
        p.add_argument("value", choices=["on", "off"])
        p.set_defaults(fn=fn)
    args = parser.parse_args()
    try:
        args.fn(args)
    except DeviceError as e:
        sys.exit(f"Device error: {e}")


if __name__ == "__main__":
    main()