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
import os
import subprocess
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)

# The xPython folder (keys/, server/, apps/, build/ ...). XPY_ROOT is set by the packed
# Windows app (xpython.exe), whose data folder is the folder of the .exe.
ROOT = Path(os.environ.get("XPY_ROOT") or Path(__file__).resolve().parents[2])
# How to run mpremote: the command, or (packed app) the .exe itself with --mpremote
MPREMOTE = json.loads(os.environ.get("XPY_MPREMOTE", '["mpremote"]'))
TEXT = {"text": True, "encoding": "utf-8", "errors": "replace"}     # same on Windows and Linux
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
def run(port, code, resume=False):
    """Run MicroPython code on the device and return the JSON it prints after 'XPY:'.
    resume=True: no soft reset first. Needed right after provisioning: a soft reset would
    start xexec, which locks the REPL of an OPERATIONAL board (development mode off)."""
    script = "import xinit, json\n" + code
    p = subprocess.run([*MPREMOTE, "connect", port, *(["resume"] if resume else []), "exec", script],
                       capture_output=True, **TEXT)
    out = p.stdout + p.stderr
    for line in out.splitlines():
        if line.startswith("XPY:"):
            return json.loads(line[4:])
    lines = [l for l in out.strip().splitlines() if l.strip()]
    raise DeviceError(lines[-1] if lines else "no response from the device")


def device_status(port, resume=False):
    return run(port,
        'd = xinit.device_id()\n'
        'c = xinit.certificate()\n'
        'a = {}\n'
        'for n in ("vendor", "app", "fw"):\n'
        '    k = xinit.anchor(n)\n'
        '    a[n] = k.hex() if k else None\n'
        'print("XPY:" + json.dumps({"state": xinit.state(), "pin": xinit.has_pin(),\n'
        '    "tries": xinit.tries_left(), "dev": xinit.dev_mode(), "id": d.hex() if d else None,\n'
        '    "anchors": a, "cert": [x.hex() for x in c] if c else None}))', resume)


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
    print(f"Keys are in {KEYS}. Back up that folder now (USB stick), and keep it private.")


def cmd_status(args):
    st = device_status(args.port)
    print(f"state : {st['state']}")
    print(f"PIN   : {'set' if st['pin'] else 'not set'}, {st['tries']} tries left")
    print(f"dev   : {'on (REPL open)' if st['dev'] else 'off'}")
    print(f"id    : {st['id'] or '-'}")
    if st["id"]:
        print(f"setup : Wi-Fi page hotspot xPython-{st['id'][:6]}, password xpy-{st['id'][:8]}")
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


BOARD_INFO = """
import os, gc, time, machine, esp, esp32, xfw
u = os.uname()
gc.collect()
r = {"board": u.machine, "micropython": u.release, "fw_tag": getattr(xfw, "TAG", ""),
     "fw": xfw.VERSION, "cpu_mhz": machine.freq() // 1000000, "flash": esp.flash_size(),
     "mac": machine.unique_id().hex(), "uptime_s": time.ticks_ms() // 1000,
     "heap": [gc.mem_free() + gc.mem_alloc(), gc.mem_free()],
     "idf_heap": [sum(h[0] for h in esp32.idf_heap_info(esp32.HEAP_DATA)),
                  sum(h[1] for h in esp32.idf_heap_info(esp32.HEAP_DATA))]}
p = esp32.Partition(esp32.Partition.RUNNING).info()
r["slot"] = [p[4], p[2], p[3]]
try:
    v = os.statvfs("/")
    r["fs"] = [v[0] * v[2], v[0] * v[3]]
except OSError:
    r["fs"] = None
try:
    import xgate
    r["role"] = [xgate.role(), xgate.link()]
except Exception:
    r["role"] = None
mods = {}
for n in ("xexec", "xnet", "xgate", "xota", "xloader", "xsfs"):
    try:
        mods[n] = __import__(n).VERSION
    except Exception:
        pass
r["modules"] = mods
print("XPY:" + json.dumps(r))
"""


def _kb(n):
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{n // 1024} KB"


def cmd_boardinfo(args):
    """The board's chip, firmware, memory and flash. Needs the REPL (development mode on);
    if it is locked, falls back to esptool, which reads the chip itself (and restarts it)."""
    try:
        r = run(args.port, BOARD_INFO)
    except DeviceError as e:
        print(f"The REPL did not answer ({e}).")
        print("Reading the chip with esptool instead (the board restarts afterwards)...")
        return _esptool_info(args.port)
    mac = ":".join(r["mac"][i:i + 2] for i in range(0, len(r["mac"]), 2))
    print(f"board      : {r['board']}")
    print(f"firmware   : {r['fw_tag'] or r['fw']}   (MicroPython {r['micropython']})")
    print(f"CPU        : {r['cpu_mhz']} MHz")
    print(f"flash      : {_kb(r['flash'])}")
    total, free = r["heap"]
    print(f"Python heap: {_kb(total)} total, {_kb(free)} free"
          + ("   (in PSRAM)" if total > 1048576 else ""))
    print(f"IDF heap   : {_kb(r['idf_heap'][0])} total, {_kb(r['idf_heap'][1])} free   (Wi-Fi, TLS)")
    name, addr, size = r["slot"]
    print(f"running    : {name} at {hex(addr)} ({_kb(size)} slot)")
    if r["fs"]:
        print(f"files      : {_kb(r['fs'][0])} total, {_kb(r['fs'][1])} free")
    print(f"MAC        : {mac}")
    if r["role"]:
        role, link = r["role"]
        print(f"role       : {role}" + (f", link {link}" if role == "device" else ""))
    print(f"up for     : {r['uptime_s'] // 3600} h {r['uptime_s'] // 60 % 60} min")
    print("modules    : " + ", ".join(f"{k} {v}" for k, v in sorted(r["modules"].items())))
    return r


def _esptool_info(port):
    """Chip type, revision, features, crystal, MAC and flash size, from the ROM bootloader."""
    try:
        import esptool                                  # pip package (bundled in xpython.exe)
        esptool.main(["--port", port, "flash_id"])
        return
    except ImportError:
        pass
    p = subprocess.run(["bash", "-c", "source esp-idf/export.sh > /dev/null && esptool.py --port "
                        + port + " flash_id"], cwd=ROOT, capture_output=True, **TEXT)
    print((p.stdout + p.stderr).strip())


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

    # 5. Its TLS certificate for mutual TLS (local broker, update server). The network CA
    #    (the "server certificates") is made once, the first time it is needed.
    if not ((KEYS / "net_ca.key").exists() and (ROOT / "server" / "ca.crt").exists()):
        print("No server certificates yet: creating them (once).")
        cmd_netca(args)
    cmd_netcert(args, pin=pin, resume=True)     # no soft reset: that would lock the REPL now


def cmd_reset(args):
    pin = getpass.getpass("SO PIN: ")
    if input("This wipes the device's identity and keys. Type RESET to confirm: ") != "RESET":
        sys.exit("Cancelled.")
    run(args.port, f'xinit.reset({pin!r})\nprint("XPY:1")')
    print("The device is BLANK again.")

def cmd_devmode(args):
    pin = getpass.getpass("SO PIN: ")
    on = args.value == "on"
    # xPython starts by itself (frozen _boot.py); an old autostart boot.py is removed
    run(args.port, f'xinit.set_dev_mode({pin!r}, {on})\n'
        'import os\ntry:\n    t = open("/boot.py").read()\n'
        '    if "xexec" in t or "autostart" in t:\n        os.remove("/boot.py")\n'
        'except OSError:\n    pass\nprint("XPY:1")')
    print("Development mode ON: the REPL stays open." if on else
          "Development mode OFF: at the next restart the board runs its apps and the REPL locks.")


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
    sys.exit("No unlock window seen. Is the device OPERATIONAL with dev mode off?")


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


def read_credentials(path):
    """An MQTT credentials file (plain text "username = ..." lines, or mqtt_secrets.h) -> dict."""
    found = {}
    for line in Path(path).expanduser().read_text().splitlines():
        low = line.lower()
        if '"' in line:
            value = line.split('"')[1]
        elif "=" in line:
            value = line.split("=", 1)[1]
        elif ":" in line:
            value = line.split(":", 1)[1]
        else:
            continue
        value = value.strip()
        for key, word in (("client_id", "client"), ("username", "user"), ("password", "pass")):
            if word in low and value and key not in found:
                found[key] = value
                break
    if not found:
        sys.exit(f"{path}: no client ID, username or password found")
    for k in ("client_id", "username", "password"):
        found.setdefault(k, "")
    return found


def load_ca(path):
    """A CA certificate file (PEM or DER) -> DER bytes."""
    from cryptography import x509
    data = Path(path).expanduser().read_bytes()
    ca = (x509.load_pem_x509_certificate(data) if b"BEGIN CERTIFICATE" in data
          else x509.load_der_x509_certificate(data))
    print(f"  CA: {ca.subject.rfc4514_string()}")
    return ca.public_bytes(serialization.Encoding.DER)


def save_cloud(port, pin, host, broker_port, ca_der, topic, client_id, username, password, fields,
               protocol="mqtt", key="", header="", name="default"):
    run(port, "import xnet\n"
        f"xnet.configure_cloud({pin!r}, {host!r}, {int(broker_port)}, bytes.fromhex({ca_der.hex()!r}), "
        f"{topic!r}, {client_id!r}, {username!r}, {password!r}, {fields!r}, "
        f"{protocol!r}, {key!r}, {header!r}, {name!r})\n"
        'print("XPY:1")')
    print(f"Service '{name}' saved on the device (sealed): {protocol.upper()} {host}:{broker_port}, {topic}")


def cmd_cloudconfig(args):
    """Send app data to a cloud service: MQTT (TLS), HTTP (HTTPS) or CoAP (DTLS)."""
    pin = getpass.getpass("SO PIN: ")
    protocol = (input("Protocol (mqtt, http, coap) [mqtt]: ").strip() or "mqtt").lower()
    default_port = {"mqtt": "8883", "http": "443", "coap": "5684"}.get(protocol, "8883")
    host = input("Host: ").strip()
    broker_port = input(f"Port [{default_port}]: ").strip() or default_port
    topic = input("Topic or path ({device} {app} {sub} {key} are filled in): ").strip()
    fields = input("Field names, comma-separated (Enter = send the message as it is): ").strip()
    cred = {"client_id": "", "username": "", "password": ""}
    key = header = ""
    if protocol == "mqtt":
        cred_file = input("Credentials file (Enter = type them): ").strip()
        if cred_file:
            cred = read_credentials(cred_file)
            print(f"  read client ID {cred['client_id']} and username {cred['username']}")
        else:
            cred = {"client_id": input("MQTT client ID (Enter = device name): ").strip(),
                    "username": input("MQTT username (Enter = none): ").strip(),
                    "password": getpass.getpass("MQTT password (Enter = none): ")}
    else:
        key = getpass.getpass("Key / API key (Enter = none): ")
        if protocol == "http":
            header = input("Header line using {key} (Enter = none): ").strip()
    ca_file = input("CA certificate file: ").strip()
    save_cloud(args.port, pin, host, broker_port, load_ca(ca_file), topic,
               cred["client_id"], cred["username"], cred["password"], fields, protocol, key, header)


def cmd_cloudtest(args):
    r = run(args.port, "import xnet\n"
        'print("XPY:" + json.dumps(xnet.cloud_test()))')
    print(f"Test message sent to {r}")


def cmd_netca(args):
    """Once: make the network CA (keys/net_ca.key, server/ca.crt) and the PC server's
    certificate (server/broker.key, server/broker.crt, name "xpython-broker"), used by the
    local broker and the OTA update server for mutual TLS. Existing files are kept."""
    import datetime as dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    server = ROOT / "server"
    KEYS.mkdir(exist_ok=True)
    server.mkdir(exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)

    def save_key(path, key):
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        path.chmod(0o600)

    ca_key_path, ca_crt_path = KEYS / "net_ca.key", server / "ca.crt"
    if ca_key_path.exists() and ca_crt_path.exists():
        print("network CA: exists, kept")
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())
    elif ca_crt_path.exists():
        sys.exit("The network CA's secret key keys/net_ca.key is missing (only server/ca.crt is here).\n"
                 "Copy keys/net_ca.key from the PC where you created it: a certificate alone can't sign.")
    else:
        rebuild = ca_key_path.exists()          # key kept, certificate lost: make it again from the key
        ca_key = (serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None) if rebuild
                  else ec.generate_private_key(ec.SECP256R1()))
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "xPython network CA")])
        ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
        ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                   .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                                  critical=True)
                   .add_extension(ski, critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
                                  critical=False)
                   .sign(ca_key, hashes.SHA256()))
        ca_crt_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        if rebuild:
            print(f"network CA: certificate rebuilt from {ca_key_path} ({ca_crt_path}). Same key and name,\n"
                  "so the boards' TLS certificates and the CA saved on them stay valid.")
        else:
            save_key(ca_key_path, ca_key)
            print(f"network CA: created ({ca_key_path}, {ca_crt_path}), valid 10 years")

    key_path, crt_path = server / "broker.key", server / "broker.crt"
    if key_path.exists() and crt_path.exists():
        print("server certificate: exists, kept")
        return
    key = ec.generate_private_key(ec.SECP256R1())
    crt = (x509.CertificateBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "xpython-broker")]))
           .issuer_name(ca_cert.subject).public_key(key.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=825))
           .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("xpython-broker")]), critical=False)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                          critical=False)
           .sign(ca_key, hashes.SHA256()))
    save_key(key_path, key)
    crt_path.write_bytes(crt.public_bytes(serialization.Encoding.PEM))
    print(f"server certificate: created ({crt_path}, name xpython-broker), valid about 2 years")
    print("Keep keys/net_ca.key and server/broker.key private, and back them up.")


def cmd_netcert(args, pin=None, resume=False):
    """Give the device a TLS certificate from the network CA (for mutual TLS)."""
    import datetime as dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    st = device_status(args.port, resume)
    if not st["id"]:
        sys.exit("Provision the device first.")
    pin = pin or getpass.getpass("SO PIN: ")
    name = "xpy-" + st["id"][:12]                       # also its MQTT name and topic prefix

    # 1. The device makes its TLS key pair and sends only the public key
    pub_hex = run(args.port, "import xnet\n"
                  f'print("XPY:" + json.dumps(xnet.tls_keygen({pin!r}).hex()))', resume)
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
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))

    # 3. Install it on the device; keep a copy in the register
    der = cert.public_bytes(serialization.Encoding.DER)
    run(args.port, "import xnet\n"
        f"xnet.set_tls_cert({pin!r}, bytes.fromhex({der.hex()!r}))\n"
        'print("XPY:1")', resume)
    DEVICES.mkdir(exist_ok=True)
    (DEVICES / f"{st['id']}-tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"TLS certificate issued: CN={name}, valid 2 years (devices/{st['id']}-tls.crt)")
    

def cmd_gateway(args):
    """Make this board a gateway, a device that sends through a gateway, or neither."""
    pin = getpass.getpass("SO PIN: ")
    gw = (getattr(args, "gateway_id", "") or "").strip()
    devices = (getattr(args, "devices", "") or "").strip()
    if args.value == "device" and not gw:
        gw = input("Gateway ID (run 'gwstatus' on the gateway board to see it): ").strip()
    link = getattr(args, "link", "espnow") or "espnow"
    r = run(args.port, "import xgate\n"
        f"print('XPY:' + json.dumps(xgate.configure({pin!r}, {args.value!r}, {gw!r}, {devices!r}, {link!r})))")
    if r["role"] == "device":
        if r.get("link") == "wifi":
            print(f"This board is now a DEVICE: its apps send through gateway {r['gateway'][:12]}... over Wi-Fi (UDP).")
            print("It needs the Wi-Fi of the gateway's network saved (Network tab), but no cloud services.")
        else:
            print(f"This board is now a DEVICE: its apps send through gateway {r['gateway'][:12]}... over ESP-NOW.")
            print("It needs no Wi-Fi.")
        print("Lock it (dev mode off) and restart to start.")
    elif r["role"] == "gateway":
        who = ", ".join(r["devices"]) if r["devices"] else "every device certified by your vendor key"
        print(f"This board is now a GATEWAY (listens on ESP-NOW and on Wi-Fi). It accepts: {who}.")
        print("It needs Wi-Fi and the cloud services the devices' apps use. Lock it and restart to start.")
    else:
        print("Gateway role removed: the board uses its own Wi-Fi again.")


def cmd_gwstatus(args):
    r = run(args.port, "import xgate\nd = xinit.device_id()\n"
        "print('XPY:' + json.dumps({'id': d.hex() if d else None, 'cfg': xgate.config()}))")
    cfg = r["cfg"]
    print(f"board ID : {r['id'] or '-'}")
    print(f"role     : {cfg.get('role', 'off')}")
    if cfg.get("role") == "device":
        print(f"gateway  : {cfg['gateway']}")
        print(f"link     : {cfg.get('link', 'espnow')}")
    if cfg.get("role") == "gateway":
        print(f"accepts  : {', '.join(cfg.get('devices') or []) or 'every device certified by your vendor key'}")


def cmd_gwdevices(args):
    """The devices that joined this gateway (read from the gateway board)."""
    d = run(args.port, 'import xgate\nprint("XPY:" + json.dumps(xgate.devices()))')
    if not d:
        print("No device has joined this gateway yet (or this board is not a gateway).")
    for k, v in sorted(d.items(), key=lambda kv: kv[1].get("last", ""), reverse=True):
        print(f"{k}  {v['link']:6}  {v['address']:21}  last joined {v['last']}  ({v['joins']} joins)")
    return d


# ---------- Wi-Fi networks (several saved, sealed on the board) ----------
def wifi_scan(port):
    """Networks the board sees, strongest first: [{"ssid", "rssi", "security", "saved"}]."""
    return run(port, 'import xnet\nprint("XPY:" + json.dumps(xnet.wifi_scan()))')


def wifi_saved(port):
    return run(port, 'import xnet\nprint("XPY:" + json.dumps(xnet.wifi_saved()))')


def wifi_add(port, pin, ssid, password):
    return run(port, f'import xnet\nprint("XPY:" + json.dumps(xnet.wifi_add({pin!r}, {ssid!r}, {password!r})))')


def wifi_remove(port, pin, ssid):
    return run(port, f'import xnet\nprint("XPY:" + json.dumps(xnet.wifi_remove({pin!r}, {ssid!r})))')


def wifi_connect(port, ssid=None):
    """Join the best saved network in range (or the saved one named). Returns wifi_status()."""
    return run(port, "import xnet\n"
               f"xnet.connect_wifi(ssid={ssid!r}, force=True)\n"
               'print("XPY:" + json.dumps(xnet.wifi_status()))')


def cmd_wifi(args):
    if args.action == "scan":
        for n in wifi_scan(args.port):
            print(f"{n['ssid']:32} {n['rssi']:4} dBm  {n['security']:10} {'saved' if n['saved'] else ''}")
    elif args.action == "list":
        print("\n".join(wifi_saved(args.port)) or "No Wi-Fi network saved.")
    elif args.action == "add":
        ssid = args.ssid or input("Wi-Fi name (SSID): ")
        saved = wifi_add(args.port, getpass.getpass("SO PIN: "), ssid, getpass.getpass("Wi-Fi password: "))
        print("Saved (sealed). Saved networks:", ", ".join(saved))
    elif args.action == "remove":
        saved = wifi_remove(args.port, getpass.getpass("SO PIN: "), args.ssid or input("Wi-Fi name (SSID): "))
        print("Deleted. Saved networks:", ", ".join(saved) or "none")
    elif args.action == "connect":
        st = wifi_connect(args.port, args.ssid or None)
        print(f"Connected to {st['ssid']}, IP {st['ip']}" if st.get("connected") else "Not connected.")


def main():
    parser = argparse.ArgumentParser(description="xPython security officer tool")
    parser.add_argument("--port", default=("COM3" if os.name == "nt" else "/dev/ttyUSB0"), help="device serial port")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, fn in [("keygen", cmd_keygen), ("status", cmd_status), ("boardinfo", cmd_boardinfo), ("netca", cmd_netca),
                    ("provision", cmd_provision), ("reset", cmd_reset),
                    ("unlock", cmd_unlock), ("netconfig", cmd_netconfig),
                    ("nettest", cmd_nettest), ("netcert", cmd_netcert),
                    ("cloudconfig", cmd_cloudconfig), ("cloudtest", cmd_cloudtest)]:
        sub.add_parser(name).set_defaults(fn=fn)
    for name, fn in [("devmode", cmd_devmode)]:
        p = sub.add_parser(name)
        p.add_argument("value", choices=["on", "off"])
        p.set_defaults(fn=fn)
    p = sub.add_parser("gateway", help="role: off, device (sends via a gateway) or gateway")
    p.add_argument("value", choices=["off", "device", "gateway"])
    p.add_argument("--gateway-id", default="", help="device: the gateway board's ID (32 hex)")
    p.add_argument("--devices", default="", help="gateway: allowed device IDs, comma-separated (empty = all)")
    p.add_argument("--link", default="espnow", choices=["espnow", "wifi"], help="device: how it reaches the gateway")
    p.set_defaults(fn=cmd_gateway)
    p = sub.add_parser("wifi", help="Wi-Fi networks: scan, list, add, remove, connect")
    p.add_argument("action", choices=["scan", "list", "add", "remove", "connect"])
    p.add_argument("ssid", nargs="?", default="")
    p.set_defaults(fn=cmd_wifi)
    sub.add_parser("gwstatus").set_defaults(fn=cmd_gwstatus)
    sub.add_parser("gwdevices", help="the devices that joined this gateway").set_defaults(fn=cmd_gwdevices)
    args = parser.parse_args()
    try:
        args.fn(args)
    except DeviceError as e:
        sys.exit(f"Device error: {e}")


if __name__ == "__main__":
    main()