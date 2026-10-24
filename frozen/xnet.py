import xpolicy
try:
    import network
    import ntptime
except ImportError:                   # the PC build has no Wi-Fi
    network = ntptime = None
# xnet: xPython Network & Communication (frozen into the firmware).
# System code only: apps never import it (xpolicy forbids it).
# Stores network settings sealed, joins Wi-Fi, and talks MQTT over TLS,
# always checking the broker's certificate against the organization's CA.
import os
import time
import json
import socket
import ssl
import struct
import xcrypto
import xinit
import xsfs

VERSION = "0.4.0"
BROKER_NAME = "xpython-broker"       # the name inside the broker's certificate
_STORE = "/xsys"                      # sealed system storage (an xsfs mount)
_STORE_ROOT = "/.xsys"
_STORE_KEY = "xsys"
_open = open                          # the real open, saved before any app runs


def version():
    return VERSION


# ---------- Sealed settings ----------
def _store():
    try:
        os.stat(_STORE)
    except OSError:
        xsfs.mount(_STORE, key=_STORE_KEY, root=_STORE_ROOT)
    return _STORE


def _load():
    try:
        with _open(_store() + "/net.json") as f:
            return json.loads(f.read())
    except OSError:
        raise ValueError("network not configured (run xpy-officer netconfig)")


def configure(pin, ssid, password, broker, port, ca_der):
    """Save the network settings, sealed. Needs the SO PIN."""
    xinit.verify_pin(pin)
    cfg = {"ssid": ssid, "password": password, "broker": broker,
           "port": port, "ca": ca_der.hex()}
    with _open(_store() + "/net.json", "w") as f:
        f.write(json.dumps(cfg))


def config():
    """The settings without the password, for checking."""
    cfg = _load()
    return {"ssid": cfg["ssid"], "broker": cfg["broker"], "port": cfg["port"],
            "ca_bytes": len(cfg["ca"]) // 2}

# ---------- The device's TLS identity (mutual TLS) ----------
# A P-256 private key in SEC1 DER form is a fixed template around the raw key:
#   30 77 02 01 01 04 20 <private 32> a0 0a 06 08 <P-256 OID> a1 44 03 42 00 <public 65>
_SEC1_HEAD = b"\x30\x77\x02\x01\x01\x04\x20"
_SEC1_MID = b"\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\xa1\x44\x03\x42\x00"


def _seal_write(name, data):
    with _open(_store() + "/" + name, "wb") as f:
        f.write(data)


def _seal_read(name):
    try:
        with _open(_store() + "/" + name, "rb") as f:
            return f.read()
    except OSError:
        return None


def tls_keygen(pin):
    """Make the device's TLS key pair inside the device. Returns the public key."""
    xinit.verify_pin(pin)
    priv, pub = xcrypto.ecdsa_keygen()
    _seal_write("tls.key", _SEC1_HEAD + priv + _SEC1_MID + pub)
    _seal_write("tls.pub", pub)
    try:
        os.remove(_store() + "/tls.crt")        # an old certificate no longer matches
    except OSError:
        pass
    return pub


def set_tls_cert(pin, cert_der):
    """Install the certificate the network CA issued for this device's TLS key."""
    xinit.verify_pin(pin)
    pub = _seal_read("tls.pub")
    if pub is None:
        raise ValueError("no TLS key yet: run tls_keygen first")
    if pub not in cert_der:                     # the certificate must carry OUR public key
        raise ValueError("certificate does not match the device's TLS key")
    _seal_write("tls.crt", cert_der)


def has_tls_cert():
    return _seal_read("tls.crt") is not None

# ---------- Wi-Fi and time ----------
def connect_wifi(timeout_s=20):
    """Join the configured Wi-Fi. Returns the device's IP address."""
    cfg = _load()
    w = network.WLAN(network.STA_IF)
    w.active(True)
    if not w.isconnected():
        w.connect(cfg["ssid"], cfg["password"])
        t0 = time.time()
        while not w.isconnected():
            if time.time() - t0 > timeout_s:
                raise OSError("Wi-Fi connection timed out")
            time.sleep(0.2)
    return w.ifconfig()[0]


def sync_time():
    try:
        ntptime.settime()
        return True
    except Exception:
        return False

def tls_connect(port):
    """A TLS connection to the server: checks its certificate, shows ours (mutual TLS)."""
    cfg = _load()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=bytes.fromhex(cfg["ca"]))
    cert = _seal_read("tls.crt")
    if cert is not None:
        ctx.load_cert_chain(cert, _seal_read("tls.key"))
    addr = socket.getaddrinfo(cfg["broker"], port)[0][-1]
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect(addr)
    return ctx.wrap_socket(sock, server_hostname=BROKER_NAME)


# ---------- A minimal MQTT 3.1.1 client over TLS ----------
class MQTT:
    """connect, publish (QoS 0) and close; enough for telemetry."""

    def __init__(self, client_id, keepalive=60):
        cfg = _load()
        self._s = tls_connect(cfg["port"])

        # CONNECT: protocol "MQTT", level 4 (3.1.1), clean session, keepalive, client id
        cid = client_id.encode()
        variable = b"\x00\x04MQTT\x04\x02" + struct.pack(">H", keepalive)
        self._send(0x10, variable + struct.pack(">H", len(cid)) + cid)
        ack = self._s.read(4)                                  # CONNACK: 20 02 00 <code>
        if not ack or ack[0] != 0x20 or ack[3] != 0:
            raise OSError("MQTT connect refused: " + str(ack))

    def _send(self, kind, body):
        """Packet = type byte + 'remaining length' (7 bits per byte) + body."""
        n = len(body)
        header = bytearray([kind])
        while True:
            b = n % 128
            n //= 128
            header.append(b | 0x80 if n else b)
            if not n:
                break
        self._s.write(bytes(header) + body)

    def publish(self, topic, payload):
        t = topic.encode()
        if isinstance(payload, str):
            payload = payload.encode()
        self._send(0x30, struct.pack(">H", len(t)) + t + payload)   # PUBLISH, QoS 0

    def close(self):
        try:
            self._s.write(b"\xe0\x00")                         # DISCONNECT
        finally:
            self._s.close()


def client_id():
    d = xinit.device_id()
    return "xpy-" + (d.hex()[:12] if d else "unprovisioned")


def test(message="hello"):
    """Join Wi-Fi, connect to the broker over TLS, publish one message."""
    ip = connect_wifi()
    sync_time()
    cid = client_id()
    c = MQTT(cid)
    topic = "xpy/" + cid + "/test"
    c.publish(topic, message)
    c.close()
    return ip, topic

# ---------- The network service for apps (xmsg.publish) ----------
_client = None                        # one TLS connection, shared and reused


def _get_client():
    global _client
    if _client is None:
        connect_wifi()
        # Certificates have validity dates, so the clock must be right before TLS
        if not sync_time() and time.localtime()[0] < 2025:
            raise OSError("clock not set: internet time (NTP) not reachable")
        _client = MQTT(client_id())
    return _client


def publish(topic, payload):
    """System publish, reconnecting once if the connection dropped."""
    global _client
    for attempt in range(2):
        try:
            _get_client().publish(topic, payload)
            return
        except OSError:
            try:
                if _client is not None:
                    _client.close()
            except OSError:
                pass
            _client = None
            if attempt:
                raise


def connect():
    """Open the shared connection now (e.g. at boot), so apps publish quickly."""
    _get_client()


def app_publish(app, sub, payload):
    """Called by xmsg.publish (in C) after the policy check."""
    if not isinstance(payload, (str, bytes)):
        raise TypeError("payload must be str or bytes")
    topic = "xpy/" + client_id() + "/" + app + "/" + sub
    publish(topic, payload)
    return topic


xpolicy.set_publisher(app_publish)    # register the service at import