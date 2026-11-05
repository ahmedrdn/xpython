try:
    import network
    import ntptime
except ImportError:                   # the PC build has no Wi-Fi
    network = ntptime = None
# xnet: xPython Network & Communication (frozen into the firmware).
# Apps send data through xmsg.publish(); the system decides topic and format here.
# Stores network settings sealed, joins Wi-Fi, and talks MQTT over TLS,
# always checking the broker's certificate against the organization's CA.
import os
import time
import json
import socket
import ssl
import struct
import binascii
import xcrypto
import xinit
import xsfs

VERSION = "0.7.0"
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
    try:
        old = _load().get("cloud")              # keep the cloud settings, if any
        if old:
            cfg["cloud"] = old
    except ValueError:
        pass
    with _open(_store() + "/net.json", "w") as f:
        f.write(json.dumps(cfg))


def config():
    """The settings without the password, for checking."""
    cfg = _load()
    out = {"ssid": cfg.get("ssid"), "broker": cfg.get("broker"), "port": cfg.get("port"),
           "ca_bytes": len(cfg.get("ca", "")) // 2}
    if cfg.get("cloud"):
        out["cloud"] = _summary(_cloud(cfg))
    if cfg.get("services"):
        out["services"] = {n: _summary(_defaults(c)) for n, c in cfg["services"].items()}
    return out


def _summary(c):
    """A service's settings without its secrets."""
    return {"protocol": c["protocol"], "host": c["host"], "port": c["port"], "topic": c["topic"],
            "fields": c["fields"], "client_id": c["client_id"] or client_id(),
            "username": c["username"], "header": c["header"], "key_set": bool(c["key"]),
            "ca_bytes": len(c["ca"]) // 2}


# ---------- Cloud service: MQTT (TLS), HTTP (HTTPS) or CoAP (CoAPS = CoAP over DTLS) ----------
# The local broker settings above stay: OTA updates still use them.
#   protocol "mqtt", "http" or "coap"; the server's certificate is ALWAYS checked
#   topic    MQTT topic, HTTP path or CoAP path; {device} {app} {sub} {key} are filled in,
#            e.g. "xpy/{device}/{app}/{sub}" (MQTT), "/api/{key}/{sub}" (HTTP), "sensors/{device}" (CoAP)
#   fields   empty: the app's message is sent as it is (e.g. JSON).
#            "temperature,humidity": a JSON message {"temperature": 27, ...} is sent as
#            "field1=27&field2=64" (form fields, for services that want that format)
#   MQTT login: client_id, username, password (all optional)
#   HTTP/CoAP:  key (a secret, e.g. an API key) and, for HTTP, one header line using it,
#               e.g. "Authorization: Bearer {key}" or "X-API-Key: {key}"
# Several services can be kept under names (e.g. "tb_http", "tb_coap"). An app picks one
# with "service" in its signed app.json permissions; without it, the "default" service is used.
PROTOCOLS = ("mqtt", "http", "coap")


def _check_name(name):
    if not (0 < len(name) <= 15 and all(c.isalpha() or c.isdigit() or c == "_" for c in name)):
        raise ValueError("service name: 1-15 letters, digits or _")


def _check_cloud(host, port, topic, fields, protocol="mqtt", header=""):
    if protocol not in PROTOCOLS:
        raise ValueError("protocol must be mqtt, http or coap")
    if not host or not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError("host and port (1-65535) are needed")
    bad = ("<", " ", "\r", "\n") + (("+", "#") if protocol == "mqtt" else ())
    if not topic or len(topic) > 128 or any(c in topic for c in bad):
        raise ValueError("bad topic/path: " + str(topic))
    if protocol == "http" and not topic.startswith("/"):
        raise ValueError("an HTTP path starts with /")
    if header and (":" not in header or "\r" in header or "\n" in header):
        raise ValueError("bad header line (Name: value)")
    if fields and len(fields.split(",")) > 8:
        raise ValueError("at most 8 fields")


def configure_cloud(pin, host, port, ca_der, topic, client_id="", username="", password="",
                    fields="", protocol="mqtt", key="", header="", name="default"):
    """Save a cloud service (sent over a secure channel). Needs the SO PIN."""
    xinit.verify_pin(pin)
    _check_name(name)
    _check_cloud(host, port, topic, fields, protocol, header)
    cfg = _load()
    entry = {"protocol": protocol, "host": host, "port": port, "ca": ca_der.hex(),
             "topic": topic, "fields": fields.replace(" ", ""), "client_id": client_id,
             "username": username, "password": password, "key": key, "header": header}
    if name == "default":
        cfg["cloud"] = entry
    else:
        cfg.setdefault("services", {})[name] = entry
    _close_client()
    with _open(_store() + "/net.json", "w") as f:
        f.write(json.dumps(cfg))


def clear_cloud(pin, name="default"):
    """Forget a service ("default": app data goes back to the local broker)."""
    xinit.verify_pin(pin)
    cfg = _load()
    if name == "default":
        cfg.pop("cloud", None)
    else:
        cfg.get("services", {}).pop(name, None)
    _close_client()
    with _open(_store() + "/net.json", "w") as f:
        f.write(json.dumps(cfg))

# ---------- Interactive setup in the board REPL: xnet.setup() ----------
# Copy the files to the board first (they are deleted again at the end):
#   mpremote cp <CA certificate file> :/ca.pem
#   mpremote cp <MQTT credentials file> :/credentials.txt
def _ask(question, default=""):
    answer = input(question + (" [" + default + "]" if default else "") + ": ").strip()
    return answer or default


def _ask_secret(question, old):
    """Passwords: never shown; Enter keeps the saved one."""
    answer = input(question + (" [Enter = keep]" if old else "") + ": ").strip()
    return answer or old


def _yes(question):
    return input(question + " [Y/n]: ").strip().lower() in ("", "y", "yes")


def read_ca_file(path):
    """A certificate file (PEM text or DER bytes) -> DER bytes."""
    with _open(path, "rb") as f:
        data = f.read()
    if data[:1] == b"\x30":
        return data                                     # already DER
    text = data.decode()
    if "-----BEGIN CERTIFICATE-----" not in text:
        raise ValueError(path + " is not a certificate (PEM or DER)")
    body = text.split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0]
    return binascii.a2b_base64("".join(body.split()))


def read_credentials_file(path):
    """An MQTT credentials file (plain text "username = ..." lines, or mqtt_secrets.h)
    -> {"client_id", "username", "password"}."""
    found = {}
    with _open(path) as f:
        for line in f:
            low = line.lower()
            if '"' in line:
                value = line.split('"')[1]              # #define SECRET_MQTT_USERNAME "..."
            elif "=" in line:
                value = line.split("=", 1)[1]           # username = ...
            elif ":" in line:
                value = line.split(":", 1)[1]           # username: ...
            else:
                continue
            value = value.strip()
            for key, word in (("client_id", "client"), ("username", "user"), ("password", "pass")):
                if word in low and value and key not in found:
                    found[key] = value
                    break
    if not found:
        raise ValueError(path + ": no client ID, username or password found")
    for k in ("client_id", "username", "password"):
        found.setdefault(k, "")
    return found


def _remove(path):
    try:
        os.remove(path)
        print("  deleted", path)
    except OSError:
        pass


def setup():
    """Asks for the Wi-Fi and cloud service settings, checks them, and saves them sealed.
    Enter keeps the value shown in [brackets]."""
    print("xPython network setup. Press Enter to keep the value in [brackets].")
    pin = input("SO PIN (visible while typing): ").strip()
    xinit.verify_pin(pin)                                # stop at once on a wrong PIN
    try:
        cfg = _load()
    except ValueError:
        cfg = {"broker": "", "port": 8883, "ca": ""}     # no local broker yet

    print("\n-- Wi-Fi")
    cfg["ssid"] = _ask("Wi-Fi name", cfg.get("ssid", ""))
    cfg["password"] = _ask_secret("Wi-Fi password", cfg.get("password", ""))

    print("\n-- Cloud service (MQTT over TLS, HTTPS or CoAP over DTLS)")
    old = _cloud(cfg) if cfg.get("cloud") else {}
    protocol = _ask("Protocol (mqtt, http, coap)", old.get("protocol", "mqtt")).lower()
    default_port = {"mqtt": 8883, "http": 443, "coap": 5684}.get(protocol, 8883)
    host = _ask("Host", old.get("host", ""))
    port = int(_ask("Port", str(old.get("port", default_port))))
    topic = _ask("Topic or path ({device} {app} {sub} {key} are filled in)", old.get("topic", ""))
    fields = _ask("Field names, comma-separated (Enter = send the message as it is)",
                  old.get("fields", ""))
    key, header = old.get("key", ""), old.get("header", "")
    if protocol in ("http", "coap"):
        key = _ask_secret("Key / API key (Enter = none)", key)
    if protocol == "http":
        header = _ask("Header line using {key} (Enter = none)", header)
    _check_cloud(host, port, topic, fields, protocol, header)

    cred, cred_path = {"client_id": "", "username": "", "password": ""}, ""
    if protocol == "mqtt":
        found = [p for p in ("/credentials.txt", "/ts_credentials.txt") if _exists(p)]
        cred_path = _ask("Credentials file on the board (Enter = type them)", found[0] if found else "")
        if cred_path:
            cred = read_credentials_file(cred_path)
            print("  read client ID", cred["client_id"], "and username", cred["username"])
        else:
            cred = {"client_id": _ask("MQTT client ID (Enter = device name)", old.get("client_id", "")),
                    "username": _ask("MQTT username (Enter = none)", old.get("username", "")),
                    "password": _ask_secret("MQTT password", old.get("password", ""))}

    found = [p for p in ("/ca.pem", "/thingspeak_ca.pem") if _exists(p)]
    default_ca = found[0] if found else ("keep" if old.get("ca") else "/ca.pem")
    ca_path = _ask("CA certificate file on the board (or keep)", default_ca)
    ca_hex = old["ca"] if ca_path == "keep" else read_ca_file(ca_path).hex()

    cfg["cloud"] = {"protocol": protocol, "host": host, "port": port, "ca": ca_hex, "topic": topic,
                    "fields": fields.replace(" ", ""), "client_id": cred["client_id"],
                    "username": cred["username"], "password": cred["password"],
                    "key": key, "header": header}
    _close_client()
    with _open(_store() + "/net.json", "w") as f:
        f.write(json.dumps(cfg))
    print("\nSaved (sealed):", config())

    # The plain copies are not needed any more; the credentials file holds a password
    if cred_path:
        _remove(cred_path)
    if ca_path != "keep" and _yes("Delete " + ca_path + " from the board too?"):
        _remove(ca_path)

    if _yes("\nSend a test message now?"):
        try:
            print("  sent to", cloud_test())
        except Exception as e:
            print("  test failed:", type(e).__name__, e)


def _exists(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False

# ---------- Wi-Fi setup page (from a phone) ----------
# When the board cannot join its Wi-Fi at boot, xexec calls portal(): the board
# opens its own hotspot "xPython-<id>" (password "xpy-<first 8 hex of the device ID>",
# shown by xpy-officer status), and serves a page at http://192.168.4.1 where you
# pick the new Wi-Fi and type its password and the SO PIN. Then the board restarts.
PORTAL_MINUTES = 10                   # then restart and try the saved Wi-Fi again


def portal_names():
    """(hotspot name, hotspot password) of the setup page."""
    d = (xinit.device_id() or b"\x00" * 8).hex()
    return "xPython-" + d[:6], "xpy-" + d[:8]


def _unquote(s):
    """Decode a form value: '+' is a space, %XX is one byte."""
    s = s.replace("+", " ")
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "%" and i + 3 <= len(s):
            try:
                out.append(int(s[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.extend(s[i].encode())
        i += 1
    return out.decode()


def _parse_form(body):
    form = {}
    for part in body.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            form[_unquote(k)] = _unquote(v)
    return form


def _escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _page(networks, message=""):
    options = "".join('<option>' + _escape(n) + '</option>' for n in networks)
    return ("<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width'>"
            "<title>xPython Wi-Fi</title><style>body{font-family:sans-serif;max-width:420px;"
            "margin:24px auto;padding:0 16px}input,select,button{width:100%;padding:10px;"
            "margin:6px 0 14px;font-size:16px;box-sizing:border-box}.m{padding:10px;"
            "background:#FAECE7;border-radius:6px}</style></head><body>"
            "<h2>xPython Wi-Fi setup</h2>"
            + ("<p class='m'>" + _escape(message) + "</p>" if message else "") +
            "<form method='POST' action='/save'>"
            "Wi-Fi network<select name='ssid'>" + options + "<option value=''>other (type below)</option></select>"
            "Other network name<input name='other' placeholder='only if not in the list'>"
            "Wi-Fi password<input name='password' type='password'>"
            "SO PIN<input name='pin' type='password' inputmode='numeric'>"
            "<button>Save and restart</button></form></body></html>")


def _handle(method, path, body, networks):
    """One page request -> (html, saved?)."""
    if method != "POST" or path != "/save":
        return _page(networks), False
    form = _parse_form(body)
    ssid = form.get("other", "").strip() or form.get("ssid", "")
    if not ssid:
        return _page(networks, "Choose or type a Wi-Fi name."), False
    try:
        xinit.verify_pin(form.get("pin", ""))
    except ValueError as e:
        return _page(networks, str(e)), False     # e.g. "wrong PIN, 4 tries left"
    try:
        cfg = _load()
    except ValueError:
        cfg = {"broker": "", "port": 8883, "ca": ""}
    cfg["ssid"], cfg["password"] = ssid, form.get("password", "")
    with _open(_store() + "/net.json", "w") as f:
        f.write(json.dumps(cfg))
    return ("<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width'></head>"
            "<body style='font-family:sans-serif;margin:24px'><h2>Saved</h2><p>The board restarts "
            "now and joins <b>" + _escape(ssid) + "</b>. You can reconnect your phone to your "
            "normal Wi-Fi.</p></body></html>"), True


def _read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 4096:
        chunk = conn.recv(512)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    method, path = (lines[0].split(" ") + ["", ""])[:2]
    length = 0
    for line in lines[1:]:
        if line.lower().startswith("content-length:"):
            length = min(int(line.split(":", 1)[1]), 2048)
    while len(body) < length:
        chunk = conn.recv(512)
        if not chunk:
            break
        body += chunk
    return method, path, body.decode()


def portal(minutes=PORTAL_MINUTES):
    """Open the Wi-Fi setup hotspot and page. Restarts the board when done."""
    import machine
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    try:
        networks = sorted(set(n[0].decode() for n in sta.scan() if n[0]))
    except OSError:
        networks = []
    sta.active(False)
    name, key = portal_names()
    ap = network.WLAN(network.AP_IF)
    ap.active(True)
    ap.config(ssid=name, key=key, security=network.WLAN.SEC_WPA2)
    print("xPython: Wi-Fi setup page: join", name, "and open http://192.168.4.1")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 80))
    srv.listen(2)
    srv.settimeout(5)
    end = time.time() + minutes * 60
    saved = False
    while not saved and time.time() < end:
        try:
            conn, _ = srv.accept()
        except OSError:
            continue                              # no visitor in the last 5 s
        try:
            conn.settimeout(10)
            method, path, body = _read_request(conn)
            html, saved = _handle(method, path, body, networks)
            conn.send(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" + html.encode())
        except Exception as e:
            print("xPython: setup page:", repr(e))
        finally:
            conn.close()
    srv.close()
    ap.active(False)
    time.sleep(2)
    machine.reset()                               # start again with the new (or old) Wi-Fi


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

def tls_connect(port, cloud=None):
    """A TLS connection that always checks the server's certificate.
    Local broker: our CA, name xpython-broker, and we show our certificate (mutual TLS).
    Cloud broker: the cloud's CA and its real host name; it identifies us by password."""
    cfg = _load()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    if cloud:
        host, name, ca = cloud["host"], cloud["host"], cloud["ca"]
    else:
        host, name, ca = cfg["broker"], BROKER_NAME, cfg["ca"]
        if not host or not ca:
            raise ValueError("no cloud service or local broker configured")
        cert = _seal_read("tls.crt")
        if cert is not None:
            ctx.load_cert_chain(cert, _seal_read("tls.key"))
    ctx.load_verify_locations(cadata=bytes.fromhex(ca))
    addr = socket.getaddrinfo(host, port)[0][-1]
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect(addr)
    return ctx.wrap_socket(sock, server_hostname=name)


# ---------- A minimal MQTT 3.1.1 client over TLS ----------
class MQTT:
    """connect, publish (QoS 0) and close; enough for telemetry."""

    def __init__(self, client_id, keepalive=60, cloud=None):
        port = cloud["port"] if cloud else _load()["port"]
        self._s = tls_connect(port, cloud)

        # CONNECT: protocol "MQTT", level 4 (3.1.1), clean session, keepalive, client id
        # (+ username 0x80 and password 0x40, if the cloud broker uses them)
        flags = 0x02
        body = struct.pack(">H", keepalive) + _str(client_id)
        if cloud and cloud["username"]:
            flags |= 0x80
            body += _str(cloud["username"])
            if cloud["password"]:
                flags |= 0x40
                body += _str(cloud["password"])
        self._send(0x10, b"\x00\x04MQTT\x04" + bytes([flags]) + body)
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


def _str(s):
    """MQTT string: 2-byte length + UTF-8 bytes."""
    b = s.encode()
    return struct.pack(">H", len(b)) + b


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
_clients = {}                         # MQTT connections, one per service, kept open


def _online():
    """Wi-Fi up and the clock right (certificates have validity dates)."""
    if network is None:
        return                                    # PC build: the PC is online already
    connect_wifi()
    if time.localtime()[0] < 2025 and not sync_time():
        raise OSError("clock not set: internet time (NTP) not reachable")


def _service(cfg, name=None):
    """A service's settings (None/"default" = the main one); None means the local broker."""
    if name and name != "default":
        c = cfg.get("services", {}).get(name)
        if c is None:
            raise ValueError("no service named '" + name + "' on this device")
        return _defaults(c)
    return _cloud(cfg) if cfg.get("cloud") else None


def _get_client(name=None):
    key = name or "default"
    if key not in _clients:
        _online()
        cloud = _service(_load(), name)
        _clients[key] = MQTT(cloud["client_id"] or client_id(), cloud=cloud) if cloud else MQTT(client_id())
    return _clients[key]


def _close_client(name=None):
    """Close one service's MQTT connection, or all of them."""
    for key in ([name or "default"] if name is not None else [k for k in _clients]):
        c = _clients.pop(key, None)
        if c is not None:
            try:
                c.close()
            except OSError:
                pass


def publish(topic, payload, name=None):
    """Send over the service's protocol, retrying once on a network error."""
    cloud = _service(_load(), name)
    if cloud and cloud["protocol"] != "mqtt":
        _online()
        if cloud["protocol"] == "coap":
            return _coap_send(cloud, topic, payload)               # CoAP retransmits itself
        for attempt in range(2):
            try:
                return _http_send(cloud, topic, payload)
            except OSError:
                if attempt:
                    raise
    for attempt in range(2):
        try:
            _get_client(name).publish(topic, payload)
            return
        except OSError:
            _close_client(name or "default")
            if attempt:
                raise


def connect():
    """Get online at boot (MQTT: also open the main connection), so apps publish quickly."""
    cfg = _load()
    cloud = _service(cfg)
    if cloud and cloud["protocol"] == "mqtt" or not cloud and cfg.get("broker"):
        _get_client()
    else:
        _online()                     # HTTP/CoAP, or only named services: Wi-Fi + clock


def app_publish(app, sub, payload, service=None):
    """Called by xmsg.publish(): app is the running app's ID, service its chosen service."""
    if not isinstance(payload, (str, bytes)):
        raise TypeError("payload must be str or bytes")
    cloud = _service(_load(), service)
    if cloud:
        payload = _convert(cloud, payload)
    topic = _topic(app, sub, cloud)
    publish(topic, payload, service)
    return topic


def _cloud(cfg):
    """The main (default) service, with defaults filled in."""
    return _defaults(cfg["cloud"])


def _defaults(c):
    """A service's settings with defaults (older settings had a "channel" instead of a topic)."""
    c = dict(c)
    if "topic" not in c:
        c["topic"] = "channels/" + c.get("channel", "0") + "/publish"
    c.setdefault("protocol", "mqtt")
    c.setdefault("fields", "")
    for k in ("client_id", "username", "password", "key", "header"):
        c.setdefault(k, "")
    return c


# ---------- HTTPS: one POST per message ----------
def _content_type(cloud, payload):
    if cloud["fields"]:
        return "application/x-www-form-urlencoded"
    return "application/json" if payload[:1] in (b"{", b"[") else "text/plain"


def _http_send(cloud, path, payload):
    """POST over TLS (server certificate checked). Raises OSError unless 2xx."""
    if isinstance(payload, str):
        payload = payload.encode()
    path = path.replace("{key}", cloud["key"])
    head = ("POST " + path + " HTTP/1.1\r\nHost: " + cloud["host"] +
            "\r\nContent-Type: " + _content_type(cloud, payload) +
            "\r\nContent-Length: " + str(len(payload)) + "\r\nConnection: close\r\n")
    if cloud["header"]:
        head += cloud["header"].replace("{key}", cloud["key"]) + "\r\n"
    s = tls_connect(cloud["port"], cloud)
    try:
        s.write(head.encode() + b"\r\n" + payload)
        parts = s.readline().split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    finally:
        s.close()
    if not 200 <= code < 300:
        raise OSError("HTTP " + str(code))
    return code


# ---------- CoAPS: CoAP (RFC 7252) over DTLS, one confirmable POST per message ----------
_mid = [int.from_bytes(xcrypto.random(2), "big")]     # CoAP message ID, random start


def _coap_ext(n):
    """Option delta/length: 4-bit nibble + extended bytes."""
    if n < 13:
        return n, b""
    if n < 269:
        return 13, bytes([n - 13])
    return 14, bytes([(n - 269) >> 8, (n - 269) & 0xFF])


def _coap_packet(mid, path, payload, fmt):
    """CON POST with Uri-Path (11), Content-Format (12), Uri-Query (15) options."""
    out = bytearray([0x40, 0x02, (mid >> 8) & 0xFF, mid & 0xFF])   # ver 1, CON, TKL 0, 0.02
    pathpart, _, query = path.partition("?")
    opts = [(11, seg.encode()) for seg in pathpart.split("/") if seg]
    opts.append((12, bytes([fmt]) if fmt else b""))                # 0 = text/plain, 50 = JSON
    opts += [(15, q.encode()) for q in query.split("&") if q]
    last = 0
    for num, val in opts:
        d, dx = _coap_ext(num - last)
        l, lx = _coap_ext(len(val))
        out += bytes([(d << 4) | l]) + dx + lx + val
        last = num
    if payload:
        out += b"\xff" + payload
    return bytes(out)


def _coap_check(resp, mid):
    """True when resp acknowledges message mid with success; raises on an error reply."""
    if not resp or len(resp) < 4 or resp[0] >> 6 != 1:
        return False
    kind, code = (resp[0] >> 4) & 3, resp[1]
    if (resp[2] << 8 | resp[3]) != mid:
        return False                                  # not the answer to our message
    if kind == 3:
        raise OSError("CoAP: reset by the server")
    if kind == 2 and (code == 0 or code >> 5 == 2):
        return True                                   # ACK, empty or 2.xx success
    raise OSError("CoAP %d.%02d" % (code >> 5, code & 31))


def _coap_send(cloud, path, payload, timeout_s=3):
    if isinstance(payload, str):
        payload = payload.encode()
    path = path.replace("{key}", cloud["key"])
    fmt = 50 if _content_type(cloud, payload) == "application/json" else 0
    _mid[0] = (_mid[0] + 1) & 0xFFFF
    pkt = _coap_packet(_mid[0], path, payload, fmt)
    addr = socket.getaddrinfo(cloud["host"], cloud["port"], 0, socket.SOCK_DGRAM)[0][-1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    sock.connect(addr)
    ctx = ssl.SSLContext(ssl.PROTOCOL_DTLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=bytes.fromhex(cloud["ca"]))
    s = ctx.wrap_socket(sock, server_hostname=cloud["host"])      # DTLS handshake
    try:
        for attempt in range(3):                                   # CoAP retransmission
            try:
                s.send(pkt)                                        # one datagram
                if _coap_check(s.recv(512), _mid[0]):               # one datagram back
                    return "2.xx"
            except OSError as e:
                if "CoAP" in str(e):
                    raise                                          # the server said no
        raise OSError("CoAP: no acknowledgement from the server")
    finally:
        s.close()


def _convert(cloud, payload):
    """JSON {"temperature": 27, ...} -> "field1=27&..." when field names are set."""
    names = [n for n in cloud["fields"].split(",") if n]
    if not names:
        return payload
    try:
        data = json.loads(payload)
    except ValueError:
        return payload                                    # not JSON: sent as it is
    if not isinstance(data, dict):
        return payload
    parts = []
    for i, name in enumerate(names):
        if name in data:
            parts.append("field" + str(i + 1) + "=" + str(data[name]))
    return "&".join(parts)


def _topic(app, sub, cloud=None):
    """The system, not the app, decides the full topic."""
    if cloud:
        t = cloud["topic"]
        return t.replace("{device}", client_id()).replace("{app}", app).replace("{sub}", sub)
    return "xpy/" + client_id() + "/" + app + "/" + sub


def cloud_test(payload=None, name=None):
    """Officer's check: one message to a cloud service. Returns the topic."""
    cloud = _service(_load(), name)
    if cloud is None:
        raise ValueError("no cloud service configured")
    if payload is None:
        names = [n for n in cloud["fields"].split(",") if n]
        payload = json.dumps({(names[0] if names else "test"): 0})
    topic = _topic("test", "telemetry", cloud)
    publish(topic, _convert(cloud, payload), name)
    return topic
