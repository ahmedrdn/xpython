# xgate: xPython Gateway (frozen into the firmware).
# The same firmware makes a board a DEVICE or a GATEWAY; only its settings decide.
#   device : no Wi-Fi of its own. Its apps' messages (xmsg.publish) go to the gateway
#            over ESP-NOW (direct ESP32-to-ESP32 radio), encrypted.
#   gateway: joined to Wi-Fi. It checks every device, then forwards the device's
#            messages to its own cloud services (the device never holds cloud secrets).
#
# Join: 4 short messages. Both sides prove who they are with the device certificate
# from provisioning (id + public key, signed by the vendor key), and both make fresh
# keys for every session (ECDHE: an old session stays secret even if a device key leaks).
#   1  device  -> gateway  HELLO    nonce | fresh public key | device certificate
#   2  gateway -> device   WELCOME  nonce | fresh public key | gateway certificate
#   3  device  -> gateway  PROOF    device signature over messages 1+2 (device key)
#   4  gateway -> device   DONE     gateway signature over messages 1+2
#   keys = HKDF(ECDH(fresh keys), salt = sha256(1+2)) -> a key for each direction + session ID
# Data: AES-256-GCM with a counter; the gateway refuses old counters (replays).
#
# Link: ESP-NOW (direct radio, no router) or Wi-Fi (UDP on the same Wi-Fi network as the
# gateway, port 4747). The protocol above is the same on both; the gateway listens on both.
import json
import time
import xcrypto
import xinit
import xkeys

VERSION = "0.4.2"
MAGIC = b"xg"
HELLO, WELCOME, PROOF, DONE, DATA, ACK, REJOIN, SEEN = 1, 2, 3, 4, 5, 6, 7, 8
BROADCAST = b"\xff" * 6
CERT_LABEL = b"xpy-devcert-v1"       # the same label xinit uses for device certificates
MAX_SESSIONS = 16                    # ESP-NOW allows 20 peers
PAUSE_MS = 60000                     # after a failed forward, drop that service's messages this long
LOW_MEMORY = 60000                   # bytes: below this, close MQTT connections before a forward
OUT_OF_MEMORY = (12, -203, -32512, -0x7F00 & 0xFFFF)   # ENOMEM, DNS out of memory, TLS alloc failed
MAX_DATA = 250 - 27                  # ESP-NOW frame 250 bytes - header 11 - tag 16
STEP_MS = 2000                       # wait for each join answer
ACK_MS = 3000                        # wait for the gateway to confirm a message
CHANNELS = range(1, 14)
PORT = 4747                          # UDP port of the gateway on Wi-Fi
_open = open


def version():
    return VERSION


# ---------- Settings (sealed, next to the network settings) ----------
def _path():
    import xnet
    return xnet._store() + "/gw.json"


_cfg = None                          # read once, until configure() changes it


def config():
    """{"role": "off" | "device" | "gateway", "gateway": <gateway ID hex>, "devices": [...],
    "link": "espnow" | "wifi" (device)}"""
    global _cfg
    if _cfg is None:
        try:
            with _open(_path()) as f:
                _cfg = json.loads(f.read())
        except (OSError, ValueError):
            _cfg = {"role": "off"}
    return _cfg


def role():
    return config().get("role", "off")


def link():
    """How a device reaches its gateway: "espnow" (default) or "wifi"."""
    return config().get("link", "espnow")


def configure(pin, role, gateway="", devices="", link="espnow"):
    """role "device": send through the gateway whose ID is given (its full ID, 32 hex),
    over link "espnow" (no router needed) or "wifi" (the device joins the Wi-Fi saved on it).
    role "gateway": accept devices certified by the vendor (only those listed, if any);
    it listens on ESP-NOW and Wi-Fi. role "off": back to normal. Needs the SO PIN."""
    xinit.verify_pin(pin)
    if role not in ("off", "device", "gateway"):
        raise ValueError("role must be off, device or gateway")
    if link not in ("espnow", "wifi"):
        raise ValueError("link must be espnow or wifi")
    cfg = {"role": role}
    if role == "device":
        cfg["link"] = link
        gateway = gateway.strip().lower()
        if len(gateway) != 32 or any(c not in "0123456789abcdef" for c in gateway):
            raise ValueError("gateway ID: 32 hex characters (the gateway board's device ID)")
        cfg["gateway"] = gateway
    if role == "gateway":
        ids = [d.strip().lower() for d in devices.split(",") if d.strip()]
        for d in ids:
            if len(d) < 12 or any(c not in "0123456789abcdef" for c in d):
                raise ValueError("device IDs: hex, at least 12 characters")
        cfg["devices"] = ids
    with _open(_path(), "w") as f:
        f.write(json.dumps(cfg))
    global _cfg, _obj
    _cfg, _obj = cfg, None              # takes full effect at the next restart
    return cfg


# ---------- Who am I (the provisioned identity) ----------
class Identity:
    """Device ID, public key and vendor signature; signs with the key that never leaves the chip."""

    def __init__(self, cert=None, sign=None, vendor=None):
        self.cert = cert or xinit.certificate()
        if self.cert is None:
            raise ValueError("no device certificate: provision this board first")
        self._sign = sign or (lambda data: xkeys.sign("device", data))
        self.vendor = vendor or xinit.anchor("vendor")
        self.id = self.cert[0]

    def sign(self, data):
        return self._sign(data)

    def blob(self):
        return self.cert[0] + self.cert[1] + self.cert[2]          # 16 + 65 + 64 bytes

    def check(self, blob):
        """A peer's certificate -> (id, public key); raises unless the vendor signed it."""
        cid, pub, sig = blob[:16], blob[16:81], blob[81:145]
        if not xcrypto.ecdsa_verify(self.vendor, CERT_LABEL + cid + pub, sig):
            raise ValueError("certificate not signed by our vendor")
        return cid, pub


# ---------- Frames ----------
def _frame(kind, body):
    return MAGIC + bytes([kind]) + body


def _kind(msg):
    if msg and len(msg) >= 3 and msg[:2] == MAGIC:
        return msg[2]
    return 0


def _hello(kind, nonce, eph_pub, me):
    return _frame(kind, nonce + eph_pub + me.blob())             # 3 + 16 + 65 + 145 = 229


def _parse_hello(msg):
    if len(msg) != 229:
        raise ValueError("bad join message")
    return msg[3:19], msg[19:84], msg[84:229]                    # nonce, eph_pub, certificate


def _keys(secret, transcript):
    okm = xcrypto.hkdf_sha256(secret, transcript, b"xpy-gw-v1", 68)
    return okm[:32], okm[32:64], okm[64:68]                      # up key, down key, session ID


def _iv(direction, ctr):
    return bytes([direction]) + bytes(7) + ctr.to_bytes(4, "big")


def _seal(kind, sid, key, direction, ctr, plain=b""):
    head = _frame(kind, sid + ctr.to_bytes(4, "big"))
    ct, tag = xcrypto.aes_gcm_encrypt(key, _iv(direction, ctr), plain, head)
    return head + ct + tag


def _open_frame(msg, key, direction):
    """-> (sid, ctr, plaintext); raises if forged or changed."""
    if len(msg) < 27:
        raise ValueError("short frame")
    head, ct, tag = msg[:11], msg[11:-16], msg[-16:]
    ctr = int.from_bytes(head[7:11], "big")
    return head[3:7], ctr, xcrypto.aes_gcm_decrypt(key, _iv(direction, ctr), ct, tag, head)


# ---------- The radio ----------
class EspNow:
    """ESP-NOW through MicroPython's espnow module."""

    def __init__(self):
        import network
        import espnow
        self.sta = network.WLAN(network.STA_IF)
        self.sta.active(True)
        self.e = espnow.ESPNow()
        self.e.config(rxbuf=2048)       # room for ~7 frames while the gateway is busy
        self.e.active(True)
        self._peers = set()

    def send(self, mac, msg):
        if mac not in self._peers:
            try:
                self.e.add_peer(mac)
            except OSError:
                pass                    # already a peer
            self._peers.add(mac)
        try:
            return self.e.send(mac, msg, True)
        except OSError:
            return False                # radio busy or peer gone: the caller retries

    def recv(self, ms):
        mac, msg = self.e.recv(ms)
        return (bytes(mac), bytes(msg)) if msg else (None, None)

    def forget(self, mac):
        if mac in self._peers:
            self._peers.discard(mac)
            try:
                self.e.del_peer(mac)
            except OSError:
                pass

    def channel(self, ch=None):
        if ch is None:
            return self.sta.config("channel")
        self.sta.config(channel=ch)

    def quiet(self):
        """Gateway: never doze, or ESP-NOW frames are missed."""
        try:
            self.sta.config(pm=self.sta.PM_NONE)
        except (AttributeError, ValueError, OSError):
            pass


class Udp:
    """Wi-Fi: the same frames as UDP packets (needs Wi-Fi to be connected).
    Addresses are (ip, port); "broadcast" goes to every board on the network."""
    channels = (None,)                  # no radio channels to try
    rounds = 3                          # Wi-Fi broadcasts are not acknowledged: try 3 times

    def __init__(self, port=PORT, to=PORT, bcast="255.255.255.255"):
        import socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.ai = socket.getaddrinfo                     # (works on the board and on the PC build)
        self.s.bind(self.ai("0.0.0.0", port)[0][-1])
        self.to, self.bcast = to, bcast

    def send(self, addr, msg):
        if addr == BROADCAST:
            addr = (self.bcast, self.to)
        try:
            self.s.sendto(msg, self.ai(addr[0], addr[1])[0][-1])
            return True
        except OSError:
            return False

    def recv(self, ms):
        self.s.settimeout(ms / 1000 if ms > 0 else 0)
        try:
            msg, addr = self.s.recvfrom(512)
        except OSError:
            return None, None
        if not isinstance(addr, tuple):                  # the PC build gives a raw sockaddr
            addr = (".".join(str(b) for b in addr[4:8]), addr[2] << 8 | addr[3])
        return tuple(addr), msg

    def forget(self, addr):
        pass

    def channel(self, ch=None):
        return None

    def quiet(self):
        pass


class Both:
    """Gateway: ESP-NOW and Wi-Fi at the same time. MAC addresses (bytes) go out by
    ESP-NOW, (ip, port) addresses by UDP."""

    def __init__(self, espnow, udp):
        self.e, self.u = espnow, udp

    def send(self, addr, msg):
        return (self.u if isinstance(addr, tuple) else self.e).send(addr, msg)

    def recv(self, ms):
        end = time.ticks_add(time.ticks_ms(), ms)
        while True:
            a, m = self.u.recv(0)                        # Wi-Fi: only what is already there
            if m:
                return a, m
            left = time.ticks_diff(end, time.ticks_ms())
            a, m = self.e.recv(max(0, min(10, left)))
            if m:
                return a, m
            if left <= 0:
                return None, None

    def forget(self, addr):
        (self.u if isinstance(addr, tuple) else self.e).forget(addr)

    def channel(self, ch=None):
        return self.e.channel(ch)

    def quiet(self):
        self.e.quiet()


# ---------- Device side ----------
class Device:
    def __init__(self, radio, me, gateway_id, channel=None):
        self.r, self.me = radio, me
        self.gw_id = gateway_id                     # 16 bytes, pinned at configuration
        self.ch = channel
        self.mac = self.sid = None

    def _wait(self, kind, mac, ms, ok=None):
        """Wait for a frame of this kind (from mac); ok(msg) can reject stale or forged ones."""
        end = time.ticks_add(time.ticks_ms(), ms)
        while time.ticks_diff(end, time.ticks_ms()) > 0:
            src, msg = self.r.recv(max(1, time.ticks_diff(end, time.ticks_ms())))
            if msg and _kind(msg) == kind and (mac is None or src == mac) and (ok is None or ok(msg)):
                return src, msg
        return None, None

    def _drain(self):
        """Throw away frames left over from earlier attempts."""
        while self.r.recv(1)[1]:
            pass

    def join(self):
        """Find the gateway (all Wi-Fi channels) and make a session. Returns the channel."""
        self.mac = self.sid = None
        priv, pub = xcrypto.ecdsa_keygen()
        hello = _hello(HELLO, xcrypto.random(16), pub, self.me)
        tag = xcrypto.sha256(hello)[:8]                 # the gateway echoes it in its WELCOME
        is_ours = lambda m: len(m) == 229 and m[11:19] == tag
        self._drain()
        chans = getattr(self.r, "channels", CHANNELS)
        order = ([self.ch] if self.ch in chans else []) + [c for c in chans if c != self.ch]
        order = order * getattr(self.r, "rounds", 1)
        for ch in order:
            if ch is not None:
                self.r.channel(ch)
            self.r.send(BROADCAST, hello)
            src, seen = self._wait(SEEN, None, 200)        # "heard you": stay on this channel
            if seen:
                src, welcome = self._wait(WELCOME, src, STEP_MS, is_ours)   # not a late one
                if welcome:
                    break
        else:
            raise OSError("no answer from the gateway on any channel (off, out of range, or it refused this device)")
        _, g_eph, g_cert = _parse_hello(welcome)
        g_id, g_pub = self.me.check(g_cert)
        if g_id != self.gw_id:
            raise ValueError("answer from a different gateway: " + g_id.hex())
        t = xcrypto.sha256(hello + welcome)
        self.r.send(src, _frame(PROOF, self.me.sign(b"xpy-join-dev" + t)))
        _, done = self._wait(DONE, src, STEP_MS,
                             lambda m: xcrypto.ecdsa_verify(g_pub, b"xpy-join-gw" + t, m[3:]))
        if not done:
            raise ValueError("gateway did not prove its identity")
        self.up, self.down, self.sid = _keys(xcrypto.ecdh(priv, g_eph), t)
        self.mac, self.ch, self.ctr = src, ch, 0
        return ch

    def send(self, plain):
        """Encrypted message to the gateway; True once the gateway confirms it."""
        if len(plain) > MAX_DATA:
            raise ValueError("message too long for the gateway link (max %d bytes)" % MAX_DATA)
        for attempt in range(3):
            if self.sid is None:
                self.join()
            self.ctr += 1
            self.r.send(self.mac, _seal(DATA, self.sid, self.up, 1, self.ctr, plain))
            end = time.ticks_add(time.ticks_ms(), ACK_MS)
            while time.ticks_diff(end, time.ticks_ms()) > 0:
                src, msg = self.r.recv(max(1, time.ticks_diff(end, time.ticks_ms())))
                if src != self.mac:
                    continue
                k = _kind(msg)
                if k == REJOIN and msg[3:7] == self.sid:
                    self.sid = None                  # the gateway lost our session
                    break
                if k == ACK:
                    try:
                        sid, ctr, _ = _open_frame(msg, self.down, 2)
                    except ValueError:
                        continue                     # not genuine: ignore
                    if sid == self.sid and ctr == self.ctr:
                        return True
            else:
                if attempt:                          # no answer twice: look for it again
                    self.sid = None
        raise OSError("gateway did not confirm the message")


# ---------- Gateway side ----------
class Gateway:
    def __init__(self, radio, me, allowed=(), forward=None):
        self.r, self.me = radio, me
        self.allowed = [a for a in allowed]
        self.forward = forward or _forward
        self.pending = {}        # mac -> (time, transcript, eph private, device id, device public, eph public)
        self.sessions = {}       # mac -> {"id", "sid", "up", "down", "last", "seen"}
        self.queue = []          # (device id, plaintext) waiting to be forwarded
        self.paused = {}         # service -> time until which its messages are dropped
        self.stats = {"joined": 0, "refused": 0, "forwarded": 0, "failed": 0}

    def _allowed(self, dev_id):
        h = dev_id.hex()
        return not self.allowed or any(h.startswith(a) for a in self.allowed)

    def handle(self, mac, msg):
        k = _kind(msg)
        try:
            if k == HELLO:
                self._hello(mac, msg)
            elif k == PROOF:
                self._proof(mac, msg)
            elif k == DATA:
                self._data(mac, msg)
        except ValueError as e:
            self.stats["refused"] += 1
            _log(mac, "refused: " + str(e))

    def _hello(self, mac, msg):
        nonce, d_eph, d_cert = _parse_hello(msg)
        self.r.send(mac, _frame(SEEN, b""))                  # quick answer before the slow checks
        p = self.pending.get(mac)
        if p and p[6] == msg:                                # the same HELLO again (a resend):
            self.r.send(mac, p[7])                           # the same WELCOME, not a new one
            return
        d_id, d_pub = self.me.check(d_cert)
        if not self._allowed(d_id):
            raise ValueError("device not in the gateway's list")
        priv, pub = xcrypto.ecdsa_keygen()
        # nonce = 8 random bytes + 8 bytes of sha256(HELLO): tells the device which HELLO this answers
        welcome = _hello(WELCOME, xcrypto.random(8) + xcrypto.sha256(msg)[:8], pub, self.me)
        self.pending[mac] = (time.ticks_ms(), xcrypto.sha256(msg + welcome), priv, d_id, d_pub, d_eph,
                             msg, welcome)
        self.r.send(mac, welcome)

    def _proof(self, mac, msg):
        p = self.pending.pop(mac, None)
        if p is None or time.ticks_diff(time.ticks_ms(), p[0]) > 3 * STEP_MS:
            raise ValueError("proof without a recent hello")
        _, t, priv, d_id, d_pub, d_eph = p[:6]
        if not xcrypto.ecdsa_verify(d_pub, b"xpy-join-dev" + t, msg[3:]):
            raise ValueError("device did not prove its identity")
        up, down, sid = _keys(xcrypto.ecdh(priv, d_eph), t)
        if mac not in self.sessions and len(self.sessions) >= MAX_SESSIONS:
            old = min(self.sessions, key=lambda m: self.sessions[m]["seen"])
            del self.sessions[old]
            self.r.forget(old)
        self.sessions[mac] = {"id": d_id, "sid": sid, "up": up, "down": down,
                              "last": 0, "seen": time.ticks_ms()}
        self.r.send(mac, _frame(DONE, self.me.sign(b"xpy-join-gw" + t)))
        self.stats["joined"] += 1
        _log(mac, "joined: " + d_id.hex()[:12])
        _remember(d_id, mac)

    def _data(self, mac, msg):
        s = self.sessions.get(mac)
        if s is None or msg[3:7] != s["sid"]:
            self.r.send(mac, _frame(REJOIN, msg[3:7]))
            return
        sid, ctr, plain = _open_frame(msg, s["up"], 1)        # raises if forged
        s["seen"] = time.ticks_ms()
        if ctr > s["last"]:                                  # new message
            s["last"] = ctr
            if len(self.queue) < 32:
                self.queue.append((s["id"], plain))
        # (an old counter is a resend or a replay: confirm again, forward nothing)
        self.r.send(mac, _seal(ACK, sid, s["down"], 2, ctr))

    def serve(self, ms):
        """Receive for about ms milliseconds; forward queued messages when the radio is quiet."""
        end = time.ticks_add(time.ticks_ms(), ms)
        while time.ticks_diff(end, time.ticks_ms()) > 0:
            mac, msg = self.r.recv(50)
            if msg:
                self.handle(mac, msg)
            elif self.queue:
                d_id, plain = self.queue.pop(0)
                try:
                    svc = json.loads(plain)[2] or "default"
                except (ValueError, IndexError, TypeError):
                    svc = "?"
                if time.ticks_diff(self.paused.get(svc, time.ticks_ms()), time.ticks_ms()) > 0:
                    self.stats["failed"] += 1           # this service keeps failing: drop, don't block
                    continue
                if feed:
                    feed()
                try:
                    self.forward(d_id, plain)
                    self.stats["forwarded"] += 1
                    self.paused.pop(svc, None)
                except Exception as e:
                    self.stats["failed"] += 1
                    self.paused[svc] = time.ticks_add(time.ticks_ms(), PAUSE_MS)
                    import gc
                    _log(None, "forward to '" + svc + "' failed: " + repr(e) +
                         " (its messages are dropped for %d s; free memory %d)" % (PAUSE_MS // 1000, gc.mem_free()))
                if feed:
                    feed()
                break                                   # one forward per call: let xexec feed the watchdog

    def status(self):
        d = dict(self.stats)
        d["sessions"] = [s["id"].hex()[:12] for s in self.sessions.values()]
        d["queued"] = len(self.queue)
        return d


def _pack(app, sub, payload, service):
    if isinstance(payload, bytes):
        payload = payload.decode()
    return json.dumps([app, sub, service or "", payload]).encode()


def _forward(dev_id, plain):
    """Default gateway action: publish to this gateway's own service of the same name."""
    import gc
    import xnet
    app, sub, service, payload = json.loads(plain)
    gc.collect()                                     # each TLS connection needs ~40 KB
    if gc.mem_free() < LOW_MEMORY:                   # not enough for one more: close the open
        xnet._close_client()                         # MQTT connections first (they reconnect)
        gc.collect()
    try:
        xnet.app_publish(app, sub, payload, service or None, device="xpy-" + dev_id.hex()[:12])
    except OSError as e:
        if not (e.args and e.args[0] in OUT_OF_MEMORY):
            raise
        xnet._close_client()                         # out of memory after all: free and retry once
        gc.collect()
        xnet.app_publish(app, sub, payload, service or None, device="xpy-" + dev_id.hex()[:12])


feed = None                          # xexec: the watchdog's feed(), called around every forward
_log_fn = None


# ---------- The devices that joined this gateway (sealed, for the GUI) ----------
def _devices_path():
    import xnet
    return xnet._store() + "/gw_devices.json"


def devices():
    """{device ID (12 hex): {"link": "espnow"|"wifi", "address": ..., "last": "YYYY-MM-DD HH:MM",
    "joins": n}} for every device that joined this gateway."""
    try:
        with _open(_devices_path()) as f:
            return json.loads(f.read())
    except (OSError, ValueError):
        return {}


def forget_devices(pin):
    """Clear the list (needs the SO PIN)."""
    xinit.verify_pin(pin)
    try:
        import os
        os.remove(_devices_path())
    except OSError:
        pass


def _remember(dev_id, addr):
    try:
        t = time.localtime()
        d = devices()
        k = dev_id.hex()[:12]
        e = d.get(k, {"joins": 0})
        e.update(link="wifi" if isinstance(addr, tuple) else "espnow", address=_who(addr),
                 last="%04d-%02d-%02d %02d:%02d UTC" % t[:5], joins=e["joins"] + 1)
        d[k] = e
        with _open(_devices_path(), "w") as f:
            f.write(json.dumps(d))
    except Exception:                           # a full disk must never stop the gateway
        pass


def _who(addr):
    """A MAC address (ESP-NOW) as hex, an (ip, port) address (Wi-Fi) as ip:port."""
    if isinstance(addr, tuple):
        return "%s:%d" % (addr[0], addr[1])
    return addr.hex()


def _log(mac, text):
    line = "xgate: " + (_who(mac) + " " if mac else "") + text
    print(line)
    if _log_fn:
        _log_fn(line)


# ---------- The system's single device/gateway object ----------
_obj = None


def _radio(kind="espnow"):
    """espnow: ESP-NOW. wifi: UDP (Wi-Fi must be up). both: the gateway's ESP-NOW + UDP."""
    if kind == "wifi":
        return Udp(PORT + 1)                 # a device: its own port; the gateway is on PORT
    if kind == "both":
        e = EspNow()
        try:
            return Both(e, Udp(PORT))
        except OSError as err:               # no Wi-Fi socket: ESP-NOW only
            _log(None, "Wi-Fi link off: " + repr(err))
            return e
    return EspNow()


def device():
    """This board's Device (role "device"), created on first use."""
    global _obj
    if _obj is None:
        cfg = config()
        if cfg.get("role") != "device":
            raise ValueError("this board is not set up as a device")
        _obj = Device(_radio(cfg.get("link", "espnow")), Identity(), bytes.fromhex(cfg["gateway"]),
                      cfg.get("channel"))
    return _obj


def gateway():
    """This board's Gateway (role "gateway"), created on first use (after Wi-Fi is up)."""
    global _obj
    if _obj is None:
        cfg = config()
        if cfg.get("role") != "gateway":
            raise ValueError("this board is not set up as a gateway")
        r = _radio("both")                   # devices may come by ESP-NOW or by Wi-Fi
        r.quiet()
        _obj = Gateway(r, Identity(), cfg.get("devices", ()))
    return _obj


def join():
    """Device: connect to the gateway now. Returns the Wi-Fi channel it was found on."""
    return device().join()


def send(app, sub, payload, service=None):
    """Device: called by xnet.app_publish() for every app message."""
    return device().send(_pack(app, sub, payload, service))


def serve(seconds):
    """Gateway: work for this many seconds (xexec calls it between app rounds)."""
    gateway().serve(seconds * 1000)


def status():
    if _obj is None:
        return {"role": role(), "active": False}
    if isinstance(_obj, Gateway):
        d = _obj.status()
        d["role"], d["channel"] = "gateway", _obj.r.channel()
        return d
    return {"role": "device", "joined": _obj.sid is not None, "channel": _obj.ch,
            "link": link(), "gateway": _who(_obj.mac) if _obj.mac else None}
