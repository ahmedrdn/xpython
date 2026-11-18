# PC test: ThingsBoard update announcements over MQTT survive lost connections.
#  - a dead link (broker stops answering) is noticed and the board reconnects
#  - after reconnecting, the board asks for the current values, so a change made while it
#    was disconnected is not missed; the first answer after boot is only the start point
# CPython, plain TCP instead of TLS. Run: python3 tests/pc_test_announce_tb.py
import json, os, socket, struct, sys, threading, time, types
from pathlib import Path

for m in ("xcrypto", "xinit", "xsfs"):
    sys.modules[m] = types.ModuleType(m)
sys.modules["xcrypto"].random = os.urandom
sys.modules["xinit"].device_id = lambda: bytes(16)
time.ticks_ms = lambda: int(time.monotonic() * 1000)
time.ticks_diff = lambda a, b: a - b
time.ticks_add = lambda a, b: a + b
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "modules/xcomm"))
import xnet


class S:
    def __init__(self, s): self.s = s
    def fileno(self): return self.s.fileno()
    def write(self, b): self.s.sendall(b)
    def read(self, n):
        out = b""
        while len(out) < n:
            c = self.s.recv(n - len(out))
            if not c: break
            out += c
        return out
    def close(self): self.s.close()


ATTR = {"fw_update": 1, "app_update": 1}     # the shared attributes on ThingsBoard
B = {"silent": False, "conns": 0, "requests": 0, "live": None}
T = "v1/devices/me/attributes"


def pub(c, topic, payload):
    t = topic.encode()
    body = struct.pack(">H", len(t)) + t + payload
    c.sendall(bytes([0x30, len(body)]) + body)


def client(c):
    buf = b""
    c.settimeout(0.05)
    while True:
        try:
            d = c.recv(1024)
            if not d: return
            buf += d
        except socket.timeout:
            continue
        except OSError:
            return
        while len(buf) >= 2 and len(buf) >= 2 + buf[1]:
            pkt, buf = buf[:2 + buf[1]], buf[2 + buf[1]:]
            if B["silent"]:
                continue                          # a dead link: nothing comes back
            k = pkt[0] & 0xF0
            if k == 0x10: c.sendall(b"\x20\x02\x00\x00")
            elif k == 0x80: c.sendall(b"\x90\x03" + pkt[2:4] + b"\x00")
            elif k == 0xC0: c.sendall(b"\xd0\x00")
            elif k == 0x30:
                tl = struct.unpack(">H", pkt[2:4])[0]
                if pkt[4:4 + tl].decode() == T + "/request/1":
                    B["requests"] += 1
                    pub(c, T + "/response/1", json.dumps({"shared": ATTR}).encode())


def broker(srv):
    while True:
        c, _ = srv.accept()
        B["conns"] += 1
        B["live"] = c
        threading.Thread(target=client, args=(c,), daemon=True).start()


srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(4)
threading.Thread(target=broker, args=(srv,), daemon=True).start()
xnet.tls_connect = lambda port, cloud=None: S(socket.create_connection(("127.0.0.1", srv.getsockname()[1]), timeout=1))
xnet._online = lambda: None
xnet._load = lambda: {"services": {"updates": {"protocol": "mqtt", "host": "x", "port": 1, "ca": "", "topic": T}}}
xnet.MQTT_RETRY_S = 0.3

ok = True
def check(n, text, cond):
    global ok
    ok &= bool(cond)
    print(f"{n:2d} {'OK  ' if cond else 'FAIL'} {text}")

def poll(seconds):
    out = set()
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        out |= xnet.announced()
        time.sleep(0.05)
    return out

check(1, "boot: asks for the current values, but they are only the start point",
      poll(0.5) == set() and B["requests"] == 1)
ATTR["fw_update"] = 2
pub(B["live"], T, b'{"fw_update": 2}')
check(2, "live change -> fw", poll(0.5) == {"fw"})
xnet._ann["c"].keepalive = 1                  # short keepalive for the test
B["silent"] = True                            # the link dies without a FIN
ATTR["app_update"] = 7                        # ... and someone announces an app meanwhile
r = poll(2.5)
check(3, f"dead link noticed ({B['conns']} connections so far)", B["conns"] >= 2 or xnet._ann["c"] is None)
B["silent"] = False
r |= poll(2)
check(4, f"after reconnecting: the change made while away is seen: {r}", "app" in r and B["requests"] >= 2)
check(5, "and the old value is not news again", poll(0.5) == set())
print("ALL OK" if ok else "SOME FAILED")
