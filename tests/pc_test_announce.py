# PC test of cloud update announcements (xnet "updates" service). Plain TCP stands in for TLS.
# Run: python3 tests/pc_test_announce.py modules/xcomm
import sys, types, time, socket, threading, struct, os
for m in ("xcrypto", "xinit", "xsfs"):
    sys.modules[m] = types.ModuleType(m)
sys.modules["xcrypto"].random = os.urandom
sys.modules["xinit"].device_id = lambda: bytes(16)
time.ticks_ms = lambda: int(time.monotonic() * 1000)
time.ticks_diff = lambda a, b: a - b
time.ticks_add = lambda a, b: a + b
sys.path.insert(0, sys.argv[1])
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
    def readline(self):
        out = b""
        while not out.endswith(b"\n"):
            c = self.s.recv(1)
            if not c: break
            out += c
        return out
    def close(self): self.s.close()

def tls(port, cloud=None):
    s = socket.create_connection(("127.0.0.1", port)); return S(s)
xnet.tls_connect = tls
xnet._online = lambda: None

# --- tiny MQTT broker: CONNACK, SUBACK, PINGRESP, then pushes what we queue
push = []; pings = [0]; subs = []
def broker(srv):
    c, _ = srv.accept(); c.settimeout(0.05); buf = b""
    while True:
        try:
            d = c.recv(1024)
            if not d: return
            buf += d
        except socket.timeout:
            pass
        while len(buf) >= 2:
            n = buf[1]; pkt = buf[:2 + n]
            if len(pkt) < 2 + n: break
            buf = buf[2 + n:]
            k = pkt[0] & 0xF0
            if k == 0x10: c.sendall(b"\x20\x02\x00\x00")
            elif k == 0x80:
                tl = struct.unpack(">H", pkt[4:6])[0]; subs.append(pkt[6:6 + tl].decode())
                c.sendall(b"\x90\x03\x00\x01\x00")
            elif k == 0xC0: pings[0] += 1; c.sendall(b"\xd0\x00")
        while push:
            t, p = push.pop(0); t = t.encode()
            body = struct.pack(">H", len(t)) + t + p
            c.sendall(bytes([0x30, len(body)]) + body)
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
threading.Thread(target=broker, args=(srv,), daemon=True).start()
mport = srv.getsockname()[1]

T = "v1/devices/me/attributes"
xnet._load = lambda: {"services": {"updates": {"protocol": "mqtt", "host": "x", "port": mport, "ca": "", "topic": T, "username": "TOKEN"}}}
print("1 nothing yet:", xnet.announced(), "subscribed:", subs)
push.append((T, b'{"fw_update":1}')); time.sleep(0.3)
print("2 announcement (fw):", xnet.announced())
print("3 same again (no news):", xnet.announced())
push.append((T, b'{"fw_update":1}')); time.sleep(0.3)
print("4 same payload re-sent:", xnet.announced())
push.append((T, b'{"app_update":1}')); time.sleep(0.3)
print("5 app announcement:", xnet.announced())
xnet._ann["c"].keepalive = 1; time.sleep(0.6); xnet.announced(); time.sleep(0.2)
print("6 keepalive pings sent:", pings[0], "still fine:", xnet.announced() == set())

# --- HTTP: a server whose answer we change
answer = [b'{"shared":{"fw_update":1,"app_update":1}}']; paths = []
def http(srv):
    while True:
        c, _ = srv.accept(); req = c.recv(2048).decode(); paths.append(req.split()[1])
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(answer[0]) + answer[0]); c.close()
hs = socket.socket(); hs.bind(("127.0.0.1", 0)); hs.listen(4)
threading.Thread(target=http, args=(hs,), daemon=True).start()
xnet._ann_reset()
xnet._load = lambda: {"services": {"updates": {"protocol": "http", "host": "x", "port": hs.getsockname()[1], "ca": "", "key": "TOKEN",
                                               "topic": "/api/v1/{key}/attributes?sharedKeys=fw_update,app_update"}}}
xnet.POLL_S = 0.2
print("7 first read = starting point:", xnet.announced(), paths[-1])
print("8 too soon, no read:", xnet.announced(), len(paths))
time.sleep(0.25); print("9 unchanged:", xnet.announced())
answer[0] = b'{"shared":{"fw_update":1,"app_update":2}}'; time.sleep(0.25)
print("10 app_update changed:", xnet.announced())
hs.close(); time.sleep(0.25)
print("11 server gone, no crash:", xnet.announced())
xnet._ann_reset(); xnet._load = lambda: {"ssid": "x"}
print("12 no updates service:", xnet.announced())
