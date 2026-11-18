# PC test of the gateway join + data protocol (fake radio, fake identities). Safe: never touches a board.
# Run: MICROPYPATH=modules/xcomm micropython tests/pc_test_xgate.py
import xcrypto, xgate, json
xgate.STEP_MS = 300; xgate.ACK_MS = 300
vpriv, vpub = xcrypto.ecdsa_keygen()
def ident(vendor_priv=vpriv):
    priv, pub = xcrypto.ecdsa_keygen(); i = xcrypto.random(16)
    sig = xcrypto.ecdsa_sign(vendor_priv, xgate.CERT_LABEL + i + pub)
    return xgate.Identity((i, pub, sig), lambda d: xcrypto.ecdsa_sign(priv, d), vpub)

class Radio:
    def __init__(s, air, mac, ch): s.air, s.mac, s.ch, s.inbox, s.gw = air, mac, ch, [], None; air.append(s)
    def send(s, mac, msg):
        for r in s.air:
            if r is not s and r.ch == s.ch and (mac == xgate.BROADCAST or mac == r.mac):
                if r.gw and not r.down: r.gw.handle(s.mac, msg)
                elif not r.down: r.inbox.append((s.mac, msg))
        return True
    def recv(s, ms): return s.inbox.pop(0) if s.inbox else (None, None)
    def forget(s, mac): pass
    def channel(s, ch=None):
        if ch is None: return s.ch
        s.ch = ch
    down = False

air = []
gr = Radio(air, b"G"*6, 6); dr = Radio(air, b"D"*6, 1)
gme, dme = ident(), ident()
gw = xgate.Gateway(gr, gme); gr.gw = gw
dev = xgate.Device(dr, dme, gme.id)
print("1 join on channel:", dev.join())
print("2 send:", dev.send(xgate._pack("dht11", "telemetry", '{"t":25}', "ts_http")), gw.queue[-1][1])
print("  counters", dev.ctr, gw.sessions[b"D"*6]["last"])
# replay: capture a DATA frame and resend it
frames=[]; orig=gr.gw.handle
def spy(mac,msg): frames.append(msg); orig(mac,msg)
gr.gw = type("x",(object,),{"handle":staticmethod(spy)})
dev.send(b'["a","s","","1"]'); n=len(gw.queue)
orig(b"D"*6, frames[-1]); print("3 replay forwarded again?", len(gw.queue) != n)
gr.gw = gw
# tamper
f = bytearray(frames[-1]); f[12] ^= 1; gw.handle(b"D"*6, bytes(f)); print("4 tampered refused:", gw.stats["refused"] == 1)
# gateway restart -> REJOIN -> rejoin & resend
gw2 = xgate.Gateway(gr, gme); gr.gw = gw2
print("5 after gateway restart:", dev.send(b'["a","s","","2"]'), gw2.stats["joined"], len(gw2.queue))
# wrong gateway (another certified board) must be refused by the device
evil = xgate.Gateway(gr, ident()); gr.gw = evil; dev.sid = None
try: dev.join(); print("6 BAD")
except ValueError as e: print("6 other gateway refused:", e)
# device certified by another vendor must be refused by the gateway
gr.gw = gw2; opriv, _ = xcrypto.ecdsa_keygen(); bad = xgate.Device(dr, ident(opriv), gme.id)
try: bad.join(); print("7 BAD")
except (OSError, ValueError) as e: print("7 foreign device refused:", e, gw2.stats["refused"])
# allow-list
gw3 = xgate.Gateway(gr, gme, allowed=["abcdef"]); gr.gw = gw3; dev.sid=None
try: dev.join(); print("8 BAD")
except (OSError, ValueError) as e: print("8 not in list refused:", e)
# too long
try: dev.send(b"x"*300)
except ValueError as e: print("9", e)
# forward
got=[]; gw2.forward = lambda i,p: got.append((i.hex()[:6], json.loads(p))); gw2.serve(200); print("10 forwarded:", got, gw2.status())
print("frame sizes", len(xgate._hello(1, bytes(16), bytes(65), gme)))
