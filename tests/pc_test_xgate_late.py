# PC test: a late WELCOME from an earlier join attempt must not break the next join.
# Run: MICROPYPATH=modules/xcomm micropython tests/pc_test_xgate_late.py
import xcrypto, xgate, json
xgate.STEP_MS = 300; xgate.ACK_MS = 300          # PC: answers come at once
vendor_priv, vendor_pub = xcrypto.ecdsa_keygen()  # we play the vendor

def board(vendor=None):                           # a provisioned board's identity
    priv, pub = xcrypto.ecdsa_keygen(); i = xcrypto.random(16)
    sig = xcrypto.ecdsa_sign(vendor or vendor_priv, xgate.CERT_LABEL + i + pub)
    return xgate.Identity((i, pub, sig), lambda d: xcrypto.ecdsa_sign(priv, d), vendor_pub)

class Radio:                                      # a pretend ESP-NOW radio
    def __init__(self, air, mac, ch):
        self.air, self.mac, self.ch, self.inbox, self.gw = air, mac, ch, [], None
        air.append(self)
    def send(self, mac, msg):
        for r in self.air:
            if r is not self and r.ch == self.ch and mac in (xgate.BROADCAST, r.mac):
                if r.gw: r.gw.handle(self.mac, msg)   # the gateway answers at once
                else: r.inbox.append((self.mac, msg))
        return True
    def recv(self, ms):
        return self.inbox.pop(0) if self.inbox else (None, None)
    def forget(self, mac): pass
    def channel(self, ch=None):
        if ch is None: return self.ch
        self.ch = ch

air = []
G, D = board(), board()                           # the gateway board, the device board
grad, drad = Radio(air, b"GGGGGG", 6), Radio(air, b"DDDDDD", 1)
gw = xgate.Gateway(grad, G); grad.gw = gw
dev = xgate.Device(drad, D, G.id)                 # the device knows the gateway's ID
# a late WELCOME from an earlier join attempt sits in the device's buffer
old = []
real = grad.send
grad.send = lambda mac, msg: (old.append((grad.mac, msg)) if xgate._kind(msg) == xgate.WELCOME else None) or real(mac, msg)
dev.join(); grad.send = real
print("joined once, stale welcome kept:", len(old))
drad.inbox[0:0] = [(grad.mac, xgate._frame(xgate.SEEN, b"")), old[0]]   # late SEEN + WELCOME
dev.sid = None
xgate.Device._drain = lambda self: None      # worst case: it arrives after the drain
print("join again ->", dev.join(), "refused:", gw.stats["refused"])
print("send:", dev.send(b'["a","s","","1"]'))
