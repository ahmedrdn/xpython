# PC test of the Wi-Fi (UDP) link: real sockets on this PC, the gateway in a thread.
# Run: MICROPYPATH=modules/xcomm micropython tests/pc_test_xgate_wifi.py
import xcrypto, xgate, json, time, _thread
vendor_priv, vendor_pub = xcrypto.ecdsa_keygen()
def board(vendor=None):
    priv, pub = xcrypto.ecdsa_keygen(); i = xcrypto.random(16)
    sig = xcrypto.ecdsa_sign(vendor or vendor_priv, xgate.CERT_LABEL + i + pub)
    return xgate.Identity((i, pub, sig), lambda d: xcrypto.ecdsa_sign(priv, d), vendor_pub)
G, D = board(), board()
# real UDP sockets on this PC ("broadcast" to 127.0.0.1 stands in for the Wi-Fi network)
gw = xgate.Gateway(xgate.Udp(47470, bcast="127.0.0.1"), G)
got = []
gw.forward = lambda dev_id, plain: got.append(json.loads(plain))
stop = [False]
def serve():
    while not stop[0]:
        gw.serve(100)
_thread.start_new_thread(serve, ())
dev = xgate.Device(xgate.Udp(47471, to=47470, bcast="127.0.0.1"), D, G.id)
t = time.ticks_ms(); dev.join(); print("1 joined over UDP from", xgate._who(dev.mac), "in", time.ticks_diff(time.ticks_ms(), t), "ms (PC)")
for i in range(5):
    print("2 send", i, dev.send(xgate._pack("dht11", "telemetry", '{"t": %d}' % (20 + i), "ts_http")))
time.sleep_ms(500); print("3 forwarded:", len(got), got[-1])
print("4 status:", gw.status())
# attack: replay the device's last frame from another socket
spy = xgate.Udp(47472, to=47470, bcast="127.0.0.1")
dev2 = xgate.Device(xgate.Udp(47473, to=47470, bcast="127.0.0.1"), board(xcrypto.ecdsa_keygen()[0]), G.id)
try: dev2.join(); print("5 BAD: foreign board joined")
except (OSError, ValueError) as e: print("5 foreign board refused:", e)
stop[0] = True; time.sleep_ms(300)
