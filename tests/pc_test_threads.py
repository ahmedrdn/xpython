# PC test of the system thread (xexec) and the network lock (xnet.LOCK). CPython, stubs.
# Run: python3 tests/pc_test_threads.py
import os, sys, threading, time, types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
time.ticks_ms = lambda: int(time.monotonic() * 1000)
time.ticks_diff = lambda a, b: a - b
time.ticks_add = lambda a, b: a + b
for m in ("xcrypto", "xsfs", "xinit", "xwatch", "xloader", "xota", "xkeys"):
    sys.modules[m] = types.ModuleType(m)
sys.modules["xcrypto"].random = os.urandom
sys.modules["xloader"].MAX_TIME_MS = 30000
sys.path[:0] = [str(ROOT / "modules/xcomm"), str(ROOT / "modules/xexec")]
import tempfile
import xnet, xgate, xexec
xexec.set_log(os.path.join(tempfile.mkdtemp(), "xpy.log"))
xexec.SYSTEM_STACK = 256 * 1024                    # CPython wants a bigger minimum than the ESP32

ok = True
def check(n, text, cond):
    global ok
    ok &= bool(cond)
    print(f"{n:2d} {'OK  ' if cond else 'FAIL'} {text}")

# ---------- the lock ----------
L = xnet.LOCK
with L:
    with L:                                       # re-entrant in the same thread
        inner = L.owner == threading.get_ident()
check(1, "re-entrant in one thread, free after", inner and L.owner is None)
order = []
def other():
    with L:
        order.append("other")
with L:
    t = threading.Thread(target=other); t.start(); time.sleep(0.2)
    order.append("main")                          # the other thread must still be waiting
t.join()
check(2, "another thread waits for the holder", order == ["main", "other"])
L.__enter__(); L.__enter__()                      # as if a time limit stopped an app inside
L.release_if_mine()
got = []
t = threading.Thread(target=lambda: (L.__enter__(), got.append(1), L.__exit__())); t.start(); t.join(1)
check(3, "release_if_mine frees a lock left by a stopped app", got == [1])

# ---------- publishes from two threads never overlap on one connection ----------
busy, overlaps, sent = [0], [0], [0]
class FakeClient:
    def publish(self, topic, payload):
        busy[0] += 1
        if busy[0] > 1:
            overlaps[0] += 1
        time.sleep(0.002)
        sent[0] += 1
        busy[0] -= 1
xnet._load = lambda: {"broker": "x"}
xnet._service = lambda cfg, name=None: None
xnet._clients["default"] = FakeClient()
def spam():
    for _ in range(100):
        xnet.publish("t", b"x")
ts = [threading.Thread(target=spam) for _ in range(3)]
[t.start() for t in ts]; [t.join() for t in ts]
check(4, f"300 publishes from 3 threads, overlaps: {overlaps[0]}", sent[0] == 300 and overlaps[0] == 0)

# ---------- the system thread ----------
served, calls = [0], [0]
def serve(s):
    served[0] += 1
    time.sleep(0.05)
xgate.serve = serve
def announced():
    calls[0] += 1
    if calls[0] == 3:
        raise OSError("cloud gone")               # must not kill the thread
    return {"app"} if calls[0] == 5 else set()
xnet.announced = announced
check(5, "no thread for an ESP-NOW device", xexec._start_system("device", False) is False)
check(6, "thread started for a gateway", xexec._start_system("gateway", True) is True)
time.sleep(2)
s = xexec._sys
check(7, "gateway served while 'apps run'", served[0] >= 5)
check(8, "announcement collected for the main loop", s["announced"] == {"app"})
check(9, "an error did not stop the thread", s["errors"] == 1 and calls[0] > 5)
check(10, "heartbeat is fresh", time.ticks_ms() - s["beat"] < 500 and s["running"])
print("ALL OK" if ok else "SOME FAILED")
