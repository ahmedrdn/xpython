# PC test of the saved Wi-Fi networks in xnet (several networks, sealed; best one in range).
# CPython with a fake `network` module and a temporary folder instead of the sealed /xsys.
# Run: python3 tests/pc_test_wifi.py
import json, os, sys, tempfile, time, types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = tempfile.mkdtemp(prefix="xpy_wifi_")
time.ticks_ms = lambda: int(time.monotonic() * 1000)
time.ticks_diff = lambda a, b: a - b
time.ticks_add = lambda a, b: a + b

# ---------- fake radio: what is "in range" and the real passwords ----------
AIR = {}            # ssid -> (rssi, password)


class WLAN:
    connected = None

    def __init__(self, i): pass
    def active(self, *a): return True
    def scan(self):
        return [(s.encode(), b"\0" * 6, 6, rssi, 3, False) for s, (rssi, _) in AIR.items()]
    def connect(self, ssid, pw):
        WLAN.connected = ssid if ssid in AIR and AIR[ssid][1] == pw else None
        WLAN.tried.append(ssid)
    def isconnected(self): return WLAN.connected is not None
    def disconnect(self): WLAN.connected = None
    def ifconfig(self): return ("192.168.1.50", "", "", "")
    def config(self, k): return WLAN.connected
    def status(self, k): return AIR[WLAN.connected][0]


WLAN.tried = []
net = types.ModuleType("network"); net.WLAN = WLAN; net.STA_IF = 0
sys.modules["network"] = net
sys.modules["ntptime"] = types.ModuleType("ntptime")
for m in ("xcrypto", "xsfs"):
    sys.modules[m] = types.ModuleType(m)
sys.modules["xcrypto"].random = os.urandom
xinit = types.ModuleType("xinit")


def verify_pin(p):
    if p != "123456":
        raise ValueError("wrong PIN")


xinit.verify_pin = verify_pin
sys.modules["xinit"] = xinit
sys.path.insert(0, str(ROOT / "modules/xcomm"))
import xnet
xnet._store = lambda: TMP

ok = True


def check(n, text, cond):
    global ok
    ok &= bool(cond)
    print(f"{n:2d} {'OK  ' if cond else 'FAIL'} {text}")


def raises(fn, *a, **k):
    try:
        fn(*a, **k)
    except (OSError, ValueError) as e:
        return str(e)
    return None


# old single-network settings are still understood
Path(TMP, "net.json").write_text(json.dumps({"ssid": "Home", "password": "homepass1", "broker": "192.168.1.4",
                                             "port": 8883, "ca": ""}))
check(1, "old settings: one saved network", xnet.wifi_saved() == ["Home"])
check(2, "wrong PIN refused", raises(xnet.wifi_add, "000000", "Lab", "labpass12") == "wrong PIN")
check(3, "add a second network", xnet.wifi_add("123456", "Lab", "labpass12") == ["Lab", "Home"])
cfg = json.loads(Path(TMP, "net.json").read_text())
check(4, "saved as a list; old keys gone; broker kept",
      "ssid" not in cfg and len(cfg["networks"]) == 2 and cfg["broker"] == "192.168.1.4")
check(5, "password checks", raises(xnet.wifi_add, "123456", "X", "short") is not None)
check(6, "config() shows names only", xnet.config()["networks"] == ["Lab", "Home"] and "password" not in json.dumps(xnet.config()["networks"]))

AIR.update({"Home": (-70, "homepass1"), "Lab": (-45, "labpass12"), "Cafe": (-60, "x")})
scan = xnet.wifi_scan()
check(7, "scan: strongest first, saved marked",
      [n["ssid"] for n in scan] == ["Lab", "Cafe", "Home"] and scan[0]["saved"] and not scan[1]["saved"])
check(8, "joins the strongest saved network", xnet.connect_wifi(timeout_s=0.3) and WLAN.connected == "Lab")
WLAN.connected = None; WLAN.tried = []
AIR["Lab"] = (-45, "changed!!")                      # Lab's password changed: fall back to Home
xnet.connect_wifi(timeout_s=0.3, force=True)
check(9, "first fails -> next saved one", WLAN.tried == ["Lab", "Home"] and WLAN.connected == "Home")
check(10, "connect to one named network", xnet.connect_wifi(timeout_s=0.3, ssid="Home", force=True) and WLAN.connected == "Home")
WLAN.connected = None
AIR.clear(); AIR["Cafe"] = (-60, "x")
check(11, "no saved network in range", "in range" in (raises(xnet.connect_wifi, timeout_s=0.3) or ""))
WLAN.tried = []
check(12, "then waits RETRY_S (no scan, no join)", "next try" in (raises(xnet.connect_wifi) or "") and WLAN.tried == [])
AIR["Home"] = (-50, "homepass1")
check(13, "force=True tries at once", xnet.connect_wifi(timeout_s=0.3, force=True) and WLAN.connected == "Home")
check(14, "already connected: no new join", xnet.connect_wifi() == "192.168.1.50")
check(15, "status", xnet.wifi_status() == {"connected": True, "ssid": "Home", "ip": "192.168.1.50", "rssi": -50})
check(16, "delete one", xnet.wifi_remove("123456", "Lab") == ["Home"])
check(17, "delete unknown -> error", raises(xnet.wifi_remove, "123456", "Nope") is not None)
check(18, "broker change keeps the networks",
      (xnet.configure("123456", "", "", "10.0.0.2", 8883, b""), xnet.wifi_saved())[1] == ["Home"]
      and xnet.config()["broker"] == "10.0.0.2")
check(19, "re-adding moves it to the front", xnet.wifi_add("123456", "Lab", "labpass12") == ["Lab", "Home"]
      and xnet.wifi_add("123456", "Home", "homepass1") == ["Home", "Lab"])
for i in range(6):
    xnet.wifi_add("123456", f"N{i}", "")
check(20, "at most 8 saved", "at most" in (raises(xnet.wifi_add, "123456", "N9", "") or ""))
check(21, "no setup page left", not hasattr(xnet, "portal"))
print("ALL OK" if ok else "SOME FAILED")
