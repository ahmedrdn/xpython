# xota: xPython over-the-air firmware updates (frozen into the firmware).
# Streams a signed firmware into the other slot, verifies it, and confirms it
# after a self-test; an unconfirmed firmware is rolled back by the bootloader.
import json
import struct
import hashlib
import esp32
import machine
import xcrypto
import xinit
import xnet
import xfw

VERSION = "0.1.0"
MAGIC = b"XFW1"
SIG_LABEL = b"xpy-fw-v1"
OTA_PORT = 8443
OTA_PATH = b"/firmware.xfw"
BLOCK = 4096


def version():
    return VERSION


def _v(s):
    parts = s.split(".")
    if len(parts) != 3:
        raise ValueError("version must be x.y.z")
    return tuple(int(x) for x in parts)


def status():
    run = esp32.Partition(esp32.Partition.RUNNING)
    return {"firmware": xfw.VERSION, "running": run.info()[4],
            "next": run.get_next_update().info()[4]}


# ---------- Reading from the TLS stream ----------
def _read_exact(s, n):
    out = b""
    while len(out) < n:
        chunk = s.read(n - len(out))
        if not chunk:
            raise OSError("download interrupted")
        out += chunk
    return out


def _http_get(s, path):
    s.write(b"GET " + path + b" HTTP/1.0\r\nHost: xpython-broker\r\n\r\n")
    status_line = s.readline()
    code = int(status_line.split()[1])
    while s.readline() not in (b"\r\n", b"\n", b""):   # skip the headers
        pass
    if code != 200:
        raise OSError("update server: HTTP " + str(code))


# ---------- Checking the header ----------
def _verify_header(header, sig):
    pub = xinit.anchor("fw")
    if pub is None:
        raise ValueError("no firmware-signing anchor installed")
    if not xcrypto.ecdsa_verify(pub, SIG_LABEL + header, sig):
        raise ValueError("bad firmware signature")
    h = json.loads(header)
    if h.get("board") != xfw.BOARD:
        raise ValueError("firmware is for another board: " + str(h.get("board")))
    _v(h["version"])
    return h


# ---------- Writing the other slot ----------
def _write_image(s, h):
    nxt = esp32.Partition(esp32.Partition.RUNNING).get_next_update()
    size = h["size"]
    if size > nxt.info()[3]:
        raise ValueError("firmware too big for the slot")
    sha = hashlib.sha256()
    buf = bytearray(BLOCK)
    mv = memoryview(buf)
    block, left = 0, size
    while left > 0:
        n = min(BLOCK, left)
        got = 0
        while got < n:                          # fill this block from the stream
            r = s.readinto(mv[got:n])
            if not r:
                raise OSError("download interrupted")
            got += r
        sha.update(mv[:n])                      # hash only the real bytes
        for i in range(n, BLOCK):
            buf[i] = 0xFF                       # pad the last block like erased flash
        nxt.writeblocks(block, buf)             # erases, then writes 4 KB
        block += 1
        left -= n
    if sha.digest().hex() != h["sha256"]:
        raise ValueError("firmware hash mismatch")
    nxt.set_boot()                              # ESP-IDF also checks the secure-boot signature here


# ---------- Public functions ----------
def update():
    """Check the update server; install a newer signed firmware into the other slot.
    Returns ("up to date", version) or ("installed", version). Reboot to start it."""
    xnet.connect()                              # Wi-Fi and clock (system code)
    s = xnet.tls_connect(OTA_PORT)
    try:
        _http_get(s, OTA_PATH)
        head = _read_exact(s, 8)
        if head[:4] != MAGIC:
            raise ValueError("not an xPython firmware package")
        hlen = struct.unpack("<I", head[4:8])[0]
        if hlen > 1024:
            raise ValueError("bad header length")
        header = _read_exact(s, hlen)
        sig = _read_exact(s, 64)
        h = _verify_header(header, sig)
        if _v(h["version"]) <= _v(xfw.VERSION):
            return ("up to date", xfw.VERSION)  # stops here: nothing is downloaded
        _write_image(s, h)
        return ("installed", h["version"])
    finally:
        s.close()


def self_test():
    """Checks a new firmware must pass before it is kept."""
    return {
        "crypto": xcrypto.selftest(),
        "identity": xinit.state() == "OPERATIONAL",
        "fw anchor": xinit.anchor("fw") is not None,
        "test switch": not xfw.SELF_TEST_FAIL,
    }


def confirm():
    """Keep the running firmware if its self-test passes; otherwise reset,
    and the bootloader rolls back to the previous firmware."""
    checks = self_test()
    if all(checks.values()):
        esp32.Partition.mark_app_valid_cancel_rollback()
        return {"confirmed": xfw.VERSION, "checks": checks}
    print("xota: self-test FAILED", checks, "- rolling back")
    machine.reset()