# xota: xPython over-the-air firmware updates (frozen into the firmware).
# Streams a signed firmware into the other slot, verifies it, and confirms it
# after a self-test; an unconfirmed firmware is rolled back by the bootloader.
import json
import struct
import hashlib
try:
    import esp32
    import machine
except ImportError:          # the PC build has no OTA hardware
    esp32 = machine = None
import xcrypto
import xinit
import xnet
import xfw

VERSION = "0.4.0"
MAGIC = b"XFW1"
SIG_LABEL = b"xpy-fw-v1"
OTA_PORT = 8443
OTA_PATH = b"/firmware.xfw"           # older servers: one file for every board type


def _fw_path():
    """This board type's own file on the server: /firmware/XPY_ESP32C3.xfw, ..."""
    return b"/firmware/" + xfw.BOARD.encode() + b".xfw"
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
        if on_block:
            on_block()                          # e.g. feed the watchdog during a long download
        left -= n
    if sha.digest().hex() != h["sha256"]:
        raise ValueError("firmware hash mismatch")
    nxt.set_boot()                              # ESP-IDF also checks the secure-boot signature here


on_block = None                                 # called after every 4 KB written (xexec: wdt.feed)


# ---------- What was tried (survives the reboot; tells a rollback apart) ----------
def _note_path():
    return xnet._store() + "/ota.json"


def _note(value=None):
    """Read the note, or write it when value is given. {"trying": v} or {"bad": v}."""
    try:
        if value is None:
            with open(_note_path()) as f:
                return json.loads(f.read())
        with open(_note_path(), "w") as f:
            f.write(json.dumps(value))
    except (OSError, ValueError):
        return {}


def boot_check():
    """Called at boot after confirm(): if the firmware we tried is not the one running,
    it failed and the bootloader rolled back. Remember it, so it is not tried again."""
    n = _note()
    if "trying" in n:
        _note({"bad": n["trying"]} if n["trying"] != xfw.VERSION else {})
    return _note()


# ---------- Public functions ----------
def update(skip=None):
    """Check the update server; install a newer signed firmware into the other slot.
    Returns ("up to date", version), ("skipped", version), ("installed", version) or
    ("nothing published", version): the server has no firmware for this board type.
    skip: a version that already failed here (auto_update). Reboot to start it."""
    xnet.online()                               # Wi-Fi and clock only: no MQTT broker needed
    s = None
    for path in (_fw_path(), OTA_PATH):         # this board type's file; else the old shared one
        s = xnet.tls_connect(OTA_PORT)
        try:
            _http_get(s, path)
            break
        except OSError as e:
            s.close()
            s = None
            if "404" not in str(e):
                raise
    if s is None:
        return ("nothing published", xfw.VERSION)
    try:
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
        if h["version"] == skip:
            return ("skipped", skip)            # it failed its self-test here before
        _write_image(s, h)
        _note({"trying": h["version"]})
        return ("installed", h["version"])
    finally:
        s.close()


# ---------- App updates (apps the board already has; never new ones) ----------
APPS_INDEX = b"/apps/index.json"       # {"dht11": "1.1.0", ...}: what the server offers


def _get(path, out=None, limit=4096):
    """GET over mutual TLS from the update server. The body is returned, or written to
    the file `out` (at most `limit` bytes either way)."""
    s = xnet.tls_connect(OTA_PORT)
    try:
        _http_get(s, path)
        if out is None:
            body = s.read(limit + 1) or b""
            if len(body) > limit:
                raise ValueError("answer too long")
            return body
        buf = bytearray(1024)
        n = 0
        with open(out, "wb") as f:
            while True:
                r = s.readinto(buf)
                if not r:
                    break
                n += r
                if n > limit:
                    raise ValueError("package too large")
                f.write(buf[:r])
                if on_block:
                    on_block()
    finally:
        s.close()


def app_updates():
    """Ask the update server for newer versions of the INSTALLED apps and install them with
    xloader (signature with the app key, file hashes, newer version, same app ID).
    The server's list is only a hint: every package is checked in full.
    Returns [(app, result), ...]; [] = nothing newer."""
    import os
    import xloader
    have = {}
    for app in xloader.list():
        m = xloader.info(app)
        if m:
            have[app] = m["version"]
    if not have:
        return []                               # no apps: nothing to ask
    xnet.online()
    offer = json.loads(_get(APPS_INDEX))
    dl = xloader._root + "/.download.xpk"       # hidden from xloader.list(); checked by install()
    out = []
    for app in have:
        v = offer.get(app)
        try:
            if not isinstance(v, str) or _v(v) <= _v(have[app]):
                continue                        # not offered, or not newer
        except ValueError:
            out.append((app, "bad version on the server: " + str(v)))
            continue
        try:
            _get(b"/apps/" + app.encode() + b".xpk", out=dl, limit=xloader.MAX_PACKAGE)
            xloader.install(dl, expect=app)
            out.append((app, "installed " + xloader.info(app)["version"]))
        except Exception as e:                  # refused or broken: the old version stays
            out.append((app, "refused: " + str(e)))
        finally:
            try:
                os.remove(dl)
            except OSError:
                pass
    return out


def self_test():
    """Checks a new firmware must pass before it is kept."""
    return {
        "crypto": xcrypto.selftest(),
        "identity": xinit.state() == "OPERATIONAL",
        "fw anchor": xinit.anchor("fw") is not None,
        "test switch": not xfw.SELF_TEST_FAIL,
    }


def keep():
    """Keep the running firmware without the self-test (board not provisioned)."""
    if esp32 is not None:
        esp32.Partition.mark_app_valid_cancel_rollback()


def confirm():
    """Keep the running firmware if its self-test passes; otherwise reset,
    and the bootloader rolls back to the previous firmware."""
    checks = self_test()
    if all(checks.values()):
        esp32.Partition.mark_app_valid_cancel_rollback()
        return {"confirmed": xfw.VERSION, "checks": checks}
    print("xota: self-test FAILED", checks, "- rolling back")
    machine.reset()


def auto_update():
    """Boards in the field: check the update server; if there is a newer firmware that
    has not failed here before, install it and restart into it (self-test at boot)."""
    r = update(skip=_note().get("bad"))
    if r[0] == "installed":
        print("xota: installed", r[1], "- restarting")
        machine.reset()
    return r
