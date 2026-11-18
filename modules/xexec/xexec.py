# xexec: xPython Execution Engine (frozen into the firmware).
# Runs apps with crash isolation, time limits and logging; at boot, runs all
# installed apps forever with the REPL locked (unless in development mode).
import gc
import os
import sys
import time
import json
import xinit
import xloader
import xwatch
import xnet
import xota
import xgate
try:
    import _thread
except ImportError:                   # a build without threads: everything in one loop
    _thread = None

VERSION = "0.7.3"
PERIOD_S = 0                          # no rest between rounds: the system thread does the board's jobs
FALLBACK_REST_S = 20                  # rest used only WITHOUT the system thread (gateway / announcements)
WDT_MS = 2 * xloader.MAX_TIME_MS + 10000
WDT_GATEWAY_MS = 180000
LOG_MAX = 4096                        # start a new log after this many bytes
UNLOCK_WINDOW_MS = 3000
UPDATE_EVERY_MS = 3600 * 1000         # boards with Wi-Fi ask the update server once an hour (firmware + apps)
ANNOUNCE_GAP_MS = 30 * 1000           # ... and sooner when the cloud announces one, at most every 30 s
SYSTEM_STACK = 16 * 1024              # the system thread's stack (TLS handshakes need room)
_log_path = "/xpy.log"
_log_lock = _thread.allocate_lock() if _thread else None
_open = open                          # the real open, saved before any app runs


def version():
    return VERSION


def set_log(path):
    global _log_path
    _log_path = path


def _log(record):
    line = json.dumps(record) + "\n"
    if _log_lock:                     # both threads log; wait at most about 1 s
        for _ in range(100):
            if _log_lock.acquire(0):
                break
            time.sleep(0.01)
        else:
            return
    try:
        try:
            size = os.stat(_log_path)[6]
        except OSError:
            size = 0
        with _open(_log_path, "w" if size > LOG_MAX else "a") as f:
            f.write(line)
    except OSError:
        pass                          # logging must never stop the engine
    finally:
        if _log_lock:
            _log_lock.release()


def log():
    """The log as a list of records."""
    try:
        with _open(_log_path) as f:
            return [json.loads(l) for l in f.read().split("\n") if l]
    except OSError:
        return []


# ---------- The system thread: works WHILE the apps run ----------
# Apps run one after another in the main thread (their time limits only work there).
# The system thread does the board's own jobs at the same time:
#   - a gateway serves its devices (receives, answers, forwards to the cloud)
#   - boards with Wi-Fi listen to the optional "updates" service (cloud announcements)
# Both threads use the network through xnet.LOCK, so they never share a connection.
_sys = {"beat": 0, "announced": set(), "running": False, "errors": 0}


def _system(role, online):
    _sys["running"] = True
    while True:
        _sys["beat"] = time.ticks_ms()
        try:
            if role == "gateway":
                xgate.serve(1)
            else:
                time.sleep(1)
            if online:
                a = xnet.announced()
                if a:
                    _sys["announced"] = _sys["announced"] | a
        except Exception as e:        # never let the thread die; slow down after errors
            _sys["errors"] += 1
            print("xPython: system thread:", repr(e))
            time.sleep(1)


def _start_system(role, online):
    """Start the system thread. False: no threads here (the old single loop is used)."""
    if _thread is None or (role != "gateway" and not online):
        return False
    try:
        _thread.stack_size(SYSTEM_STACK)
        _thread.start_new_thread(_system, (role, online))
        _thread.stack_size(0)
        return True
    except Exception as e:            # e.g. not enough memory for the stack
        _log({"app": "-", "status": "system thread not started: " + repr(e)})
        return False


def run_app(app):
    """Run one app. Never raises: every outcome is returned and logged."""
    gc.collect()
    free_before = gc.mem_free()
    t0 = time.ticks_ms()
    status, result = "ok", None
    try:
        result = xloader.run(app)
    except KeyboardInterrupt:
        status = "timeout" if xwatch.fired() else "interrupted"
    except MemoryError:
        status = "out of memory"
    except Exception as e:
        status = "crash: " + type(e).__name__ + ": " + str(e)
    xloader.cleanup()                 # make sure nothing is left active
    ms = time.ticks_diff(time.ticks_ms(), t0)
    gc.collect()
    record = {"app": app, "status": status, "ms": ms, "mem_kept": free_before - gc.mem_free()}
    _log(record)
    record["result"] = result
    return record


def _unlock_window():
    """For a few seconds after boot, accept one line: XPY-UNLOCK <pin>."""
    print("XPY: unlock window open")
    import select
    poll = select.poll()
    poll.register(sys.stdin, select.POLLIN)
    buf = ""
    deadline = time.ticks_add(time.ticks_ms(), UNLOCK_WINDOW_MS)
    while time.ticks_diff(deadline, time.ticks_ms()) > 0:
        if not poll.poll(50):
            continue
        ch = sys.stdin.read(1)
        if ch not in "\r\n":
            buf = (buf + ch)[-64:]
            continue
        if buf.startswith("XPY-UNLOCK "):
            try:                      # only ONE attempt per boot
                xinit.set_dev_mode(buf[11:], True)
                print("XPY: unlocked, development mode on")
                return True
            except ValueError as e:
                print("XPY: unlock failed:", e)
                return False
        buf = ""
    return False


_started = False


def start():
    """Called at every boot by the firmware's own _boot.py (no boot.py needed).
    Dev mode ON (or not provisioned): returns at once and the REPL is open.
    Dev mode OFF: runs all installed apps forever with the REPL locked."""
    global _started
    if _started:                      # e.g. an old boot.py calling it a second time
        return
    _started = True
    try:
        if xinit.state() == "OPERATIONAL":
            print("xPython:", xota.confirm())  # keep a new firmware only if its self-test passes
            n = xota.boot_check()     # did a firmware we tried roll back?
            if n.get("bad"):
                _log({"app": "-", "status": "update " + n["bad"] + " failed its self-test; kept " + __import__("xfw").VERSION})
        else:
            # Not provisioned (or LOCKED): the self-test would fail at every boot and the
            # board would restart forever. Such a board cannot receive a signed update,
            # so simply keep the running firmware.
            xota.keep()
    except Exception as e:
        _log({"app": "-", "status": "ota confirm: " + repr(e)})
    if xinit.state() != "OPERATIONAL" or xinit.dev_mode():
        print("xPython: development mode, REPL available")
        return
    import micropython
    import machine
    micropython.kbd_intr(-1)          # Ctrl-C no longer breaks into the REPL
    if _unlock_window():
        micropython.kbd_intr(3)
        return
    print("xPython: OPERATIONAL, REPL locked")
    role = xgate.role()
    if role == "device":              # app data goes to the gateway (ESP-NOW, or Wi-Fi + UDP)
        if xgate.link() == "wifi":
            try:
                xnet.connect_wifi()   # Wi-Fi, but still no cloud secrets on this board
            except Exception as e:    # no saved network in range: retried every round
                _log({"app": "-", "status": "Wi-Fi: " + repr(e)})
        try:
            xgate.join()
            print("xPython: device, joined the gateway by", xgate.link())
        except Exception as e:        # apps try again when they publish
            _log({"app": "-", "status": "gateway: " + repr(e)})
    else:
        try:
            xnet.connect_wifi()
        except Exception as e:        # no saved network in range: retried every round
            _log({"app": "-", "status": "Wi-Fi: " + repr(e)})
        try:
            xnet.connect()            # open the network early; apps publish quickly
        except Exception as e:
            _log({"app": "-", "status": "network: " + repr(e)})
        if role == "gateway":
            try:
                xgate.gateway()       # start listening (ESP-NOW on the Wi-Fi channel)
                print("xPython: gateway ready")
            except Exception as e:
                _log({"app": "-", "status": "gateway: " + repr(e)})
                role = "off"
    # last resort: reset if anything hangs. A gateway waits longer: forwarding to a cloud
    # that can't be reached (name lookup, TLS, one retry) can take a minute by itself.
    wdt = machine.WDT(timeout=WDT_MS if role != "gateway" else WDT_GATEWAY_MS)
    main_id = _thread.get_ident() if _thread else None
    stale_ms = (WDT_MS if role != "gateway" else WDT_GATEWAY_MS) - 10000

    def feed():
        """The main thread feeds the watchdog, but only while the system thread is alive:
        a hang in EITHER thread then resets the board. The system thread only beats."""
        if _thread and _thread.get_ident() != main_id:
            _sys["beat"] = time.ticks_ms()
        elif not _sys["running"] or time.ticks_diff(time.ticks_ms(), _sys["beat"]) < stale_ms:
            wdt.feed()

    xota.on_block = feed              # a long download must not trip the watchdog
    xgate.feed = feed
    xnet.feed = feed                  # joining Wi-Fi (several networks) can take a while
    next_update = time.ticks_ms()     # first check after the first round
    last_check = time.ticks_add(time.ticks_ms(), -ANNOUNCE_GAP_MS)
    announced = set()                 # the cloud said "new firmware"/"new app": check soon
    waiting = False                   # an announcement is waiting for the 30 s gap (printed once)
    wifi_role = role != "device" or xgate.link() == "wifi"
    online = wifi_role                # devices on ESP-NOW: no internet (updates over USB)
    if online:
        print("xPython: update announcements:", xnet.updates_service() or
              "none (no 'updates' service saved: hourly checks only)")
    threaded = _start_system(role, online)
    if threaded:
        print("xPython: system thread running (gateway/announcements work while apps run)")
    while True:
        if wifi_role:                 # lost or never found: look for a saved network again
            try:                      # (at most once a minute: xnet.RETRY_S)
                xnet.connect_wifi()
            except Exception as e:
                print("xPython: Wi-Fi:", e)
            feed()
        try:
            apps = xloader.list()
            for app in apps:
                feed()
                r = run_app(app)
                xnet.LOCK.release_if_mine()   # a time limit hit while it held the network
                print(app + ":", r["status"], r["ms"], "ms")
                feed()
            if _sys["announced"]:     # heard by the system thread while the apps ran
                heard, _sys["announced"] = _sys["announced"], set()
                announced |= heard
            due = time.ticks_diff(time.ticks_ms(), next_update) >= 0
            soon = time.ticks_diff(time.ticks_ms(), last_check) >= ANNOUNCE_GAP_MS
            if announced and not soon and not waiting:
                wait_s = (ANNOUNCE_GAP_MS - time.ticks_diff(time.ticks_ms(), last_check)) // 1000 + 1
                print("xPython: update announced:", " + ".join(sorted(announced)),
                      "(check in %d s)" % wait_s)
                waiting = True
            check = {"fw", "app"} if due else (announced if soon else set())
            if online and check:
                if not due:
                    print("xPython: update announced by the cloud:", " + ".join(sorted(check)))
                else:
                    next_update = time.ticks_add(time.ticks_ms(), UPDATE_EVERY_MS)
                announced = set()
                waiting = False
                last_check = time.ticks_ms()
                feed()
                if "app" in check:            # apps first: a new firmware restarts the board
                    try:
                        r = xota.app_updates()
                        print("xPython: app update check:", r or "up to date")
                        for app, result in r:
                            _log({"app": app, "status": "update: " + result})
                    except Exception as e:
                        print("xPython: app update check:", repr(e))
                    feed()
                if "fw" in check:
                    try:
                        r = xota.auto_update()   # restarts the board if it installed one
                        print("xPython: update check:", r[0], r[1])
                    except Exception as e:     # server not running, not configured, ...
                        print("xPython: update check:", repr(e))
                    feed()
            # No rest with the system thread: the next round starts at once. Without the
            # thread (no threads, or not enough memory) the old rest does the board's jobs.
            rest = PERIOD_S if threaded or (role != "gateway" and not online) else FALLBACK_REST_S
            if not apps:
                rest = max(rest, 1)   # nothing installed: don't spin
            for _ in range(rest):
                if role == "gateway" and not threaded:
                    xgate.serve(1)    # no thread: the rest time is spent serving the devices
                else:
                    time.sleep(1)
                feed()
                if online and not threaded:   # optional "updates" service: {"fw", "app"}
                    announced |= xnet.announced()
                    feed()
        except BaseException as e:    # never fall through to the REPL
            _log({"app": "-", "status": "engine error: " + repr(e)})
            machine.reset()