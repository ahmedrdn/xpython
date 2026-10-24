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

VERSION = "0.1.1"
PERIOD_S = 10                         # pause between rounds of apps
WDT_MS = 2 * xloader.MAX_TIME_MS + 10000
LOG_MAX = 4096                        # start a new log after this many bytes
UNLOCK_WINDOW_MS = 3000
_log_path = "/xpy.log"
_open = open                          # the real open, saved before any app runs


def version():
    return VERSION


def set_log(path):
    global _log_path
    _log_path = path


def _log(record):
    line = json.dumps(record) + "\n"
    try:
        try:
            size = os.stat(_log_path)[6]
        except OSError:
            size = 0
        with _open(_log_path, "w" if size > LOG_MAX else "a") as f:
            f.write(line)
    except OSError:
        pass                          # logging must never stop the engine


def log():
    """The log as a list of records."""
    try:
        with _open(_log_path) as f:
            return [json.loads(l) for l in f.read().split("\n") if l]
    except OSError:
        return []


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


def start():
    """Called from boot.py. Returns at once in development mode (REPL open).
    Otherwise runs all installed apps forever and never returns (REPL locked)."""
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
    wdt = machine.WDT(timeout=WDT_MS) # last resort: reset if anything hangs
    while True:
        try:
            for app in xloader.list():
                wdt.feed()
                r = run_app(app)
                print(app + ":", r["status"], r["ms"], "ms")
                wdt.feed()
            for _ in range(PERIOD_S):
                time.sleep(1)
                wdt.feed()
        except BaseException as e:    # never fall through to the REPL
            _log({"app": "-", "status": "engine error: " + repr(e)})
            machine.reset()