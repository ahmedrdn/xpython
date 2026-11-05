# xPython _boot.py: replaces the ESP32 port's own _boot.py (frozen into the firmware).
# It mounts the file system like the original, then starts xPython at EVERY boot, so
# there is no boot.py to edit or delete: dev mode alone decides what happens.
import gc
import vfs
from flashbdev import bdev

try:
    if bdev:
        vfs.mount(bdev, "/")
except OSError:
    import inisetup

    inisetup.setup()

gc.collect()

# Block Ctrl-C right away on a locked board (dev mode off), before anything else runs;
# xexec opens it again only after a correct unlock PIN.
import micropython
import xinit

_locked = xinit.state() == "OPERATIONAL" and not xinit.dev_mode()
if _locked:
    micropython.kbd_intr(-1)
try:
    import xexec

    xexec.start()                    # never returns on a locked board
except Exception as e:
    print("xPython: start failed:", repr(e))
    if _locked:                      # never fall through to an open REPL on a locked board
        import time
        import machine

        time.sleep(10)
        machine.reset()
del _locked
gc.collect()
