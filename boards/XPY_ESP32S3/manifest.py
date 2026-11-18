# xPython on the ESP32-S3: the same frozen modules as XPY_ESP32 (one list, one place).
# The only difference is the board name inside the firmware's version label, so an S3
# only accepts S3 updates.
import os

here = os.getcwd()                                   # this board folder (set by the build)
board = os.path.basename(here)                       # "XPY_ESP32S3"
src = os.path.join(here, "..", "..", "modules", "xfota", "xfw.py")
gen = os.path.join(here, "_gen")
os.makedirs(gen, exist_ok=True)
with open(src) as f:
    text = f.read().replace("XPY-FW:XPY_ESP32:", "XPY-FW:" + board + ":")
with open(os.path.join(gen, "xfw.py"), "w") as f:
    f.write(text)

include("$(BOARD_DIR)/../XPY_ESP32/manifest.py", board_xfw=gen)
