# The ESP32 port's own manifest (ports/esp32/boards/manifest.py), with ONE change:
# _boot.py comes from this board folder, because xPython starts from it.
# If you update MicroPython, compare this list with ports/esp32/modules again.
freeze("$(PORT_DIR)/modules", ("apa106.py", "espnow.py", "flashbdev.py", "inisetup.py", "machine.py"))
module("_boot.py", base_path="$(BOARD_DIR)")
include("$(MPY_DIR)/extmod/asyncio")

# Useful networking-related packages.
require("bundle-networking")

# Require some micropython-lib modules.
require("aioespnow")
require("dht")
require("ds18x20")
require("neopixel")
require("onewire")
require("umqtt.robust")
require("umqtt.simple")
require("upysh")

# xPython modules written in Python: frozen into the firmware
for name in ("xfw", "xsfs", "xloader", "xexec", "xnet", "xota", "xmsg"):
    module(name + ".py", base_path="$(BOARD_DIR)/../../modules/" + name)
