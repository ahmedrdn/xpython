# The ESP32 port's own manifest (ports/esp32/boards/manifest.py), with ONE change:
# _boot.py comes from this board folder, because xPython starts from it.
# If you update MicroPython, compare this list with ports/esp32/modules again.
freeze("$(PORT_DIR)/modules", ("apa106.py", "espnow.py", "flashbdev.py", "inisetup.py", "machine.py"))
module("_boot.py", base_path=".")                    # this folder (also when XPY_ESP32C6 includes it)
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
# (folder, module): related modules share a folder
for folder, name in (("xsfs", "xsfs"), ("xloader", "xloader"), ("xexec", "xexec"),
                     ("xfota", "xota"),
                     ("xcomm", "xnet"), ("xcomm", "xmsg"), ("xcomm", "xgate")):
    module(name + ".py", base_path="../../modules/" + folder)
# xfw holds the version label "XPY-FW:<board>:<version>". Another board (XPY_ESP32C6) passes
# its own copy with its board name; the version itself always comes from modules/xfota/xfw.py.
module("xfw.py", base_path=options.board_xfw or "../../modules/xfota")
