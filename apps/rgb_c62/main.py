# rgb_c61: toggle the RGB (WS2812 / NeoPixel) LED of the ESP32-C6 SuperMini.
#
# Board : ESP32-C6 SuperMini (firmware XPY_ESP32C6)
# Pin   : GPIO8 = one addressable WS2812 RGB LED
#         (GPIO15 is the plain status LED -> see app blink_c61)
#
# Each run (one per engine round, ~every 20 s):
#   - toggles the RGB LED on/off TOGGLES times, PERIOD_MS apart,
#   - every "on" uses the next colour (red, green, blue, ...),
#   - the start colour continues from the last run (kept in /data),
#   - leaves the LED OFF (safe state) and returns a short status string.
# Worst-case run time: 10 * 250 ms = 2.5 s, limit time_ms = 5000.
#
# BRIGHT keeps the LED dim (0..255); WS2812s are very bright at 255.
# Note: the WS2812 chip draws a little current even when "off".

from machine import Pin
from neopixel import NeoPixel
import time
import json

LED_PIN = 8
BRIGHT = 40
TOGGLES = 10        # 10 toggles = 5 coloured flashes
PERIOD_MS = 250
STATE_FILE = "/data/state.json"

COLOURS = (
    ("red", (BRIGHT, 0, 0)),
    ("green", (0, BRIGHT, 0)),
    ("blue", (0, 0, BRIGHT)),
)
OFF = (0, 0, 0)


def _load():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"runs": 0, "next": 0}


def _save(st):
    try:
        with open(STATE_FILE, "w") as f:
            f.write(json.dumps(st))
    except OSError:
        pass  # only a counter / colour index; blinking still worked


def _show(np, rgb):
    np[0] = rgb
    np.write()


def main():
    st = _load()
    idx = st.get("next", 0) % len(COLOURS)
    np = NeoPixel(Pin(LED_PIN, Pin.OUT), 1)  # NeoPixel handles GRB order
    lit = False
    last = ""
    try:
        for _ in range(TOGGLES):
            lit = not lit
            if lit:
                last, rgb = COLOURS[idx]
                idx = (idx + 1) % len(COLOURS)
                _show(np, rgb)
            else:
                _show(np, OFF)
            time.sleep_ms(PERIOD_MS)
    finally:
        _show(np, OFF)  # always leave the LED off

    st["runs"] = st.get("runs", 0) + 1
    st["next"] = idx
    _save(st)
    return "RGB GPIO%d toggled %dx, last %s, run %d" % (
        LED_PIN, TOGGLES, last, st["runs"])
