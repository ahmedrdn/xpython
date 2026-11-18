# rgb_c61: smooth colour fade on the RGB (WS2812 / NeoPixel) LED
# of the ESP32-C6 SuperMini.
#
# Board : ESP32-C6 SuperMini (firmware XPY_ESP32C6)
# Pin   : GPIO8 = one addressable WS2812 RGB LED
#         (GPIO15 is the plain status LED -> see app blink_c61)
#
# Each run (one per engine round, ~every 20 s):
#   - fades in from off to red,
#   - cross-fades red -> green -> blue -> red (passing through
#     yellow, cyan and magenta on the way),
#   - fades out to off (safe state),
#   - counts runs in /data/state.json and returns a short status string.
#
# Smoothness: each fade has STEPS small steps, STEP_MS apart
# (20 ms = 50 updates per second, which the eye sees as smooth).
# Run time: 5 fades * 40 steps * 20 ms = 4.0 s, limit time_ms = 8000.
#
# BRIGHT keeps the LED dim (0..255); WS2812s are very bright at 255.
# Note: the WS2812 chip draws a little current even when "off".

from machine import Pin
from neopixel import NeoPixel
import time
import json

LED_PIN = 8
BRIGHT = 40
STEPS = 40          # steps per fade
STEP_MS = 20        # pause between steps
STATE_FILE = "/data/state.json"

OFF = (0, 0, 0)
RED = (BRIGHT, 0, 0)
GREEN = (0, BRIGHT, 0)
BLUE = (0, 0, BRIGHT)

# The path the colour follows in one run.
PATH = (OFF, RED, GREEN, BLUE, RED, OFF)


def _load():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"runs": 0}


def _save(st):
    try:
        with open(STATE_FILE, "w") as f:
            f.write(json.dumps(st))
    except OSError:
        pass  # only a counter; the fade still worked


def _fade(np, a, b):
    # Linear blend from colour a to colour b in STEPS steps.
    for i in range(1, STEPS + 1):
        np[0] = (
            a[0] + (b[0] - a[0]) * i // STEPS,
            a[1] + (b[1] - a[1]) * i // STEPS,
            a[2] + (b[2] - a[2]) * i // STEPS,
        )
        np.write()
        time.sleep_ms(STEP_MS)


def main():
    np = NeoPixel(Pin(LED_PIN, Pin.OUT), 1)  # NeoPixel handles GRB order
    try:
        for k in range(len(PATH) - 1):
            _fade(np, PATH[k], PATH[k + 1])
    finally:
        np[0] = OFF  # always leave the LED off
        np.write()

    st = _load()
    st["runs"] = st.get("runs", 0) + 1
    _save(st)
    return "RGB GPIO%d faded R>G>B, run %d" % (LED_PIN, st["runs"])