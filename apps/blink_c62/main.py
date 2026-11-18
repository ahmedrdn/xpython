# blink_c61: toggle the plain status LED of the ESP32-C6 SuperMini.
#
# Board : ESP32-C6 SuperMini (firmware XPY_ESP32C6)
# Pin   : GPIO15 = plain single-colour status LED
#         (GPIO8 is the RGB WS2812 LED -> see app rgb_c61)
#
# Each run (one per engine round, ~every 20 s):
#   - toggles the LED TOGGLES times, PERIOD_MS apart (visible blinking),
#   - leaves the LED OFF (safe state),
#   - counts runs in /data/state.json and returns a short status string.
# Worst-case run time: 10 * 250 ms = 2.5 s, limit time_ms = 5000.
#
# Polarity: most C6 SuperMini boards light this LED when GPIO15 is HIGH.
# If your board's LED is lit when the app says "off", set ACTIVE_HIGH = False.
#
# GPIO15 is a strapping pin, which only matters at reset; driving it as an
# output after boot is fine.

from machine import Pin
import time
import json

LED_PIN = 15
ACTIVE_HIGH = True
TOGGLES = 10        # 10 toggles = 5 on/off blinks
PERIOD_MS = 250
STATE_FILE = "/data/state.json"


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
        pass  # state is only a counter; blinking still worked


def main():
    on = 1 if ACTIVE_HIGH else 0
    off = 1 - on
    led = Pin(LED_PIN, Pin.OUT, value=off)
    lit = False
    try:
        for _ in range(TOGGLES):
            lit = not lit
            led.value(on if lit else off)
            time.sleep_ms(PERIOD_MS)
    finally:
        led.value(off)  # always leave the LED off

    st = _load()
    st["runs"] = st.get("runs", 0) + 1
    _save(st)
    return "GPIO%d toggled %dx, run %d" % (LED_PIN, TOGGLES, st["runs"])
