# blink_s3: toggles the on-board LED of an ESP32-S3 DevKitC-1 once per second.
# That LED is an RGB "NeoPixel" (WS2812), not a plain LED, so it needs the neopixel module.
# xexec runs apps in rounds: each run toggles for SECONDS seconds, then the engine rests
# (about 20 s) and runs it again. The LED keeps its last state during the rest.
import time
import machine
import neopixel

PIN = 48            # DevKitC-1 v1.0: GPIO48. If nothing lights up, try 38 (DevKitC-1 v1.1)
COLOR = (40, 0, 0)  # dim blue (0-255 per colour; 40 is bright enough and saves power)
SECONDS = 20        # toggles per run (1 per second); stays under the 25 s time limit

led = neopixel.NeoPixel(machine.Pin(PIN), 1)


def _set(on):
    led[0] = COLOR if on else (0, 0, 0)
    led.write()


def main():
    on = False
    for _ in range(SECONDS):
        on = not on
        _set(on)
        time.sleep(1)
    _set(False)                     # leave it off while the engine rests
    return "toggled %d times on GPIO%d" % (SECONDS, PIN)
