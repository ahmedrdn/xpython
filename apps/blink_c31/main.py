# blink_c3: toggles the on-board LED of an ESP32-C3 board once per second.
# Two kinds of C3 boards are common, both with the LED on GPIO8:
#   "rgb":   Espressif DevKitM-1 / DevKitC-02: an RGB "NeoPixel" (WS2812) LED
#   "plain": C3 "SuperMini" and similar: a plain blue LED that lights when the pin is LOW
# xexec runs apps in rounds: each run toggles for SECONDS seconds, then the engine rests
# (about 20 s) and runs it again. The LED is switched off during the rest.
import time
import machine

PIN = 8
KIND = "plain"        # "rgb" or "plain": if nothing lights up, try the other one
COLOR = (0, 40, 0)  # rgb only: dim green (0-255 per colour)
SECONDS = 20        # toggles per run (1 per second); stays under the 25 s time limit

if KIND == "rgb":
    import neopixel
    _led = neopixel.NeoPixel(machine.Pin(PIN), 1)

    def _set(on):
        _led[0] = COLOR if on else (0, 0, 0)
        _led.write()
else:
    _pin = machine.Pin(PIN, machine.Pin.OUT, value=1)

    def _set(on):
        _pin.value(0 if on else 1)   # LOW = on for this LED


def main():
    on = False
    for _ in range(SECONDS):
        on = not on
        _set(on)
        time.sleep(0.1)
    _set(False)
    return "toggled %d times on GPIO%d (%s)" % (SECONDS, PIN, KIND)
