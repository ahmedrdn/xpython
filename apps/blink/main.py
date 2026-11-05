import time
import machine

LED = machine.Pin(2, machine.Pin.OUT)   # the blue on-board LED of most ESP32 DevKit boards
TIMES = 10                              # blinks per run
DELAY = 0.25                            # seconds on, then seconds off


def main():
    for i in range(TIMES):
        LED.on()
        time.sleep(DELAY)
        LED.off()
        time.sleep(DELAY)
    return "blinked %d times" % TIMES
