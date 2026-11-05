import json
import time
import dht
import machine
import xmsg

SENSOR_PIN = 4


def main():
    d = dht.DHT11(machine.Pin(SENSOR_PIN))
    for attempt in range(3):                     # the DHT11 sometimes misses a reading
        try:
            d.measure()
            break
        except Exception:
            if attempt == 2:
                raise
            time.sleep(2)
    message = json.dumps({"temperature": d.temperature(), "humidity": d.humidity()})
    topic = xmsg.publish("telemetry", message)   # xnet sends it securely (TLS)
    print("sent", message, "to", topic)
    return message
