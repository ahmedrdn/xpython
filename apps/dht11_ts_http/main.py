# Reads the DHT11 and sends it to ThingSpeak over HTTPS.
# HOW it is sent is not in this code: app.json says "service": "ts_http", and the
# device's sealed settings say what that service is (host, path, Write API Key, CA,
# and the field names that turn this JSON into ThingSpeak's field1=..&field2=..).
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
    topic = xmsg.publish("telemetry", message)
    print("sent", message, "to", topic)
    return message
