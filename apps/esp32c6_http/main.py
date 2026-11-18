import json
import xmsg
import random


import json
import random
import xmsg


def main():
    temperature = random.randint(20, 35)       # dummy value, °C
    humidity = random.randint(40, 80)          # dummy value, %
    co2 = random.randint(60, 100)
    light = random.randint(80, 120)
    message = json.dumps({"temperature": temperature, "humidity": humidity, "co2": co2, "light": light})
    topic = xmsg.publish("telemetry", message)
    print("sent", message, "to", topic)
    return message
