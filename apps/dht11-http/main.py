import json
import xmsg
import random


def main():
    temperature = random.randint(20, 35)       # dummy value, °C
    humidity = random.randint(40, 80)   
    message = json.dumps({"temperature": temperature, "humidity": humidity})
    topic = xmsg.publish("telemetry", message)   # xnet sends it securely (TLS)
    print("sent", message, "to", topic)
    return message
