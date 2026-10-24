import json
import random
import time

def main():
    reading = {"temp": round(20 + random.random() * 10, 1), "t": time.time()}
    topic = __import__("xmsg").publish("telemetry", json.dumps(reading))
    print("published", reading, "to", topic)
    return topic