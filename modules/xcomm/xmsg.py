# xmsg: the messaging API for apps (frozen into the firmware).
# An app calls xmsg.publish("telemetry", data); xnet sends it securely (MQTT/TLS,
# HTTPS or CoAPS) to the service named by "service" in the app's signed app.json
# (or the default service), and the SYSTEM decides the full topic and the format.
import xloader
import xnet

VERSION = "0.3.0"


def publish(sub, payload):
    """Send payload (str or bytes) under the subtopic sub. Returns the full topic."""
    if (not isinstance(sub, str) or not 0 < len(sub) <= 64 or sub[0] == "/"
            or "+" in sub or "#" in sub or ".." in sub):
        raise ValueError("xmsg: bad subtopic")
    if not isinstance(payload, (str, bytes)):
        raise TypeError("xmsg: payload must be str or bytes")
    return xnet.app_publish(xloader.running() or "-", sub, payload, xloader.service())
