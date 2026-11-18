# bench: xPython benchmark app. Each round it runs the next measurement group under the real
# engine (xexec + xloader + xwatch), prints one line "XPY-BENCH {...}" and keeps the last
# results sealed in its /data. Collect the lines on the PC with:
#   python3 tools/xpy-bench/xpy_bench.py listen --port /dev/ttyUSB0
import json
import xbench

STATE = "/data/state.json"
LAST = "/data/last.json"


def _load(path, default):
    try:
        with open(path) as f:
            return json.loads(f.read())
    except (OSError, ValueError):
        return default


def main():
    st = _load(STATE, {"next": 0, "rounds": 0})
    now = xbench.time.ticks_ms()
    if now < st.get("uptime", 1 << 30):           # first run since the board (re)started
        import xfw
        first = {"group": "boot", "first_run_ms": now,                      # power on -> first app
                 "fw": getattr(xfw, "TAG", xfw.VERSION), "bench": xbench.VERSION}
        print("XPY-BENCH " + json.dumps(first))
    name = xbench.GROUPS[st["next"] % len(xbench.GROUPS)]
    r = xbench.run_group(name)
    r["round"] = st["rounds"]
    line = json.dumps(r)
    print("XPY-BENCH " + line)
    last = _load(LAST, {})
    last[name] = r                                 # one result per group: stays far below 16 KB
    with open(LAST, "w") as f:
        f.write(json.dumps(last))
    st["next"] = (st["next"] + 1) % len(xbench.GROUPS)
    st["rounds"] += 1
    st["uptime"] = xbench.time.ticks_ms()
    with open(STATE, "w") as f:
        f.write(json.dumps(st))
    return name
