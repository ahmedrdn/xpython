#!/usr/bin/env python3
"""xpy-bench: collect xPython benchmark numbers from boards and turn them into tables.

  run      board in development mode: runs every group N times over USB (mpremote)
  listen   locked board with the signed "bench" app: records its XPY-BENCH lines from USB
  summary  results files -> one table: mean ± sd per metric and board (+ CSV for Excel)

Examples (in ~/xpython):
  python3 tools/xpy-bench/xpy_bench.py run --port /dev/ttyUSB0 --reps 10
  python3 tools/xpy-bench/xpy_bench.py listen --port /dev/ttyACM0 --minutes 10
  python3 tools/xpy-bench/xpy_bench.py summary bench/results/*.jsonl --md bench/summary.md
"""
import argparse
import datetime
import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(os.environ.get("XPY_ROOT") or Path(__file__).resolve().parents[2])
MPREMOTE = json.loads(os.environ.get("XPY_MPREMOTE", '["mpremote"]'))
XBENCH = ROOT / "apps" / "bench" / "xbench.py"
OUT = ROOT / "bench" / "results"
TAG = "XPY-BENCH "
GROUPS = ("crypto", "keys", "storage", "deploy", "memory")      # "publish" needs the app


def board_of(record):
    """'XPY-FW:XPY_ESP32S3:1.5.3' -> 'XPY_ESP32S3'"""
    fw = str(record.get("fw", "?"))
    return fw.split(":")[1] if fw.count(":") == 2 else fw


def _out_file(board, how):
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    return OUT / f"{board}_{how}_{stamp}.jsonl"


def _save(f, record, how, port, rep=None):
    record.update({"how": how, "port": port, "time": datetime.datetime.now().isoformat(timespec="seconds")})
    if rep is not None:
        record["rep"] = rep
    f.write(json.dumps(record) + "\n")
    f.flush()


# ---------- run: development mode, over mpremote ----------
def cmd_run(args):
    groups = args.groups.split(",") if args.groups else list(GROUPS)
    code = XBENCH.read_text()
    call = "\nimport json\nfor _g in %r:\n    print(%r + json.dumps(run_group(_g)))\n" % (groups, TAG)
    f = path = None
    for rep in range(args.reps):
        t0 = time.time()
        try:
            p = subprocess.run([*MPREMOTE, "connect", args.port, "exec", code + call],
                               capture_output=True, text=True, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            sys.exit(f"rep {rep + 1}: no answer within {args.timeout} s")
        lines = [l[len(TAG):] for l in p.stdout.splitlines() if l.startswith(TAG)]
        if not lines:
            sys.exit(f"rep {rep + 1}: no results. Is development mode on?\n{(p.stdout + p.stderr)[-800:]}")
        for l in lines:
            r = json.loads(l)
            if f is None:
                path = _out_file(board_of(r), "run")
                f = open(path, "w")
            _save(f, r, "run", args.port, rep)
        print(f"rep {rep + 1}/{args.reps}: {len(lines)} groups in {time.time() - t0:.1f} s")
    f.close()
    print(f"Saved {path}")
    print(f"Table: python3 tools/xpy-bench/xpy_bench.py summary {path}")


# ---------- listen: the signed app on a locked board ----------
def cmd_listen(args):
    import serial                                   # comes with mpremote (pyserial)
    s = serial.Serial(args.port, 115200, timeout=1)
    end = time.time() + args.minutes * 60
    f = path = None
    n = 0
    print(f"Listening on {args.port} for {args.minutes} min (Ctrl-C stops). Each round prints one group.")
    try:
        while time.time() < end:
            line = s.readline().decode("utf-8", "replace").strip()
            if not line.startswith(TAG):
                if line and args.verbose:
                    print("  " + line)
                continue
            r = json.loads(line[len(TAG):])
            if f is None:
                path = _out_file(board_of(r) if "fw" in r else "board", "app")
                f = open(path, "w")
            _save(f, r, "app", args.port)
            n += 1
            print(f"{n:3d} {r.get('group')}: {r.get('group_ms', '')} ms")
    except KeyboardInterrupt:
        pass
    s.close()
    if f:
        f.close()
        print(f"Saved {n} results to {path}")
    else:
        print("No XPY-BENCH lines seen. Is the bench app installed and the board locked?")


# ---------- summary ----------
def _metrics(r):
    """The numeric metrics of one record (unit in the name), plus each app's verify time."""
    out = {}
    for k, v in r.items():
        if isinstance(v, (int, float)) and not isinstance(v, bool) and k.endswith(("_us", "_ms", "_kb", "_b")):
            if k not in ("group_ms",):
                out[k] = v
    for app, a in (r.get("apps") or {}).items():
        if "verify_us" in a:
            out[f"verify_{app}_us"] = a["verify_us"]
            out[f"size_{app}_b"] = a["size_b"]
    return out


def _stats(xs):
    n = len(xs)
    mean = sum(xs) / n
    sd = math.sqrt(sum((x - mean) ** 2 for x in xs) / (n - 1)) if n > 1 else 0.0
    return n, mean, sd, min(xs), max(xs)


def _fmt(v):
    if v >= 1000:
        return f"{v:,.0f}"
    if v >= 10:
        return f"{v:.1f}"
    return f"{v:.2f}"


RATIOS = [("sealed_write_1k_us", "plain_write_1k_us"), ("sealed_read_1k_us", "plain_read_1k_us"),
          ("sealed_write_4k_us", "plain_write_4k_us"), ("sealed_read_4k_us", "plain_read_4k_us"),
          ("sealed_write_15k_us", "plain_write_15k_us"), ("sealed_read_15k_us", "plain_read_15k_us"),
          ("xkeys_sign_us", "ecdsa_sign_us"), ("xkeys_encrypt_1k_us", "aesgcm_enc_1k_us")]


def _order():
    """Metric order as written in xbench.py (storage names are built there, so listed here)."""
    import re
    names = re.findall(r'"([a-z0-9_]+_(?:us|ms|kb|b))"', XBENCH.read_text())
    for size in ("1k", "4k", "15k"):
        for kind in ("plain", "sealed"):
            for op in ("write", "read"):
                names.append(f"{kind}_{op}_{size}_us")
    return names


def _key(metric, order):
    if metric in order:
        return (0, order.index(metric), metric)
    return (1, 0, metric)


def cmd_summary(args):
    data = {}                                       # board -> group -> metric -> [values]
    for name in args.files:
        for line in Path(name).read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            b = board_of(r)
            g = r.get("group", "?")
            for k, v in _metrics(r).items():
                data.setdefault(b, {}).setdefault(g, {}).setdefault(k, []).append(v)
    if not data:
        sys.exit("No results in those files.")
    boards = sorted(data)
    rows = []                                       # (group, metric, {board: stats})
    order_m = _order()
    order = ["boot", "crypto", "keys", "storage", "deploy", "memory", "publish"]
    groups = sorted({g for b in boards for g in data[b]}, key=lambda g: order.index(g) if g in order else 99)
    for g in groups:
        metrics = []
        for b in boards:
            for k in data[b].get(g, {}):
                if k not in metrics:
                    metrics.append(k)
        metrics.sort(key=lambda m: _key(m, order_m))
        for k in metrics:
            rows.append((g, k, {b: _stats(data[b][g][k]) for b in boards if k in data[b].get(g, {})}))
    # derived: what the protection costs (ratio of means)
    ratios = []
    for a, base in RATIOS:
        cells = {}
        for b in boards:
            allm = {k: v for g in data[b].values() for k, v in g.items()}
            if a in allm and base in allm:
                cells[b] = (sum(allm[a]) / len(allm[a])) / (sum(allm[base]) / len(allm[base]))
        if cells:
            ratios.append((f"{a} / {base}", cells))

    lines = ["# xPython benchmark", "",
             f"Boards: {', '.join(boards)}. Cells: mean ± standard deviation (n = repetitions). "
             "Units are in the metric name: _us microseconds per operation, _ms milliseconds, "
             "_kb kilobytes, _b bytes.", ""]
    head = "| Group | Metric | " + " | ".join(boards) + " |"
    lines += [head, "|" + "---|" * (2 + len(boards))]
    for g, k, cells in rows:
        vals = []
        for b in boards:
            if b in cells:
                n, mean, sd, lo, hi = cells[b]
                vals.append(f"{_fmt(mean)} ± {_fmt(sd)} (n={n})" if n > 1 else _fmt(mean))
            else:
                vals.append("–")
        lines.append(f"| {g} | {k} | " + " | ".join(vals) + " |")
    if ratios:
        lines += ["", "## Cost of the protection (ratio of means)", "",
                  "| Ratio | " + " | ".join(boards) + " |", "|" + "---|" * (1 + len(boards))]
        for name, cells in ratios:
            lines.append(f"| {name} | " + " | ".join(f"{cells[b]:.2f}×" if b in cells else "–" for b in boards) + " |")
    text = "\n".join(lines) + "\n"
    print(text)
    if args.md:
        Path(args.md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md).write_text(text)
        print(f"Saved {args.md}")
    if args.csv:
        import csv
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["board", "group", "metric", "n", "mean", "sd", "min", "max"])
            for g, k, cells in rows:
                for b, (n, mean, sd, lo, hi) in cells.items():
                    w.writerow([b, g, k, n, round(mean, 3), round(sd, 3), lo, hi])
        print(f"Saved {args.csv}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run", help="development mode: run the groups N times over USB")
    p.add_argument("--port", required=True)
    p.add_argument("--reps", type=int, default=10)
    p.add_argument("--groups", help="comma-separated, default: " + ",".join(GROUPS))
    p.add_argument("--timeout", type=int, default=180)
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("listen", help="locked board with the bench app: record its results")
    p.add_argument("--port", required=True)
    p.add_argument("--minutes", type=float, default=10)
    p.add_argument("--verbose", action="store_true", help="also show the board's other lines")
    p.set_defaults(fn=cmd_listen)
    p = sub.add_parser("summary", help="results files -> table")
    p.add_argument("files", nargs="+")
    p.add_argument("--md", help="save the table as Markdown")
    p.add_argument("--csv", help="save every statistic as CSV (Excel)")
    p.set_defaults(fn=cmd_summary)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
