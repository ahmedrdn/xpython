# bench: the xPython benchmark

Measures what xPython's security costs on a board, for the thesis evaluation.

| Group | What it measures |
|---|---|
| crypto | xcrypto: SHA-256, HMAC, HKDF, AES-256-GCM (1 KB / 4 KB), ECDSA P-256 keygen/sign/verify, ECDH, random |
| keys | the same with keys inside xkeys (sign, encrypt, decrypt, public) |
| storage | sealed files (xsfs) vs plain files: write and read of 1, 4 and 15 KB |
| deploy | xloader.verify() of every installed app (done before EVERY run), with app size |
| memory | Python heap, IDF heap, flash, firmware slot, file system, uptime |
| publish | (app only) time of xmsg.publish: device→gateway ACK, or board→cloud |
| boot | (app only) time from power-on to the first app run |

Two ways to run it (same code, `xbench.py`):

1. **Development mode, from the PC** (most numbers, many repetitions):
   `python3 tools/xpy-bench/xpy_bench.py run --port /dev/ttyUSB0 --reps 10`
2. **As a signed app on a locked board** (real conditions; adds boot and publish):
   build + install `apps/bench`, Lock, then
   `python3 tools/xpy-bench/xpy_bench.py listen --port /dev/ttyUSB0 --minutes 15`

Then one table for all boards:
`python3 tools/xpy-bench/xpy_bench.py summary bench/results/*.jsonl --md bench/summary.md --csv bench/summary.csv`

The benchmark keeps three keys on the board (`bench_ecc`, `bench_aes`, `bench_sfs`) so that each run measures the
same thing; it writes and deletes test files in `/.bench_plain` and `/.bench_sfs` (or the app's `/data`).
The app's `service` is `bench`: on a device the publish time is the gateway's ACK (sent before forwarding);
the gateway needs a `bench` service only if you want those test messages forwarded.
