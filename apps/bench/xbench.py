# xbench: measures what xPython's security costs on a board (for the thesis evaluation).
# The same file runs in two ways:
#   - inside the signed "bench" app (main.py): one group per round, under the real xexec/xloader
#   - from the PC tool tools/xpy-bench (board in development mode): every group, many times
# Every group returns {"group": name, metric: value, ...}. Metric names end in their unit:
#   _us = microseconds per operation, _ms = milliseconds, _kb = kilobytes, _b = bytes.
import gc
import os
import time
import xcrypto
import xkeys

VERSION = "1.0.0"
GROUPS = ("crypto", "keys", "storage", "deploy", "memory", "publish")
KEY_ECC = "bench_ecc"           # keys the benchmark creates once and keeps (xkeys labels)
KEY_AES = "bench_aes"
KEY_SFS = "bench_sfs"


def _per_op(fn, n):
    """Average time of fn() over n calls, in microseconds."""
    fn()                                         # warm-up (imports, caches)
    gc.collect()
    t0 = time.ticks_us()
    for _ in range(n):
        fn()
    return round(time.ticks_diff(time.ticks_us(), t0) / n, 1)


def _measure(out, name, fn, n):
    try:
        out[name] = _per_op(fn, n)
    except Exception as e:                       # one failing metric must not lose the rest
        out[name] = None
        out.setdefault("errors", {})[name] = repr(e)


# ---------- crypto: the primitives every service is built on (xcrypto) ----------
def crypto():
    r = {"group": "crypto"}
    k32, iv = xcrypto.random(32), xcrypto.random(12)
    d1 = xcrypto.random(1024)                    # random() gives at most 1 KB per call
    d4, d16 = d1 * 4, d1 * 16
    priv, pub = xcrypto.ecdsa_keygen()
    priv2, pub2 = xcrypto.ecdsa_keygen()
    sig = xcrypto.ecdsa_sign(priv, d1)
    ct1, tag1 = xcrypto.aes_gcm_encrypt(k32, iv, d1)
    _measure(r, "sha256_1k_us", lambda: xcrypto.sha256(d1), 50)
    _measure(r, "sha256_16k_us", lambda: xcrypto.sha256(d16), 10)
    _measure(r, "hmac_1k_us", lambda: xcrypto.hmac_sha256(k32, d1), 50)
    _measure(r, "hkdf_32_us", lambda: xcrypto.hkdf_sha256(k32, b"salt", b"info", 32), 50)
    _measure(r, "aesgcm_enc_1k_us", lambda: xcrypto.aes_gcm_encrypt(k32, iv, d1), 50)
    _measure(r, "aesgcm_dec_1k_us", lambda: xcrypto.aes_gcm_decrypt(k32, iv, ct1, tag1), 50)
    _measure(r, "aesgcm_enc_4k_us", lambda: xcrypto.aes_gcm_encrypt(k32, iv, d4), 20)
    _measure(r, "ecdsa_keygen_us", xcrypto.ecdsa_keygen, 5)
    _measure(r, "ecdsa_sign_us", lambda: xcrypto.ecdsa_sign(priv, d1), 5)
    _measure(r, "ecdsa_verify_us", lambda: xcrypto.ecdsa_verify(pub, d1, sig), 5)
    _measure(r, "ecdh_us", lambda: xcrypto.ecdh(priv, pub2), 5)
    _measure(r, "random_32_us", lambda: xcrypto.random(32), 50)
    return r


# ---------- keys: the same work with keys that never leave the key store (xkeys) ----------
def keys():
    r = {"group": "keys"}
    if not xkeys.exists(KEY_ECC):
        xkeys.generate(KEY_ECC, xkeys.ECC_P256)
    if not xkeys.exists(KEY_AES):
        xkeys.generate(KEY_AES, xkeys.AES256)
    d1, iv = xcrypto.random(1024), xcrypto.random(12)
    ct, tag = xkeys.encrypt(KEY_AES, iv, d1)
    _measure(r, "xkeys_sign_us", lambda: xkeys.sign(KEY_ECC, d1), 5)
    _measure(r, "xkeys_encrypt_1k_us", lambda: xkeys.encrypt(KEY_AES, iv, d1), 20)
    _measure(r, "xkeys_decrypt_1k_us", lambda: xkeys.decrypt(KEY_AES, iv, ct, tag), 20)
    _measure(r, "xkeys_public_us", lambda: xkeys.public(KEY_ECC), 20)
    return r


# ---------- storage: sealed files (xsfs) against plain files on the same flash ----------
def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def storage():
    r = {"group": "storage"}
    import xloader
    if xloader.running():                        # inside the app: its own sealed /data
        sealed, mounted = "/data", False
    else:                                        # from the PC tool: a sealed folder of our own
        import xsfs
        sealed, mounted = "/bench_s", True
        try:
            xsfs.mount(sealed, key=KEY_SFS, root="/.bench_sfs")
        except OSError:
            pass                                 # still mounted from an earlier run
    plain = "/.bench_plain"
    try:
        os.mkdir(plain)
    except OSError:
        pass
    try:
        for size, n in ((1024, 5), (4096, 5), (15 * 1024, 3)):
            data = (xcrypto.random(1024) * 16)[:size]
            kb = str(size // 1024)
            for kind, base in (("plain", plain), ("sealed", sealed)):
                p = base + "/b" + kb
                _measure(r, kind + "_write_" + kb + "k_us", lambda: _write(p, data), n)
                _measure(r, kind + "_read_" + kb + "k_us", lambda: _read(p), n)
                try:
                    os.remove(p)
                except OSError:
                    pass
    finally:
        if mounted:
            try:
                os.umount(sealed)
            except OSError:
                pass
    return r


# ---------- deploy: what xloader checks before EVERY run of an app ----------
def deploy():
    r = {"group": "deploy"}
    import xloader
    apps = {}
    for app in xloader.list():
        try:
            m = xloader.info(app)
            size = 0
            for name in m["files"]:
                size += os.stat(xloader._root + "/" + app + "/" + name)[6]
            apps[app] = {"files": len(m["files"]), "size_b": size,
                         "verify_us": _per_op(lambda: xloader.verify(app), 5)}
        except Exception as e:
            apps[app] = {"error": repr(e)}
    r["apps"] = apps
    ok = [a["verify_us"] for a in apps.values() if "verify_us" in a]
    if ok:
        r["verify_mean_us"] = round(sum(ok) / len(ok), 1)
    return r


# ---------- memory: heaps, flash and file system ----------
def memory():
    r = {"group": "memory"}
    gc.collect()
    r["py_heap_total_kb"] = (gc.mem_free() + gc.mem_alloc()) // 1024
    r["py_heap_free_kb"] = gc.mem_free() // 1024
    try:
        import esp32
        h = esp32.idf_heap_info(esp32.HEAP_DATA)
        r["idf_heap_total_kb"] = sum(x[0] for x in h) // 1024
        r["idf_heap_free_kb"] = sum(x[1] for x in h) // 1024
        r["idf_heap_largest_kb"] = max(x[2] for x in h) // 1024
        r["idf_heap_min_free_kb"] = sum(x[3] for x in h) // 1024
        import esp
        r["flash_kb"] = esp.flash_size() // 1024
        p = esp32.Partition(esp32.Partition.RUNNING).info()
        r["slot_kb"] = p[3] // 1024
    except ImportError:
        pass                                     # PC build
    try:
        v = os.statvfs("/")
        r["fs_total_kb"] = v[0] * v[2] // 1024
        r["fs_free_kb"] = v[0] * v[3] // 1024
    except OSError:
        pass
    r["uptime_ms"] = time.ticks_ms()
    return r


# ---------- publish: one message end to end through xmsg (gateway or cloud) ----------
def publish():
    r = {"group": "publish"}
    import xloader
    if not xloader.running() or not xloader.service():
        r["skipped"] = "needs the bench app with a service in its app.json"
        return r
    import xmsg
    times = []
    for i in range(3):
        t0 = time.ticks_ms()
        try:
            xmsg.publish("bench", '{"n": %d}' % i)
            times.append(time.ticks_diff(time.ticks_ms(), t0))
        except Exception as e:
            r.setdefault("errors", []).append(repr(e))
        time.sleep_ms(500)
    if times:
        r["publish_first_ms"] = times[0]         # may include a join / connection
        r["publish_ms"] = sum(times[1:]) / max(1, len(times) - 1) if len(times) > 1 else times[0]
    return r


def run_group(name):
    if name not in GROUPS:
        raise ValueError("unknown group: " + name)
    t0 = time.ticks_ms()
    r = globals()[name]()
    r["group_ms"] = time.ticks_diff(time.ticks_ms(), t0)
    r["bench"] = VERSION
    try:
        import xfw
        r["fw"] = getattr(xfw, "TAG", xfw.VERSION)
    except ImportError:
        r["fw"] = "?"
    return r
