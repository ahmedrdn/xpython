# xloader: xPython Secure Loader (frozen into the firmware).
# Installs and runs only app packages signed with the device's "app" anchor.
import os
import sys
import json
import struct
import xcrypto
import xinit

VERSION = "0.1.0"
MAGIC = b"XPK1"
SIG_LABEL = b"xpy-app-v1"
MAX_PACKAGE = 64 * 1024
RESERVED = ("manifest.json", "manifest.sig")
_root = "/apps"


def version():
    return VERSION


def set_root(path):
    """Change where apps are installed (used by the PC tests)."""
    global _root
    _root = path.rstrip("/")


# ---------- Small helpers ----------
def _exists(p):
    try:
        os.stat(p)
        return True
    except OSError:
        return False


def _rmtree(p):
    try:
        for e in os.ilistdir(p):
            q = p + "/" + e[0]
            if e[1] == 0x4000:
                _rmtree(q)
            else:
                os.remove(q)
        os.rmdir(p)
    except OSError:
        pass


def _check_name(name):
    """App and file names: no folders, no hidden names, no '..' tricks."""
    if (not name or len(name) > 32 or "/" in name or "\\" in name
            or name.startswith(".") or name in RESERVED):
        raise ValueError("bad name: " + name)


def _parse_version(v):
    parts = v.split(".")
    if len(parts) != 3:
        raise ValueError("version must be x.y.z")
    return tuple(int(x) for x in parts)


# ---------- Package parsing and checks ----------
def _parse(blob):
    """Split a package into (manifest bytes, signature, {name: data})."""
    if blob[:4] != MAGIC:
        raise ValueError("not an xPython package")
    pos = 4
    (mlen,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    manifest = bytes(blob[pos:pos + mlen])
    pos += mlen
    sig = bytes(blob[pos:pos + 64])
    pos += 64
    if len(manifest) != mlen or len(sig) != 64:
        raise ValueError("truncated package")
    files = {}
    while pos < len(blob):
        (nlen,) = struct.unpack_from("<H", blob, pos)
        pos += 2
        name = bytes(blob[pos:pos + nlen]).decode()
        pos += nlen
        (dlen,) = struct.unpack_from("<I", blob, pos)
        pos += 4
        data = bytes(blob[pos:pos + dlen])
        pos += dlen
        if len(data) != dlen:
            raise ValueError("truncated package")
        files[name] = data
    return manifest, sig, files


def _verify(manifest, sig):
    """Check the signature with the 'app' anchor, then the manifest's contents."""
    pub = xinit.anchor("app")
    if pub is None:
        raise ValueError("no app-signing anchor installed")
    if not xcrypto.ecdsa_verify(pub, SIG_LABEL + manifest, sig):
        raise ValueError("bad signature")
    m = json.loads(manifest)
    for key in ("app_id", "version", "entry", "files", "permissions"):
        if key not in m:
            raise ValueError("manifest missing " + key)
    _check_name(m["app_id"])
    _parse_version(m["version"])
    for name in m["files"]:
        _check_name(name)
    if m["entry"] not in m["files"]:
        raise ValueError("entry file missing")
    if not isinstance(m["permissions"], dict):
        raise ValueError("bad permissions")
    return m


def _check_files(m, files):
    if sorted(files) != sorted(m["files"]):
        raise ValueError("files don't match the manifest")
    for name, data in files.items():
        if xcrypto.sha256(data).hex() != m["files"][name]:
            raise ValueError("hash mismatch: " + name)


# ---------- Public functions ----------
def install(path):
    """Verify and install a .xpk package. Returns the app id."""
    if xinit.state() != "OPERATIONAL":
        raise ValueError("device must be OPERATIONAL")
    if os.stat(path)[6] > MAX_PACKAGE:
        raise ValueError("package too large")
    with open(path, "rb") as f:
        blob = f.read()
    manifest, sig, files = _parse(blob)
    m = _verify(manifest, sig)
    _check_files(m, files)

    app = m["app_id"]
    old = info(app)
    if old and _parse_version(m["version"]) <= _parse_version(old["version"]):
        raise ValueError("version must be newer than " + old["version"])

    # Unpack into a staging folder first
    if not _exists(_root):
        os.mkdir(_root)
    stage = _root + "/.stage"
    _rmtree(stage)
    os.mkdir(stage)
    for name, data in files.items():
        with open(stage + "/" + name, "wb") as f:
            f.write(data)
    with open(stage + "/manifest.json", "wb") as f:
        f.write(manifest)
    with open(stage + "/manifest.sig", "wb") as f:
        f.write(sig)

    # Swap it into place
    dest = _root + "/" + app
    old_dir = _root + "/.old"
    _rmtree(old_dir)
    if _exists(dest):
        os.rename(dest, old_dir)
    os.rename(stage, dest)
    _rmtree(old_dir)
    return app


def info(app):
    """The installed app's manifest as a dict, or None."""
    try:
        with open(_root + "/" + app + "/manifest.json", "rb") as f:
            return json.loads(f.read())
    except OSError:
        return None


def list():
    try:
        return sorted(e[0] for e in os.ilistdir(_root) if not e[0].startswith("."))
    except OSError:
        return []


def remove(app):
    _check_name(app)
    if info(app) is None:
        raise ValueError("app not installed: " + app)
    _rmtree(_root + "/" + app)


def verify(app):
    """Re-check an installed app's signature and file hashes. Returns its manifest."""
    _check_name(app)
    d = _root + "/" + app
    try:
        with open(d + "/manifest.json", "rb") as f:
            manifest = f.read()
        with open(d + "/manifest.sig", "rb") as f:
            sig = f.read()
    except OSError:
        raise ValueError("app not installed: " + app)
    m = _verify(manifest, sig)
    for name, h in m["files"].items():
        with open(d + "/" + name, "rb") as f:
            if xcrypto.sha256(f.read()).hex() != h:
                raise ValueError("app modified: " + name)
    return m


def run(app):
    """Verify the app, import its entry file, and return main()'s result."""
    m = verify(app)
    d = _root + "/" + app
    for name in m["files"]:                     # forget any old copies of its modules
        sys.modules.pop(name.rsplit(".", 1)[0], None)
    before = set(sys.modules)
    sys.path.insert(0, d)
    try:
        mod = __import__(m["entry"].rsplit(".", 1)[0])
        return mod.main() if hasattr(mod, "main") else None
    finally:
        sys.path.pop(0)
        for name in set(sys.modules) - before:  # unload the app's modules again
            del sys.modules[name]