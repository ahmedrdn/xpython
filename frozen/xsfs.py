# xsfs: xPython Secure File System.
# Frozen into the firmware. Files under the mount point are stored sealed with
# AES-256-GCM using an xkeys key; the file's path is bound in as AAD.
import os
import io
import errno
import xkeys
import xcrypto

VERSION = "0.1.0"
MAGIC = b"XSF1"
HEADER = 4 + 12 + 16            # magic + IV + tag
MAX_FILE = 16 * 1024            # whole file is held in RAM while open


def version():
    return VERSION


class _File:
    """An open secure file. Holds the plaintext in RAM; seals and saves it on close."""

    def __init__(self, fs, path, mode, data):
        self._fs = fs
        self._path = path
        self._text = "b" not in mode
        self._writing = "w" in mode or "a" in mode or "+" in mode
        self._closed = False
        self._buf = io.StringIO(data.decode()) if self._text else io.BytesIO(data)
        if "a" in mode:
            self._buf.seek(0, 2)            # append: start at the end

    def read(self, *args):
        return self._buf.read(*args)

    def readline(self, *args):
        return self._buf.readline(*args)

    def readinto(self, b):
        return self._buf.readinto(b)

    def write(self, data):
        if not self._writing:
            raise OSError(errno.EBADF)      # opened read-only
        return self._buf.write(data)

    def seek(self, *args):
        return self._buf.seek(*args)

    def tell(self):
        return self._buf.tell()

    def flush(self):
        if self._writing and not self._closed:
            value = self._buf.getvalue()
            self._fs._save(self._path, value.encode() if self._text else value)

    def close(self):
        if not self._closed:
            self.flush()
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line


class SecureFS:
    """A user VFS: mount it with os.mount(SecureFS(...), "/secure")."""

    def __init__(self, key="sfs", root="/.xsfs"):
        self._key = key                     # xkeys label of the AES-256 key
        self._root = root.rstrip("/")       # where the sealed files really live
        self._cwd = "/"

    # ---------- Path helpers ----------
    def _abs(self, path):
        """Path inside this file system, always starting with '/'."""
        if not path.startswith("/"):
            path = self._cwd.rstrip("/") + "/" + path
        return path

    def _real(self, path):
        """Where the sealed file is stored on the real file system."""
        p = self._abs(path).strip("/")
        return self._root + "/" + p if p else self._root

    def _aad(self, path):
        """Binds the ciphertext to its own path, so files can't be swapped."""
        return MAGIC + self._abs(path).encode()

    # ---------- Sealing ----------
    def _load(self, path):
        with open(self._real(path), "rb") as f:
            blob = f.read()
        if len(blob) < HEADER or blob[:4] != MAGIC:
            raise OSError(errno.EIO)            # not a sealed file
        iv, tag, ct = blob[4:16], blob[16:32], blob[32:]
        try:
            return xkeys.decrypt(self._key, iv, ct, tag, self._aad(path))
        except ValueError:
            raise OSError(errno.EIO)            # tampered, moved, or wrong key

    def _save(self, path, data):
        if len(data) > MAX_FILE:
            raise OSError(errno.ENOMEM)         # too big to hold in RAM
        iv = xcrypto.random(12)                 # fresh IV for every save
        ct, tag = xkeys.encrypt(self._key, iv, data, self._aad(path))
        real = self._real(path)
        tmp = real + ".tmp"
        with open(tmp, "wb") as f:
            f.write(MAGIC + iv + tag + ct)
        os.rename(tmp, real)                    # replace the old version in one step

    # ---------- VFS interface (called by MicroPython) ----------
    def mount(self, readonly, mkfs):
        if not xkeys.exists(self._key):
            xkeys.generate(self._key, xkeys.AES256)
        try:
            os.mkdir(self._root)
        except OSError:
            pass                                # already exists

    def umount(self):
        pass

    def open(self, path, mode):
        mode = mode or "r"
        if "w" in mode:
            data = b""
        else:
            try:
                data = self._load(path)
            except OSError as e:
                if e.errno == errno.ENOENT and "a" in mode:
                    data = b""                  # append to a new file
                else:
                    raise
        return _File(self, path, mode, data)

    def ilistdir(self, path):
        for entry in os.ilistdir(self._real(path)):
            if not entry[0].endswith(".tmp"):
                yield (entry[0], entry[1], 0)

    def stat(self, path):
        st = os.stat(self._real(path))
        if st[0] & 0x4000:                      # a directory
            return st
        return st[:6] + (max(st[6] - HEADER, 0),) + st[7:]   # report the plaintext size

    def statvfs(self, path):
        return os.statvfs(self._root)

    def mkdir(self, path):
        os.mkdir(self._real(path))

    def rmdir(self, path):
        os.rmdir(self._real(path))

    def remove(self, path):
        os.remove(self._real(path))

    def rename(self, old, new):
        data = self._load(old)                  # the path is part of the seal,
        self._save(new, data)                   # so re-seal under the new name
        os.remove(self._real(old))

    def chdir(self, path):
        self._cwd = self._abs(path)

    def getcwd(self):
        return self._cwd


def mount(point="/secure", key="sfs", root="/.xsfs"):
    """Mount a secure file system. Returns the SecureFS object."""
    fs = SecureFS(key, root)
    os.mount(fs, point)
    return fs