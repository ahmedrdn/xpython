import sys, os, xsfs, xkeys

# On the PC, store sealed files in /tmp (the real / isn't writable)
ROOT = "/.xsfs_test" if sys.platform == "esp32" else "/tmp/xsfs_test"
KEY = "t_sfs"
print("xsfs version:", xsfs.version())

def rmtree(p):
    try:
        for e in os.ilistdir(p):
            q = p + "/" + e[0]
            if e[1] == 0x4000:
                rmtree(q)
            else:
                os.remove(q)
        os.rmdir(p)
    except OSError:
        pass

def raw_read(name):
    with open(ROOT + "/" + name, "rb") as f:
        return f.read()

def raw_write(name, data):
    with open(ROOT + "/" + name, "wb") as f:
        f.write(data)

# Clean start
try:
    os.umount("/secure")
except OSError:
    pass
rmtree(ROOT)
if xkeys.exists(KEY):
    xkeys.delete(KEY)
xsfs.mount("/secure", key=KEY, root=ROOT)

# 1. Text and binary files read back correctly
with open("/secure/config.json", "w") as f:
    f.write('{"wifi": "secret-password"}')
with open("/secure/config.json") as f:
    assert f.read() == '{"wifi": "secret-password"}'
with open("/secure/blob.bin", "wb") as f:
    f.write(bytes(range(256)))
with open("/secure/blob.bin", "rb") as f:
    assert f.read() == bytes(range(256))

# 2. What's really stored is encrypted
raw = raw_read("config.json")
assert raw[:4] == b"XSF1" and b"secret-password" not in raw

# 3. Append, listing and sizes work
with open("/secure/config.json", "a") as f:
    f.write("!")
with open("/secure/config.json") as f:
    assert f.read().endswith("}!")
assert sorted(os.listdir("/secure")) == ["blob.bin", "config.json"]
assert os.stat("/secure/blob.bin")[6] == 256

# 4. Tampering is detected: flip one stored bit
raw = bytearray(raw_read("blob.bin"))
raw[-1] ^= 1
raw_write("blob.bin", raw)
try:
    with open("/secure/blob.bin", "rb") as f:
        f.read()
    raise AssertionError("tampered file accepted")
except OSError:
    pass

# 5. A sealed file copied to another name is refused
raw_write("copy.json", raw_read("config.json"))
try:
    with open("/secure/copy.json") as f:
        f.read()
    raise AssertionError("moved file accepted")
except OSError:
    pass

# 6. Rename re-seals, so the file stays readable under its new name
os.rename("/secure/config.json", "/secure/settings.json")
with open("/secure/settings.json") as f:
    assert "secret-password" in f.read()

# 7. Folders work
os.mkdir("/secure/logs")
with open("/secure/logs/a.txt", "w") as f:
    f.write("log line")
assert os.listdir("/secure/logs") == ["a.txt"]

# Clean up
os.umount("/secure")
rmtree(ROOT)
xkeys.delete(KEY)
print("xsfs: all tests passed")