#!/usr/bin/env python3
"""xpy-gui: one window for the xPython PC tools (xpy-officer, xpy-pack, xpy-ota).

It runs the SAME code as the command-line tools: every button calls one of their
commands and answers its questions from the fields in the window.
Start it from the repo:   python3 tools/xpy-gui/xpy_gui.py
Needs Tkinter:            sudo apt install python3-tk
Packed for Windows:       xpython.exe (see tools/xpy-gui/build_windows.bat); its data
                          folder (keys/, server/, apps/, build/) is the folder of the .exe.
"""
import argparse
import builtins
import contextlib
import getpass
import glob
import importlib.util
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)              # True inside xpython.exe (PyInstaller)
HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))   # where tools/ are


def _data_folder():
    """The xPython data folder (keys/, server/, apps/, build/ ...).
    From the repo: ~/xpython. Installed xpython.exe: Documents/xPython (Program Files is not
    writable). Portable xpython.exe: its own folder, if a file named "portable" is next to it.
    XPY_DATA overrides all of these."""
    if os.environ.get("XPY_DATA"):
        return Path(os.environ["XPY_DATA"])
    if not FROZEN:
        return Path(__file__).resolve().parents[2]
    exe_dir = Path(sys.executable).resolve().parent
    if (exe_dir / "portable").exists():
        return exe_dir
    return Path.home() / "Documents" / "xPython"


ROOT = _data_folder()
os.environ["XPY_ROOT"] = str(ROOT)
if FROZEN:                                          # the .exe runs mpremote itself (see below)
    os.environ["XPY_MPREMOTE"] = json.dumps([sys.executable, "--mpremote"])


def _load_tool(name, rel):
    spec = importlib.util.spec_from_file_location(name, HERE / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The packed .exe also plays the command-line programs the tools start:
#   xpython.exe --mpremote ...   = mpremote          xpython.exe --ota serve ... = xpy_ota.py
if os.environ.get("XPY_NEVER_SET"):                 # never true: it only shows PyInstaller what the
    import datetime, functools, getpass, hashlib, http.server, re, ssl, struct, tempfile  # noqa
    import serial, serial.tools.list_ports            # noqa: tools (loaded from files at run time)
    import cryptography.exceptions, cryptography.x509, cryptography.x509.oid  # noqa: need, so it
    import cryptography.hazmat.primitives.asymmetric.ec, cryptography.hazmat.primitives.asymmetric.utils  # noqa
    import esptool, mpremote.main                    # noqa: packs them into xpython.exe


def _attach_std_streams():
    """A windowed .exe (no console) starts with sys.stdout = None; when the GUI runs it as
    a helper with pipes, reconnect stdout/stderr to those pipes so the output comes back."""
    if os.name != "nt" or (sys.stdout and sys.stderr):
        return
    import ctypes
    import msvcrt
    for num, name in ((-11, "stdout"), (-12, "stderr")):      # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
        handle = ctypes.windll.kernel32.GetStdHandle(num)
        if handle and handle != -1:
            try:
                fd = msvcrt.open_osfhandle(handle, 0)
                setattr(sys, name, open(fd, "w", encoding="utf-8", errors="replace", buffering=1))
            except OSError:
                pass


if len(sys.argv) > 1 and sys.argv[1] in ("--mpremote", "--ota"):
    _attach_std_streams()
if len(sys.argv) > 1 and sys.argv[1] == "--mpremote":
    from mpremote.main import main as _mpremote_main
    sys.argv = ["mpremote"] + sys.argv[2:]
    sys.exit(_mpremote_main())
if len(sys.argv) > 1 and sys.argv[1] == "--ota":
    sys.argv = ["xpy_ota"] + sys.argv[2:]
    _load_tool("xpy_ota", "tools/xpy-ota/xpy_ota.py").main()
    sys.exit(0)

import tkinter as tk                                    # noqa: E402 (only the window needs Tk)
from tkinter import filedialog, messagebox, ttk         # noqa: E402

ROOT.mkdir(parents=True, exist_ok=True)
os.chdir(ROOT)                                      # the tools write files relative to here
officer = _load_tool("xpy_officer", "tools/xpy-officer/xpy_officer.py")
packer = _load_tool("xpy_pack", "tools/xpy-pack/xpy_pack.py")
ota = _load_tool("xpy_ota", "tools/xpy-ota/xpy_ota.py")


BUILD = ROOT / "micropython/ports/esp32/build-XPY_ESP32"      # where "ESP32: build" puts its files
APP_ADDR, APP_SLOT = 0x10000, 0x1D0000                          # ota_0 in partitions-xpy-ota.csv
OTADATA = (0xD000, 0x2000)                                      # which slot boots


def check_firmware(path):
    """Check a firmware file before flashing. Returns (image file to flash, description).
    .xfw (signed OTA package): signature (keys/fw_sign.pem), hash and board are verified.
    .bin (plain image): only that it is an ESP32 app with xPython inside, that fits the slot."""
    import hashlib, json, struct
    data = Path(path).read_bytes()
    if data[:4] == b"XFW1":
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        from cryptography.exceptions import InvalidSignature
        n = struct.unpack("<I", data[4:8])[0]
        header, sig, image = data[8:8 + n], data[8 + n:72 + n], data[72 + n:]
        key = ROOT / "keys" / "fw_sign.pem"
        pub = serialization.load_pem_private_key(key.read_bytes(), password=None).public_key()
        try:
            pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                       b"xpy-fw-v1" + header, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ValueError("bad signature: not signed with your firmware key (keys/fw_sign.pem)")
        h = json.loads(header)
        if hashlib.sha256(image).hexdigest() != h["sha256"] or len(image) != h["size"]:
            raise ValueError("the firmware inside the package was changed after signing")
        if h.get("board") != "XPY_ESP32":
            raise ValueError("firmware for another board: " + str(h.get("board")))
        out = ROOT / "build" / "ota" / "_flash_image.bin"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(image)
        desc = f"signed xPython firmware {h['version']} (signature OK)"
    else:
        image, out, desc = data, Path(path), "plain image (.bin): it has no xPython signature to check"
    if image[:1] != b"\xe9":
        raise ValueError("not an ESP32 firmware image")
    if b"xexec" not in image or b"xloader" not in image:
        raise ValueError("this is not an xPython firmware")
    if len(image) > APP_SLOT:
        raise ValueError(f"too big for the firmware slot ({len(image)} > {APP_SLOT} bytes)")
    return out, desc


# Standard secure port of each protocol (filled in when the protocol is chosen).
DEFAULT_PORTS = {"mqtt": "8883", "http": "443", "coap": "5684"}


class _LogWriter:
    """Everything a tool prints goes to the log box (through a queue: Tk is not thread-safe)."""
    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(text)

    def flush(self):
        pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("xPython tools  —  data folder: " + str(ROOT))
        self.geometry("920x800")
        self.minsize(760, 560)
        self.q = queue.Queue()
        self.busy = False
        self.monitor_stop = None
        self.server = None
        self.answers = {}
        self.after_done = None
        self.ota_dir = None                         # folder of the last signed firmware.xfw
        self._build()
        self.after(100, self._drain)
        self.protocol("WM_DELETE_WINDOW", self._quit)

    # ---------------- layout ----------------
    def _build(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Head.TLabel", font=("TkDefaultFont", 10, "bold"))

        top = ttk.Frame(self, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="Board port").pack(side="left")
        self.port = ttk.Combobox(top, width=16, values=self._ports())
        self.port.set((self._ports() or ["COM3" if os.name == "nt" else "/dev/ttyUSB0"])[0])
        self.port.pack(side="left", padx=4)
        ttk.Button(top, text="↻", width=3, command=lambda: self.port.configure(values=self._ports())).pack(side="left")
        ttk.Label(top, text="   SO PIN").pack(side="left")
        self.pin = ttk.Entry(top, width=12, show="•")
        self.pin.pack(side="left", padx=4)
        ttk.Button(top, text="Status", command=self.do_status).pack(side="left", padx=(12, 0))
        ttk.Button(top, text="Data folder", command=self.open_data_folder).pack(side="right")
        self.state_lbl = ttk.Label(top, text="", style="Head.TLabel")
        self.state_lbl.pack(side="left", padx=10)

        pw = ttk.PanedWindow(self, orient="vertical")
        pw.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        nb = ttk.Notebook(pw)
        pw.add(nb, weight=3)
        for title, builder in (("Device", self._tab_device), ("Network", self._tab_network),
                               ("Apps", self._tab_apps), ("Firmware", self._tab_firmware)):
            outer, f = self._scrollable(nb)
            nb.add(outer, text=title)
            builder(f)

        logf = ttk.Frame(pw)
        pw.add(logf, weight=2)
        bar = ttk.Frame(logf)
        bar.pack(fill="x")
        ttk.Label(bar, text="Output", style="Head.TLabel").pack(side="left")
        ttk.Button(bar, text="Clear", command=lambda: self.log.delete("1.0", "end")).pack(side="right")
        self.log = tk.Text(logf, height=12, wrap="word", font=("TkFixedFont", 10),
                           background="#1e1e1e", foreground="#e8e8e8", insertbackground="#e8e8e8")
        sb = ttk.Scrollbar(logf, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log.pack(fill="both", expand=True)

    def _scrollable(self, parent):
        """A tab whose content scrolls when the window is too small for it."""
        outer = ttk.Frame(parent)
        canvas = tk.Canvas(outer, highlightthickness=0, background=ttk.Style(self).lookup("TFrame", "background"))
        bar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas, padding=12)
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        def wheel(e):
            if inner.winfo_height() > canvas.winfo_height():
                canvas.yview_scroll(-1 if (e.num == 4 or e.delta > 0) else 1, "units")
        for w in (canvas, inner):
            w.bind("<Enter>", lambda e: (self.bind_all("<Button-4>", wheel), self.bind_all("<Button-5>", wheel),
                                         self.bind_all("<MouseWheel>", wheel)))
        return outer, inner

    def _section(self, parent, title):
        f = ttk.LabelFrame(parent, text=title, padding=10)
        f.pack(fill="x", pady=(0, 10))
        return f

    def _row(self, parent, label, width=34, show=None, browse=None, default=""):
        r = ttk.Frame(parent)
        r.pack(fill="x", pady=2)
        ttk.Label(r, text=label, width=22).pack(side="left")
        e = ttk.Entry(r, width=width, show=show)
        e.insert(0, default)
        e.pack(side="left", fill="x", expand=True)
        if browse:
            ttk.Button(r, text="Browse…", command=lambda: self._browse(e, browse)).pack(side="left", padx=4)
        return e

    def _buttons(self, parent, *items):
        r = ttk.Frame(parent)
        r.pack(fill="x", pady=(6, 0))
        for text, cmd in items:
            ttk.Button(r, text=text, command=cmd).pack(side="left", padx=(0, 6))
        return r

    def _browse(self, entry, kind):
        if kind == "dir":
            p = filedialog.askdirectory(initialdir=ROOT / "apps")
        elif kind == "fw":
            p = filedialog.askopenfilename(initialdir=ROOT / "build", title="Firmware file",
                                           filetypes=[("xPython firmware", "*.xfw *.bin"), ("All files", "*")])
        else:
            p = filedialog.askopenfilename(initialdir=ROOT if kind == "xpk" else Path.home(),
                                           filetypes=[("xPython app", "*.xpk")] if kind == "xpk" else [("All files", "*")])
        if p:
            entry.delete(0, "end")
            entry.insert(0, p)

    def _tab_device(self, f):
        s = self._section(f, "Set up a new board")
        ttk.Label(s, text="Keys are created once on this PC (kept in keys/). Provision needs a BLANK board;\n"
                          "on a board without a PIN, the PIN in the top bar becomes its new SO PIN.").pack(anchor="w")
        self._buttons(s, ("Create organization keys", lambda: self.run_cmd(officer.cmd_keygen)),
                      ("Provision", lambda: self.run_cmd(officer.cmd_provision, pin=True)),
                      ("Reset to BLANK…", self.do_reset))
        s = self._section(f, "Lock / unlock")
        ttk.Label(s, text="Lock: the board runs its apps by itself and the REPL is closed (dev mode off, restart).\n"
                          "Unlock: opens the REPL for setting up and testing (sends the PIN in the 3-second\n"
                          "window after a restart; if nothing happens, press the board's EN button).").pack(anchor="w")
        self._buttons(s, ("Lock", self.do_lock),
                      ("Unlock", lambda: self.run_cmd(officer.cmd_unlock, pin=True)))
        s = self._section(f, "Monitor")
        ttk.Label(s, text="Shows what the board prints, also when it is locked. Other buttons stop it first,\n"
                          "because they need the USB port.").pack(anchor="w")
        self._buttons(s, ("Start monitor", self.do_monitor), ("Stop monitor", self.stop_monitor),
                      ("Restart board", lambda: self.do_monitor(reset=True)))

    def _tab_network(self, f):
        self._tab_wifi(f)
        self._tab_cloud(f)

    def _tab_wifi(self, f):
        s = self._section(f, "Wi-Fi")
        self.ssid = self._row(s, "Wi-Fi name")
        self.wpass = self._row(s, "Wi-Fi password", show="•")
        self.broker = self._row(s, "Local broker IP (optional)")
        self._buttons(s, ("Save Wi-Fi", self.do_wifi))
        s = self._section(f, "Local broker (mutual TLS, also used for firmware updates)")
        self._buttons(s, ("Issue device TLS certificate", lambda: self.run_cmd(officer.cmd_netcert, pin=True)),
                      ("Test local broker", lambda: self.run_cmd(officer.cmd_nettest)),
                      ("Send app data here, not to the cloud", self.do_clear_cloud))

    def _tab_cloud(self, f):
        s = self._section(f, "Cloud services: where app data goes (the server's certificate is always checked)")
        r = ttk.Frame(s)
        r.pack(fill="x", pady=2)
        ttk.Label(r, text="Protocol", width=22).pack(side="left")
        self.proto = ttk.Combobox(r, width=10, state="readonly", values=["mqtt", "http", "coap"])
        self.proto.set("mqtt")
        self.proto.pack(side="left")
        self.proto.bind("<<ComboboxSelected>>", lambda e: self._protocol_changed())
        ttk.Label(r, text="  MQTT over TLS · HTTPS · CoAP over DTLS").pack(side="left")
        self.sname = self._row(s, "Service name", width=16, default="default")
        self.host = self._row(s, "Host")
        self.bport = self._row(s, "Port", width=8, default="8883")
        self.topic = self._row(s, "Topic / path")
        self.fields = self._row(s, "Field names (optional)")
        self.mqtt_box = ttk.Frame(s)                  # MQTT login
        self.cid = self._row(self.mqtt_box, "Client ID (optional)")
        self.user = self._row(self.mqtt_box, "Username (optional)")
        self.bpass = self._row(self.mqtt_box, "Password (optional)", show="•")
        self.key_box = ttk.Frame(s)                   # HTTP / CoAP secret
        self.key = self._row(self.key_box, "Key / API key (optional)", show="•")
        self.header = self._row(self.key_box, "HTTP header (optional)")
        self.ca = self._row(s, "CA certificate", browse="file")
        self.btn_box = self._buttons(s, ("Load credentials file…", self.do_load_creds),
                                     ("Find CA for host", self.do_find_ca))
        self._buttons(s, ("Save", self.do_cloud), ("Send test message", self.do_cloud_test),
                      ("Delete service", self.do_delete_service),
                      ("Show saved services", lambda: self.run_code(
                          'import xnet\nc = xnet.config()\nd = dict(c.get("services", {}))\n'
                          'd["default"] = c.get("cloud")\nprint("XPY:" + json.dumps(d))',
                          lambda r: "\n".join(f"{n}: {v['protocol'].upper()} {v['host']}:{v['port']} {v['topic']}"
                                              if v else f"{n}: (none)" for n, v in r.items()))))
        self._show_protocol()

    def do_delete_service(self):
        name = self.sname.get().strip() or "default"
        if not self._need_pin():
            return
        if messagebox.askyesno("Delete service", f"Delete the service '{name}' from the board?\n"
                                                 "Apps that use it will fail until it is saved again."):
            pin = self.pin.get()
            self.run_code(f'import xnet\nif {name!r} != "default" and {name!r} not in xnet.config().get("services", {{}}):\n'
                          f'    raise ValueError("no service named " + {name!r})\n'
                          f'xnet.clear_cloud({pin!r}, {name!r})\nprint("XPY:1")',
                          lambda r: f"Service '{name}' deleted.")

    def do_cloud_test(self):
        name = self.sname.get().strip() or "default"
        self.run_code(f'import xnet\nprint("XPY:" + json.dumps(xnet.cloud_test(name={name!r})))',
                      lambda r: f"Test message sent via '{name}' to {r}")

    def _show_protocol(self):
        """Show the login fields of the chosen protocol only."""
        self.mqtt_box.pack_forget()
        self.key_box.pack_forget()
        box = self.mqtt_box if self.proto.get() == "mqtt" else self.key_box
        box.pack(fill="x", before=self.ca.master)
        state = "normal" if self.proto.get() == "http" else "disabled"
        self.header.configure(state=state)

    def _tab_apps(self, f):
        s = self._section(f, "Build and install")
        self.app_dir = self._row(s, "App folder", browse="dir", default=str(ROOT / "apps" / "dht11"))
        self._buttons(s, ("Build (sign)", self.do_build_app), ("Build + install", lambda: self.do_build_app(install=True)))
        self.xpk = self._row(s, "Package (.xpk)", browse="xpk")
        self._buttons(s, ("Install", self.do_install))
        s = self._section(f, "On the board")
        r = ttk.Frame(s)
        r.pack(fill="x")
        self.apps = tk.Listbox(r, height=5)
        self.apps.pack(side="left", fill="x", expand=True)
        col = ttk.Frame(r)
        col.pack(side="left", padx=8)
        for text, cmd in (("Refresh", self.do_list_apps), ("Run once", self.do_run_app),
                          ("Remove", self.do_remove_app)):
            ttk.Button(col, text=text, width=12, command=cmd).pack(pady=2)
        self._buttons(s, ("Read sensor", lambda: self.run_code(
            'import machine\nf = getattr(machine, "dht_readinto", None) or __import__("esp").dht_readinto\n'
            'b = bytearray(5)\nf(machine.Pin(4), b)\nprint("XPY:" + json.dumps([b[2], b[0]]))',
            lambda r: f"DHT11: {r[0]} °C, {r[1]} % humidity")),
            ("Show device log", lambda: self.run_code(
                'try:\n    t = open("/xpy.log").read()[-1500:]\nexcept OSError:\n    t = "(empty)"\n'
                'print("XPY:" + json.dumps(t))', lambda r: r)))

    def _tab_firmware(self, f):
        s = self._section(f, "Flash over USB")
        self.fw_file = self._row(s, "Firmware file (.xfw/.bin)", browse="fw", default=str(BUILD / "micropython.bin"))
        ttk.Label(s, text="Flash: writes the firmware only; identity, keys, apps and settings are kept.\n"
                          "Erase + flash: wipes the whole board first; it must be provisioned again.").pack(anchor="w")
        self._buttons(s, ("Flash", lambda: self.do_flash(erase=False)),
                      ("Erase + flash…", lambda: self.do_flash(erase=True)))
        self._tab_ota(f)

    def _tab_ota(self, f):
        s = self._section(f, "Over the air (signed update over Wi-Fi, with self-test and rollback)")
        self.sign_file = self._row(s, "Firmware to sign (.bin)", browse="fw", default=str(BUILD / "micropython.bin"))
        ttk.Label(s, text="Signs it with keys/fw_sign.pem into firmware.xfw, in the same folder. The version comes from\n"
                          "modules/xfw/xfw.py: raise it before building, the board only accepts newer versions.").pack(anchor="w")
        r = ttk.Frame(s)
        r.pack(fill="x", pady=(6, 0))
        ttk.Button(r, text="Sign firmware", command=self.do_sign).pack(side="left", padx=(0, 6))
        ttk.Button(r, text="Start server", command=self.do_serve).pack(side="left", padx=(0, 6))
        ttk.Button(r, text="Stop server", command=self.do_stop_serve).pack(side="left", padx=(0, 6))
        ttk.Label(r, text="Server:").pack(side="left", padx=(6, 2))
        self.srv_lbl = ttk.Label(r, text="stopped", style="Head.TLabel")
        self.srv_lbl.pack(side="left")
        self._buttons(s, ("Push update", lambda: self.run_cmd(ota.cmd_push, ota_port=8443)),
                      ("Firmware status", lambda: self.run_cmd(ota.cmd_status)))

    def do_sign(self):
        """Check the chosen .bin, then sign it into build/ota/firmware.xfw (as xpy_ota.py build)."""
        import re
        path = self.sign_file.get().strip()
        try:
            if Path(path).read_bytes()[:4] == b"XFW1":
                raise ValueError("this is already a signed package (.xfw); choose the .bin")
            check_firmware(path)
            version = re.search(r'VERSION\s*=\s*"([^"]+)"', ota.XFW.read_text()).group(1)
        except (OSError, ValueError, AttributeError) as e:
            messagebox.showerror("Sign firmware", f"{path}\n\nNot signed: {e}")
            return
        if version.encode() not in Path(path).read_bytes() and not messagebox.askyesno(
                "Sign firmware", f"The VERSION in xfw.py ({version}) is not inside this firmware.\n"
                                 "Was it built after you changed the version? Sign it as " + version + " anyway?"):
            return

        def work():
            old = ota.IMAGE, ota.OTA_DIR
            ota.IMAGE = Path(path)                  # sign the chosen file ...
            ota.OTA_DIR = Path(path).parent         # ... into firmware.xfw next to it
            try:
                ota.cmd_build(argparse.Namespace(key=str(ota.FW_KEY), tamper_after=False,
                                                 tamper_before=False, variant=""))
                self.ota_dir = Path(path).parent    # the server will offer this one
            finally:
                ota.IMAGE, ota.OTA_DIR = old
        self._say(f"\n▶ sign firmware: {path}")
        self.answers = {}
        self._start(work)

    # ---------------- running the tools ----------------
    def _ports(self):
        try:                                        # COM3... on Windows, /dev/ttyUSB0... on Linux
            from serial.tools import list_ports
            found = [p.device for p in list_ports.comports()]
        except ImportError:
            found = []
        return sorted(set(found + glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")))

    def _say(self, text):
        self.q.put(text if text.endswith("\n") else text + "\n")

    def _answer(self, prompt=""):
        """Answers the tool's input()/getpass() questions from the window's fields."""
        p = prompt.lower()
        for key, value in self.answers.items():
            if key in p:
                self.q.put(prompt + ("•••" if "pin" in key or "password" in key else str(value)) + "\n")
                return value
        raise RuntimeError("no answer in the window for: " + prompt.strip())

    def _start(self, work):
        if self.busy:
            messagebox.showinfo("Busy", "Wait for the current task to finish.")
            return
        self.stop_monitor()
        self.busy = True
        self.config(cursor="watch")
        threading.Thread(target=self._worker, args=(work,), daemon=True).start()

    def _worker(self, work):
        real_input, real_getpass = builtins.input, getpass.getpass
        builtins.input = getpass.getpass = self._answer
        try:
            with contextlib.redirect_stdout(_LogWriter(self.q)), contextlib.redirect_stderr(_LogWriter(self.q)):
                work()
        except SystemExit as e:
            if e.code not in (None, 0):
                self._say(str(e.code))
        except Exception as e:
            self._say("Error: " + str(e))
        finally:
            builtins.input, getpass.getpass = real_input, real_getpass
            self.q.put(("done",))

    def _drain(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, tuple):
                    if item[0] == "done":
                        self.busy = False
                        self.config(cursor="")
                        self._say("— done —\n")
                        if self.after_done:                 # e.g. watch the board after Lock
                            then, self.after_done = self.after_done, None
                            then()
                    elif item[0] == "state":
                        self.state_lbl.configure(text=item[1])
                    elif item[0] == "apps":
                        self.apps.delete(0, "end")
                        for a in item[1]:
                            self.apps.insert("end", a)
                    elif item[0] == "ca":
                        self.ca.delete(0, "end")
                        self.ca.insert(0, item[1])
                    elif item[0] == "xpk":
                        self.xpk.delete(0, "end")
                        self.xpk.insert(0, item[1])
                    elif item[0] == "server":
                        self.srv_lbl.configure(text=item[1])
                else:
                    self.log.insert("end", item)
                    self.log.see("end")
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _need_pin(self):
        if not self.pin.get():
            messagebox.showwarning("SO PIN", "Type the SO PIN in the top bar first.")
            return False
        return True

    def run_cmd(self, fn, pin=False, answers=None, **fields):
        """Run one command of a tool, exactly as on the command line."""
        if pin and not self._need_pin():
            return
        args = argparse.Namespace(port=self.port.get(), **fields)
        self.answers = {"so pin": self.pin.get(), "new so pin": self.pin.get(), "repeat": self.pin.get()}
        self.answers.update(answers or {})
        self._say(f"\n▶ {fn.__name__.replace('cmd_', '')}")
        self._start(lambda: fn(args))

    def run_code(self, code, show):
        """Run a little MicroPython on the board (in development mode) and show its answer."""
        port = self.port.get()

        def work():
            self._say(show(officer.run(port, code)))
        self._start(work)

    # ---------------- button actions ----------------
    def open_data_folder(self):
        """Open the data folder (keys/, server/, apps/ ...) in the file manager."""
        if os.name == "nt":
            os.startfile(ROOT)                          # noqa: Windows only
        else:
            subprocess.Popen(["xdg-open", str(ROOT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def do_status(self):
        port = self.port.get()

        def work():
            real = officer.device_status

            def spy(p):                             # also show the state in the top bar
                st = real(p)
                self.q.put(("state", f"{st['state']} · dev {'on' if st['dev'] else 'off'}"))
                return st
            officer.device_status = spy
            try:
                officer.cmd_status(argparse.Namespace(port=port))
            finally:
                officer.device_status = real
        self._say("\n▶ status")
        self.answers = {}
        self._start(work)

    def do_lock(self):
        """Dev mode off, then restart: the board locks its REPL and runs its apps."""
        if not self._need_pin():
            return
        port = self.port.get()
        self.answers = {"so pin": self.pin.get()}

        def work():
            try:
                officer.cmd_devmode(argparse.Namespace(port=port, value="off"))
            except officer.DeviceError:
                self._say("Could not reach the REPL: the board is probably locked already.")
                return
            self.after_done = lambda: self.do_monitor(reset=True)   # restart it and show what it does
        self._say("\n▶ lock")
        self._start(work)

    def do_reset(self):
        if not self._need_pin():
            return
        if messagebox.askyesno("Reset to BLANK", "This wipes the board's identity, keys and sealed settings.\n"
                                                "Continue?", icon="warning"):
            self.run_cmd(officer.cmd_reset, pin=True, answers={"type reset": "RESET"})

    def do_wifi(self):
        if not self._need_pin() or not self.ssid.get():
            return
        port, pin, ssid, pw, broker = self.port.get(), self.pin.get(), self.ssid.get(), self.wpass.get(), self.broker.get()

        def work():
            ca = b""
            if broker:                                  # local broker: its CA from server/ca.crt
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                c = x509.load_pem_x509_certificate((ROOT / "server" / "ca.crt").read_bytes())
                ca = c.public_bytes(serialization.Encoding.DER)
            officer.run(port, "import xnet\n"
                        f"xnet.configure({pin!r}, {ssid!r}, {pw!r}, {broker!r}, 8883, bytes.fromhex({ca.hex()!r}))\n"
                        'print("XPY:1")')
            self._say(f"Wi-Fi saved on the board (sealed): {ssid}")
        self._say("\n▶ Wi-Fi")
        self._start(work)

    def _protocol_changed(self):
        """Show the protocol's login fields and its standard port (if a standard one was set)."""
        if self.bport.get().strip() in ("",) + tuple(DEFAULT_PORTS.values()):
            self.bport.delete(0, "end")
            self.bport.insert(0, DEFAULT_PORTS[self.proto.get()])
        self._show_protocol()

    def do_load_creds(self):
        path = filedialog.askopenfilename(initialdir=ROOT / "server", title="Credentials file")
        if not path:
            return
        try:
            cred = officer.read_credentials(path)
        except SystemExit as e:
            messagebox.showerror("Credentials", str(e))
            return
        for entry, key in ((self.cid, "client_id"), (self.user, "username"), (self.bpass, "password")):
            entry.delete(0, "end")
            entry.insert(0, cred[key])
        self._say(f"Credentials loaded: client ID {cred['client_id']}, username {cred['username']}")

    def do_find_ca(self):
        """Ask the broker which root CA it uses, and find that root on this PC."""
        host, port = self.host.get().strip(), self.bport.get().strip() or "8883"
        if not host or "<" in host:
            messagebox.showwarning("CA", "Type the broker host first.")
            return

        def work():
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            import shutil
            if not (shutil.which("openssl") and glob.glob("/etc/ssl/certs/*.pem")):
                return self._find_ca_python(host, port)     # Windows: no openssl, no /etc/ssl
            dtls = ["-dtls"] if self.proto.get() == "coap" else []
            p = subprocess.run(["openssl", "s_client", *dtls, "-connect", f"{host}:{port}", "-servername", host,
                                "-showcerts"], input="", capture_output=True, text=True, timeout=20)
            issuers = [l.split("CN = ", 1)[1].split(",")[0].strip()
                       for l in p.stdout.splitlines() if l.strip().startswith("i:") and "CN = " in l]
            if not issuers:
                self._say("Could not reach " + host + ":" + port + " (check the host and your internet)")
                return
            root = issuers[-1]
            self._say("The broker's chain ends at: " + root)
            for f in sorted(glob.glob("/etc/ssl/certs/*.pem")):
                try:
                    c = x509.load_pem_x509_certificate(Path(f).read_bytes())
                    cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                except Exception:
                    continue
                if cn and cn[0].value == root:
                    out = ROOT / "server" / (host + "_ca.pem")
                    out.parent.mkdir(exist_ok=True)
                    out.write_bytes(Path(f).read_bytes())
                    v = subprocess.run(["openssl", "s_client", *dtls, "-connect", f"{host}:{port}", "-servername",
                                        host, "-CAfile", str(out)], input="", capture_output=True,
                                       text=True, timeout=20).stdout
                    ok = "Verify return code: 0 (ok)" in v
                    self._say(f"Saved {out}  ({'verified OK' if ok else 'NOT verified, check it'})")
                    self.q.put(("ca", str(out)))
                    return
            self._say("That root is not in /etc/ssl/certs; download it from the CA's website.")
        self._say("\n▶ find CA")
        self.answers = {}
        self._start(work)

    def _find_ca_python(self, host, port):
        """Find CA without openssl: connect with this PC's trusted roots and keep the root
        certificate of the verified chain (needs Python 3.13+). TLS only: not for CoAP."""
        import socket, ssl
        if self.proto.get() == "coap":
            self._say("CoAP uses DTLS, which this PC tool cannot open: choose the CA file with Browse…\n"
                      "(e.g. the root CA from the service's website).")
            return
        ctx = ssl.create_default_context()          # Windows: the Windows certificate store
        try:
            with socket.create_connection((host, int(port)), timeout=15) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    if not hasattr(tls, "get_verified_chain"):
                        self._say("Find CA needs Python 3.13 or newer here; choose the CA file with Browse…")
                        return
                    root = tls.get_verified_chain()[-1]
        except (OSError, ssl.SSLError) as e:
            self._say(f"Could not get a trusted connection to {host}:{port}: {e}")
            return
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_der_x509_certificate(root)   # get_verified_chain() gives DER bytes
        out = ROOT / "server" / (host + "_ca.pem")
        out.parent.mkdir(exist_ok=True)
        out.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self._say(f"The chain ends at: {cert.subject.rfc4514_string()}\nSaved {out}  (verified OK)")
        self.q.put(("ca", str(out)))

    def do_cloud(self):
        if not self._need_pin():
            return
        proto = self.proto.get()
        vals = dict(host=self.host.get().strip(), bport=self.bport.get().strip(), topic=self.topic.get().strip(),
                    fields=self.fields.get().strip(), cid=self.cid.get().strip(), user=self.user.get().strip(),
                    bpass=self.bpass.get(), ca=self.ca.get().strip(), key=self.key.get().strip(),
                    header=self.header.get().strip() if proto == "http" else "")
        if proto != "mqtt":
            vals.update(cid="", user="", bpass="")
        else:
            vals.update(key="", header="")
        problems = [n for n, ok in (("host", vals["host"] and "<" not in vals["host"]),
                                    ("port", vals["bport"].isdigit()),
                                    ("topic", vals["topic"] and "<" not in vals["topic"]),
                                    ("CA certificate", vals["ca"])) if not ok]
        if problems:
            messagebox.showwarning("Cloud service", "Fill in: " + ", ".join(problems))
            return
        port, pin = self.port.get(), self.pin.get()
        name = self.sname.get().strip() or "default"

        def work():
            officer.save_cloud(port, pin, vals["host"], vals["bport"], officer.load_ca(vals["ca"]),
                               vals["topic"], vals["cid"], vals["user"], vals["bpass"], vals["fields"],
                               proto, vals["key"], vals["header"], name)
        self._say("\n▶ save cloud service")
        self._start(work)

    def do_clear_cloud(self):
        if self._need_pin():
            pin = self.pin.get()
            self.run_code(f'import xnet\nxnet.clear_cloud({pin!r})\nprint("XPY:1")',
                          lambda r: "App data now goes to the local broker.")

    def do_build_app(self, install=False):
        d = self.app_dir.get()
        if not d:
            return
        port = self.port.get()

        def work():
            import json
            meta = json.loads((Path(d) / "app.json").read_text())
            out = ROOT / "build" / "apps" / f"{meta['app_id']}-{meta['version']}.xpk"
            out.parent.mkdir(parents=True, exist_ok=True)
            packer.cmd_build(argparse.Namespace(port=port, app_dir=d, output=str(out), no_compile=False))
            self.q.put(("xpk", str(out)))
            if install:
                packer.cmd_install(argparse.Namespace(port=port, package=str(out)))
        self._say("\n▶ build" + (" + install" if install else ""))
        self.answers = {}
        self._start(work)

    def do_install(self):
        if self.xpk.get():
            self.run_cmd(packer.cmd_install, package=self.xpk.get())

    def do_list_apps(self):
        port = self.port.get()

        def work():
            apps = officer.run(port, 'import xloader\nprint("XPY:" + json.dumps(xloader.list()))')
            self.q.put(("apps", apps))
            self._say("Installed: " + (", ".join(apps) or "(none)"))
        self._say("\n▶ list apps")
        self._start(work)

    def _selected_app(self):
        sel = self.apps.curselection()
        if not sel:
            messagebox.showinfo("Apps", "Press Refresh, then select an app.")
            return None
        return self.apps.get(sel[0])

    def do_run_app(self):
        a = self._selected_app()
        if a:
            self.run_cmd(packer.cmd_run, app_id=a)

    def do_remove_app(self):
        a = self._selected_app()
        if a and messagebox.askyesno("Remove", f"Remove the app '{a}' and its data from the board?"):
            self.run_code(f'import xloader\nxloader.remove({a!r})\nprint("XPY:1")', lambda r: f"Removed {a}")
            self.after(1500, self.do_list_apps)

    def do_flash(self, erase):
        """Flash a checked firmware file over USB (after erasing the whole chip, if asked)."""
        port, path = self.port.get(), self.fw_file.get().strip()
        try:
            image, desc = check_firmware(path)
        except (OSError, ValueError, KeyError) as e:
            messagebox.showerror("Firmware", f"{path}\n\nNot flashed: {e}")
            return
        # An erased chip also needs the bootloader and the partition table: taken from the
        # firmware's own folder first (e.g. on Windows), else from the last build
        here = Path(path).parent
        boot = next((p for p in (here / "bootloader.bin", BUILD / "bootloader" / "bootloader.bin") if p.exists()), None)
        table = next((p for p in (here / "partition-table.bin", BUILD / "partition_table" / "partition-table.bin")
                      if p.exists()), None)
        if erase:
            if not (boot and table):
                messagebox.showerror("Erase + flash", "An erased board also needs bootloader.bin and "
                                     "partition-table.bin. Put them next to the firmware file (copy them from "
                                     "the build folder), or run 'ESP32: build' on this PC.")
                return
            if not messagebox.askyesno("Erase + flash", f"{desc}\n\nThis ERASES the whole board: identity, keys, PIN, "
                                       "apps and settings. Afterwards it is BLANK and must be provisioned again."
                                       "\n\nContinue?", icon="warning"):
                return
            steps = [["erase_flash"],
                     ["write_flash", "0x1000", str(boot), "0x8000", str(table), hex(APP_ADDR), str(image)]]
        else:
            if not messagebox.askyesno("Flash", f"{desc}\n\nFlash it? Identity, keys, apps and settings are kept."):
                return
            # write slot ota_0, and clear "which slot boots" so the board starts this firmware
            steps = [["erase_region", hex(OTADATA[0]), hex(OTADATA[1])],
                     ["write_flash", hex(APP_ADDR), str(image)]]

        def work():
            try:
                import esptool                      # pip package (bundled in xpython.exe)
            except ImportError:
                esptool = None
            for step in steps:
                argv = ["--chip", "esp32", "--port", port] + step
                self._say("esptool " + " ".join(step[:1]))
                if esptool is not None:
                    try:
                        esptool.main(argv)
                    except (Exception, SystemExit) as e:
                        self._say(f"FAILED: {e}")
                        return
                else:                               # Linux without the package: ESP-IDF's esptool
                    p = subprocess.Popen(["bash", "-c", "source esp-idf/export.sh > /dev/null && esptool.py "
                                          + " ".join(argv)], cwd=ROOT, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True)
                    for line in p.stdout:
                        self.q.put(line)
                    if p.wait() != 0:
                        self._say(f"FAILED (exit code {p.returncode}).")
                        return
            self._say("Finished OK. The board restarts with the new firmware.")
        self._say(f"\n▶ {'erase + flash' if erase else 'flash'}: {path}\n  {desc}")
        self.answers = {}
        self._start(work)

    def do_serve(self):
        if self.server and self.server.poll() is None:
            return
        folder = self.ota_dir or ota.OTA_DIR
        if not (Path(folder) / "firmware.xfw").exists():
            messagebox.showwarning("Server", f"There is no firmware.xfw in {folder}.\nClick 'Sign firmware' first.")
            return
        cmd = ([sys.executable, "--ota"] if FROZEN else [sys.executable, "-u", str(HERE / "tools/xpy-ota/xpy_ota.py")])
        self.server = subprocess.Popen(cmd + ["serve", "--dir", str(folder)],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=ROOT)
        self.q.put(("server", "running on port 8443"))

        def pump(p=self.server):
            for line in p.stdout:
                self.q.put("[server] " + line)
            self.q.put(("server", "stopped"))
        threading.Thread(target=pump, daemon=True).start()

    def do_stop_serve(self):
        if self.server and self.server.poll() is None:
            self.server.terminate()

    def do_monitor(self, reset=False):
        if self.busy:
            return
        self.stop_monitor()
        import serial
        port, stop = self.port.get(), threading.Event()
        self.monitor_stop = stop

        def watch():
            try:
                with serial.Serial(port, 115200, timeout=0.2) as s:
                    if reset:                       # EN pulse, normal boot (same as unlock)
                        s.dtr, s.rts = False, True
                        time.sleep(0.2)
                        s.rts = False
                    self._say(f"\n▶ monitor {port} (Stop monitor to end)")
                    while not stop.is_set():
                        data = s.read(256)
                        if data:
                            self.q.put(data.decode(errors="replace").replace("\r", ""))
            except Exception as e:
                self._say("Monitor: " + str(e))
            self._say("— monitor stopped —")
        threading.Thread(target=watch, daemon=True).start()

    def stop_monitor(self):
        if self.monitor_stop:
            self.monitor_stop.set()
            self.monitor_stop = None
            time.sleep(0.3)                         # let it release the port

    def _quit(self):
        self.stop_monitor()
        self.do_stop_serve()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
