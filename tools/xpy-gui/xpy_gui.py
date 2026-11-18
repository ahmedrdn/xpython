#!/usr/bin/env python3
"""xpy-gui: one window for the xPython PC tools (xpy-officer, xpy-pack, xpy-ota).

It runs the SAME code as the command-line tools: every button calls one of their
commands and answers its questions from the fields in the window.
Start it from the repo:   python3 tools/xpy-gui/xpy_gui.py
Needs Tkinter:            sudo apt install python3-tk
Windows installer:        tools/xpy-gui/build_windows.bat makes dist/xpython-setup.exe;
                          the installed program keeps its data in Documents/xPython.
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
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)              # True inside xpython.exe (PyInstaller)
HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))   # where tools/ are


def _data_folder():
    """The xPython data folder (keys/, server/, apps/, build/ ...).
    From the repo: ~/xpython. Installed xPython tools (Windows): Documents/xPython.
    XPY_DATA overrides both."""
    if os.environ.get("XPY_DATA"):
        return Path(os.environ["XPY_DATA"])
    if not FROZEN:
        return Path(__file__).resolve().parents[2]
    return _documents() / "xPython"


def _documents():
    """The user's real Documents folder. On Windows it is asked from Windows itself, because
    OneDrive often moves it (e.g. C:\\Users\\me\\OneDrive\\Documents); the installer uses the same."""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            # FOLDERID_Documents {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
            guid = (ctypes.c_ubyte * 16)(*bytes.fromhex("d09ad3fd8f23af46adb46c85480369c7"))
            out = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(guid, 0, None, ctypes.byref(out)) == 0:
                path = out.value
                ctypes.windll.ole32.CoTaskMemFree(out)
                return Path(path)
        except (OSError, AttributeError):
            pass
    return Path.home() / "Documents"


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
# The boards xPython is built for: esptool's chip name and where the bootloader goes
BOARDS = {"XPY_ESP32": ("esp32", 0x1000), "XPY_ESP32C6": ("esp32c6", 0x0),
          "XPY_ESP32S3": ("esp32s3", 0x0), "XPY_ESP32C3": ("esp32c3", 0x0)}
CHIP_IDS = {0: "XPY_ESP32", 13: "XPY_ESP32C6", 9: "XPY_ESP32S3", 5: "XPY_ESP32C3"}                  # byte 12-13 of an ESP app image


def board_of(image):
    """Which xPython board an app image is for: its version label, else its chip ID."""
    tag = ota.firmware_tag(image)
    board = tag[0] if tag else CHIP_IDS.get(image[12] | image[13] << 8 if len(image) > 13 else -1)
    if board not in BOARDS:
        raise ValueError("firmware for an unknown board: " + str(board))
    chip = CHIP_IDS.get(image[12] | image[13] << 8)
    if chip and chip != board:
        raise ValueError(f"its label says {board} but the image is for {chip}")
    return board


def build_dir(board):
    return ROOT / "micropython/ports/esp32" / ("build-" + board)
APP_ADDR, APP_SLOT = 0x10000, 0x1D0000                          # ota_0 in partitions-xpy-ota.csv
OTADATA = (0xD000, 0x2000)                                      # which slot boots


def check_firmware(path):
    """Check a firmware file before flashing.
    .xfw (signed OTA package): signature (keys/fw_sign.pem), hash and board are verified.
    .bin (plain image): only that it is an ESP32 app with xPython inside, that fits the slot.
    Returns (image file to flash, description, board name)."""
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
        if h.get("board") not in BOARDS:
            raise ValueError("firmware for an unknown board: " + str(h.get("board")))
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
    board = board_of(image)
    return out, f"{desc}\nBoard: {board} (chip {BOARDS[board][0]})", board


# Standard secure port of each protocol (filled in when the protocol is chosen).
DEFAULT_PORTS = {"mqtt": "8883", "http": "443", "coap": "5684"}

# Platform presets: they only fill the fields (all stay editable); replace the <...> parts.
#   {device} {app} {sub} {key} in a topic or path are filled in by the board (xnet).
PRESETS = {
    "ThingSpeak (MQTT)": {"protocol": "mqtt", "host": "mqtt3.thingspeak.com", "port": "8883",
                          "topic": "channels/<channel ID>/publish", "fields": "temperature,humidity",
                          "header": "", "name": "ts_mqtt"},
    "ThingSpeak (HTTP)": {"protocol": "http", "host": "api.thingspeak.com", "port": "443",
                          "topic": "/update", "fields": "temperature,humidity",
                          "header": "THINGSPEAKAPIKEY: {key}", "name": "ts_http"},
    "ThingsBoard (MQTT)": {"protocol": "mqtt", "host": "mqtt.thingsboard.cloud", "port": "8883",
                           "topic": "v1/devices/me/telemetry", "fields": "", "header": "", "name": "tb_mqtt"},
    "ThingsBoard (HTTP)": {"protocol": "http", "host": "thingsboard.cloud", "port": "443",
                           "topic": "/api/v1/{key}/telemetry", "fields": "", "header": "", "name": "tb_http"},
    "ThingsBoard (CoAP)": {"protocol": "coap", "host": "thingsboard.cloud", "port": "5684",
                           "topic": "api/v1/{key}/telemetry", "fields": "", "header": "", "name": "tb_coap"},
    "HiveMQ Cloud (MQTT)": {"protocol": "mqtt", "host": "<cluster>.s1.eu.hivemq.cloud", "port": "8883",
                            "topic": "xpy/{device}/{app}/{sub}", "fields": "", "header": "", "name": "hivemq"},
    # the "updates" service is only listened to: fw_update (ThingSpeak field1) changed = check firmware,
    # app_update (field2) changed = check apps
    "Updates: ThingsBoard (MQTT)": {"protocol": "mqtt", "host": "mqtt.thingsboard.cloud", "port": "8883",
                                    "topic": "v1/devices/me/attributes", "fields": "", "header": "", "name": "updates"},
    "Updates: ThingsBoard (HTTP)": {"protocol": "http", "host": "thingsboard.cloud", "port": "443",
                                    "topic": "/api/v1/{key}/attributes?sharedKeys=fw_update,app_update", "fields": "",
                                    "header": "", "name": "updates"},
    "Updates: ThingSpeak (HTTP)": {"protocol": "http", "host": "api.thingspeak.com", "port": "443",
                                   "topic": "/channels/<channel ID>/feeds/last.json?api_key={key}", "fields": "",
                                   "header": "", "name": "updates"},
    "Custom MQTT": {"protocol": "mqtt", "host": "", "port": "8883",
                    "topic": "xpy/{device}/{app}/{sub}", "fields": "", "header": "", "name": "default"},
    "Custom HTTP": {"protocol": "http", "host": "", "port": "443",
                    "topic": "/api/{device}/{sub}", "fields": "", "header": "Authorization: Bearer {key}", "name": "default"},
    "Custom CoAP": {"protocol": "coap", "host": "", "port": "5684",
                    "topic": "{device}/{sub}", "fields": "", "header": "", "name": "default"},
}


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
        icon = HERE / "tools" / "xpy-gui" / "icon" / "xpython.png"    # window and taskbar icon
        if icon.exists():
            self._icon = tk.PhotoImage(file=str(icon))
            self.iconphoto(True, self._icon)
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
        style = ttk.Style()
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
        ttk.Button(top, text="Board info", command=lambda: self.run_cmd(officer.cmd_boardinfo)).pack(side="left", padx=(4, 0))
        ttk.Button(top, text="Data folder", command=self.open_data_folder).pack(side="right")
        self.state_lbl = ttk.Label(top, text="", style="Head.TLabel")
        self.state_lbl.pack(side="left", padx=10)

        self.out_btn = ttk.Button(top, text="Hide output", command=self.toggle_output)
        self.out_btn.pack(side="right", padx=(0, 6))
        self._canvases = []
        pw = ttk.PanedWindow(self, orient="vertical")
        pw.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        nb = ttk.Notebook(pw)
        pw.add(nb, weight=3)
        self._pages = []
        for title, builder in (("Device", self._tab_device), ("Network", self._tab_network),
                               ("Apps", self._tab_apps), ("Firmware", self._tab_firmware)):
            page = ttk.Frame(nb)
            nb.add(page, text=title)
            # left: the tab's section names (like Office's Options window); right: one section
            nav = tk.Listbox(page, width=24, activestyle="none", exportselection=False, borderwidth=0,
                             highlightthickness=0, font=("TkDefaultFont", 11),
                             background=style.lookup("TFrame", "background"),
                             selectbackground="#cfe0f5", selectforeground="#000000")
            nav.pack(side="left", fill="y", padx=(6, 0), pady=8)
            ttk.Separator(page, orient="vertical").pack(side="left", fill="y", padx=(6, 0), pady=8)
            outer, f = self._scrollable(page)
            outer.pack(side="left", fill="both", expand=True)
            self._page = {"nav": nav, "sections": [], "canvas": self._canvases[-1][0]}
            self._pages.append(self._page)
            builder(f)
            nav.bind("<<ListboxSelect>>", lambda e, pg=self._page: self._show_section(pg))
            self._show_section(self._page, 0)
        nb.bind("<<NotebookTabChanged>>",           # opening a tab shows its first section
                lambda e: self._show_section(self._pages[nb.index("current")], 0))

        logf = ttk.Frame(pw)
        pw.add(logf, weight=2)
        self.pw, self.logf, self.log_shown = pw, logf, True
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
        for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(ev, self._wheel)

    def toggle_output(self):
        """Hide or show the output pane (the tabs then use the whole window)."""
        if self.log_shown:
            self.pw.forget(self.logf)
        else:
            self.pw.add(self.logf, weight=2)
        self.log_shown = not self.log_shown
        self.out_btn.configure(text="Hide output" if self.log_shown else "Show output")

    def _scrollable(self, parent):
        """A tab whose content scrolls when the window is too small for it."""
        outer = ttk.Frame(parent)
        canvas = tk.Canvas(outer, highlightthickness=0, background=ttk.Style().lookup("TFrame", "background"))
        bar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas, padding=12)
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._canvases.append((canvas, inner))
        return outer, inner

    def _wheel(self, e):
        """Mouse wheel: scroll only the tab under the pointer. Lists, the output and drop-down
        boxes scroll themselves, so the tab behind them stays still."""
        w = e.widget
        if not hasattr(w, "winfo_class") or w.winfo_class() in ("Text", "Listbox", "TCombobox", "Treeview"):
            return
        path = str(w)
        for canvas, inner in self._canvases:
            if path == str(canvas) or path.startswith(str(canvas) + "."):
                if canvas.winfo_ismapped() and inner.winfo_height() > canvas.winfo_height():
                    canvas.yview_scroll(-1 if (e.num == 4 or e.delta > 0) else 1, "units")
                return

    def _section(self, parent, title, nav=None):
        """One section of the current tab: its name goes into the tab's list on the left
        (nav, or the title up to ':' or '('), and it is shown when that name is clicked."""
        f = ttk.LabelFrame(parent, text=title, padding=10)
        name = nav or title.split(":")[0].split("(")[0].strip()
        self._page["sections"].append(f)
        self._page["nav"].insert("end", "  " + name)
        return f

    def _show_section(self, page, index=None):
        nav = page["nav"]
        if index is None:
            sel = nav.curselection()
            if not sel:
                return
            index = sel[0]
        nav.selection_clear(0, "end")
        nav.selection_set(index)
        for i, f in enumerate(page["sections"]):
            if i == index:
                f.pack(fill="x", pady=(0, 10))
            else:
                f.pack_forget()
        page["canvas"].yview_moveto(0)

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
        ttk.Label(s, text="Provision a BLANK board: the PIN in the top bar becomes its SO PIN; it also gets its TLS certificate.").pack(anchor="w")
        self._buttons(s, ("Create organization keys", lambda: self.run_cmd(officer.cmd_keygen)),
                      ("Provision", lambda: self.run_cmd(officer.cmd_provision, pin=True)),
                      ("Renew TLS certificate", lambda: self.run_cmd(officer.cmd_netcert, pin=True)),
                      ("Reset to BLANK…", self.do_reset))
        s = self._section(f, "Lock / unlock")
        ttk.Label(s, text="Lock: apps run by themselves, REPL closed.  Unlock: REPL open for setup (press EN if nothing happens).").pack(anchor="w")
        self._buttons(s, ("Lock", self.do_lock),
                      ("Unlock", lambda: self.run_cmd(officer.cmd_unlock, pin=True)))
        s = self._section(f, "Monitor")
        ttk.Label(s, text="Shows what the board prints, even when locked.").pack(anchor="w")
        self._buttons(s, ("Start monitor", self.do_monitor), ("Stop monitor", self.stop_monitor),
                      ("Restart board", lambda: self.do_monitor(reset=True)))

    def _tab_network(self, f):
        self._tab_wifi(f)
        self._tab_cloud(f)
        self._tab_gateway(f)
        self._tab_server(f)

    def _tab_server(self, f):
        s = self._section(f, "Server: firmware and app updates over the air (HTTPS with mutual TLS, port 8443)",
                          nav="Update server")
        ttk.Label(s, text="Serves one firmware per board type (build/ota/firmware) and the apps in build/ota/apps\n"
                          "to the boards over mutual TLS. Each board fetches only the firmware of its own type.\n"
                          "Publish puts a new version there (no restart needed); then announce it in ThingsBoard:\n"
                          "fw_update = check firmware only, app_update = check apps only (or wait for the hourly check).").pack(anchor="w")
        self._buttons(s, ("Publish firmware…", self.do_publish_fw), ("Publish app…", self.do_publish_app))
        ttk.Label(s, text="Published now (what the boards can fetch):").pack(anchor="w", pady=(8, 0))
        self.pub_list = ttk.Treeview(s, columns=("kind", "name", "version", "file"), show="headings",
                                     height=5, selectmode="browse")
        for col, text, w in (("kind", "Kind", 80), ("name", "Name", 140), ("version", "Version", 80),
                             ("file", "File", 320)):
            self.pub_list.heading(col, text=text)
            self.pub_list.column(col, width=w, stretch=(col == "file"))
        self.pub_list.pack(fill="x")
        self._buttons(s, ("Refresh", self.do_show_published), ("Remove selected…", self.do_unpublish))
        self.refresh_published()
        self._buttons(s, ("Create server certificates (once)", lambda: self.run_cmd(officer.cmd_netca)))
        r = ttk.Frame(s)
        r.pack(fill="x", pady=(6, 0))
        ttk.Button(r, text="Start server", command=self.do_serve).pack(side="left", padx=(0, 6))
        ttk.Button(r, text="Stop server", command=self.do_stop_serve).pack(side="left", padx=(0, 6))
        ttk.Label(r, text="Server:").pack(side="left", padx=(6, 2))
        self.srv_lbl = ttk.Label(r, text="stopped", style="Head.TLabel")
        self.srv_lbl.pack(side="left")
        self._buttons(s, ("Push update", lambda: self.run_cmd(ota.cmd_push, ota_port=8443)))
        # several boards at once
        ttk.Label(s, text="Select USB boards (Ctrl/Shift + click) and push. Wi-Fi boards also check the server every hour;\nESP-NOW devices are updated over USB.").pack(anchor="w", pady=(8, 2))
        r = ttk.Frame(s)
        r.pack(fill="x")
        self.push_list = tk.Listbox(r, selectmode="extended", height=4, width=24, exportselection=False)
        self.push_list.pack(side="left")
        col = ttk.Frame(r)
        col.pack(side="left", padx=6, anchor="n")
        ttk.Button(col, text="↻ Find boards", command=self.refresh_push_list).pack(fill="x")
        ttk.Button(col, text="Select all", command=lambda: self.push_list.select_set(0, "end")).pack(fill="x", pady=2)
        ttk.Button(col, text="Push to selected boards", command=self.do_push_many).pack(fill="x")
        self.refresh_push_list()

    def _tab_gateway(self, f):
        s = self._section(f, "Role: off · device (sends through a gateway) · gateway (forwards for its devices)",
                          nav="Gateway / role")
        ttk.Label(s, text="Gateway: role gateway, Save, then 'Copy this board's ID'.  Device: role device + that ID, Save.").pack(anchor="w")
        r = ttk.Frame(s)
        r.pack(fill="x", pady=2)
        ttk.Label(r, text="Role", width=22).pack(side="left")
        self.gw_role = ttk.Combobox(r, width=10, state="readonly", values=["off", "device", "gateway"])
        self.gw_role.set("device")
        self.gw_role.pack(side="left")
        r = ttk.Frame(s)
        r.pack(fill="x", pady=2)
        ttk.Label(r, text="Link (device)", width=22).pack(side="left")
        self.gw_link = ttk.Combobox(r, width=10, state="readonly", values=["espnow", "wifi"])
        self.gw_link.set("espnow")
        self.gw_link.pack(side="left")
        ttk.Label(r, text="  espnow: no router · wifi: via the gateway's Wi-Fi").pack(side="left")
        self.gw_id = self._row(s, "Gateway ID (device)")
        self.gw_devs = self._row(s, "Allowed devices (gateway)")
        ttk.Label(s, text="Allowed devices: optional IDs, comma-separated; empty = all your boards.").pack(anchor="w")
        self._buttons(s, ("Save role", self.do_gateway), ("Copy this board's ID", self.do_gw_copy_id),
                      ("Show role", lambda: self.run_cmd(officer.cmd_gwstatus)))
        ttk.Label(s, text="Devices that joined this gateway (connect the GATEWAY board):").pack(anchor="w", pady=(8, 2))
        r = ttk.Frame(s)
        r.pack(fill="x")
        self.dev_list = tk.Listbox(r, height=5, exportselection=False, font=("Courier", 9))
        self.dev_list.pack(side="left", fill="x", expand=True)
        col = ttk.Frame(r)
        col.pack(side="left", padx=6, anchor="n")
        ttk.Button(col, text="↻ Refresh", command=self.do_list_devices).pack(fill="x")
        ttk.Button(col, text="Clear list…", command=self.do_forget_devices).pack(fill="x", pady=2)

    def do_list_devices(self):
        port = self.port.get()

        def work():
            d = officer.run(port, 'import xgate\nprint("XPY:" + json.dumps(xgate.devices()))')
            rows = sorted(d.items(), key=lambda kv: kv[1].get("last", ""), reverse=True)
            lines = [f"{k}  {v['link']:6}  {v['address']:21}  last {v['last']}  ({v['joins']}×)" for k, v in rows]
            self.q.put(("devices", lines or ["(no device has joined this gateway yet)"]))
            self._say(f"{len(lines)} device(s) joined this gateway.")
        self._say("\n▶ gateway devices")
        self.answers = {}
        self._start(work)

    def do_forget_devices(self):
        if self._need_pin() and messagebox.askyesno("Clear list", "Clear the gateway's list of devices?\n"
                                                    "(The devices themselves are not affected.)"):
            pin = self.pin.get()
            self.run_code(f'import xgate\nxgate.forget_devices({pin!r})\nprint("XPY:1")',
                          lambda r: "Device list cleared.")
            self.after(2500, self.do_list_devices)

    def do_gateway(self):
        self.run_cmd(officer.cmd_gateway, pin=True, value=self.gw_role.get(),
                     gateway_id=self.gw_id.get().strip(), devices=self.gw_devs.get().strip(),
                     link=self.gw_link.get())

    def do_gw_copy_id(self):
        port = self.port.get()

        def work():
            r = officer.run(port, 'd = xinit.device_id()\nprint("XPY:" + json.dumps(d.hex() if d else None))')
            if not r:
                self._say("This board has no ID yet: provision it first.")
                return
            self.q.put(("gw_id", r))
            self._say(f"Gateway ID copied: {r}\nNow connect a device board and save its role 'device'.")
        self._start(work)

    def _tab_wifi(self, f):
        s = self._section(f, "Wi-Fi: several networks, saved sealed on the board; it joins the strongest saved one")
        ttk.Label(s, text="Scan shows what the board sees. Select a network, type its password, Save + connect.\n"
                          "If no saved network is in range, the board keeps its apps running and tries again every minute.").pack(anchor="w")
        r = ttk.Frame(s)
        r.pack(fill="x", pady=(6, 0))
        left = ttk.Frame(r)
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="Networks in range").pack(anchor="w")
        self.scan_list = ttk.Treeview(left, columns=("ssid", "signal", "security", "saved"), show="headings",
                                      height=6, selectmode="browse")
        for col, text, w in (("ssid", "Name", 220), ("signal", "Signal", 80), ("security", "Security", 100),
                             ("saved", "Saved", 60)):
            self.scan_list.heading(col, text=text)
            self.scan_list.column(col, width=w, stretch=(col == "ssid"))
        self.scan_list.pack(fill="x")
        self.scan_list.bind("<<TreeviewSelect>>", self._wifi_picked)
        right = ttk.Frame(r)
        right.pack(side="left", fill="y", padx=(12, 0))
        ttk.Label(right, text="Saved networks").pack(anchor="w")
        self.saved_list = tk.Listbox(right, height=7, width=26, exportselection=False)
        self.saved_list.pack(fill="y")
        self._buttons(s, ("Scan", self.do_wifi_scan), ("Connect to best saved", self.do_wifi_connect),
                      ("Show saved", self.do_wifi_saved), ("Delete selected saved…", self.do_wifi_remove))
        self.ssid = self._row(s, "Wi-Fi name")
        self.wpass = self._row(s, "Wi-Fi password", show="•")
        self._buttons(s, ("Save + connect", self.do_wifi))
        self.broker = self._row(s, "Local broker IP (optional)")
        self._buttons(s, ("Save broker IP", self.do_broker))
        s = self._section(f, "Local broker (mutual TLS, also used for firmware updates)")
        self._buttons(s, ("Test local broker", lambda: self.run_cmd(officer.cmd_nettest)),
                      ("Send app data here, not to the cloud", self.do_clear_cloud))

    def _tab_cloud(self, f):
        s = self._section(f, "Cloud services: where app data goes (the server's certificate is always checked)")
        r = ttk.Frame(s)
        r.pack(fill="x", pady=2)
        ttk.Label(r, text="Platform", width=22).pack(side="left")
        self.preset = ttk.Combobox(r, width=28, state="readonly", values=list(PRESETS))
        self.preset.pack(side="left")
        self.preset.bind("<<ComboboxSelected>>", lambda e: self._apply_preset())
        ttk.Label(r, text="  fills the fields; replace the <...> parts").pack(side="left")
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
                      ("Delete service", self.do_delete_service))
        ttk.Label(s, text="Saved on the board (click one to put its name in 'Service name'):").pack(anchor="w", pady=(8, 2))
        r = ttk.Frame(s)
        r.pack(fill="x")
        self.svc_list = tk.Listbox(r, height=4, exportselection=False)
        self.svc_list.pack(side="left", fill="x", expand=True)
        self.svc_list.bind("<<ListboxSelect>>", self._service_picked)
        ttk.Button(r, text="↻ Refresh", command=self.do_list_services).pack(side="left", padx=6, anchor="n")
        self._show_protocol()

    SERVICES_CODE = ('import xnet\nc = xnet.config()\nd = dict(c.get("services", {}))\n'
                     'd["default"] = c.get("cloud")\nprint("XPY:" + json.dumps(d))')

    def _service_lines(self, port):
        d = officer.run(port, self.SERVICES_CODE)
        return [f"{n}:  {v['protocol'].upper()}  {v['host']}:{v['port']}  {v['topic']}" if v else f"{n}:  (none)"
                for n, v in sorted(d.items())]

    def do_list_services(self):
        port = self.port.get()

        def work():
            lines = self._service_lines(port)
            self.q.put(("services", lines))
            self._say("Saved services:\n  " + "\n  ".join(lines))
        self._say("\n▶ saved services")
        self.answers = {}
        self._start(work)

    def _service_picked(self, _event=None):
        sel = self.svc_list.curselection()
        if sel:
            name = self.svc_list.get(sel[0]).split(":")[0]
            self.sname.delete(0, "end")
            self.sname.insert(0, name)

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
            self.after(2500, self.do_list_services)

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
        self._buttons(s, ("Install", self.do_install), ("Publish app (over the air)", lambda: self.do_publish_app(self.xpk.get())))
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
        self.fw_addr = self._row(s, "Start address (optional)", width=12)
        ttk.Label(s, text="Flash keeps identity, apps and settings; Erase wipes everything.\nStart address: empty = automatic, or write any file at that address (unchecked).").pack(anchor="w")
        self._buttons(s, ("Flash", lambda: self.do_flash(erase=False)),
                      ("Erase + flash…", lambda: self.do_flash(erase=True)),
                      ("Erase board…", self.do_erase))
        self._tab_ota(f)

    def _tab_ota(self, f):
        s = self._section(f, "Sign a firmware for updates over the air (self-test and rollback on the board)",
                          nav="Publish over the air")
        self.sign_file = self._row(s, "Firmware to sign (.bin)", browse="fw", default=str(BUILD / "micropython.bin"))
        self.sign_version = self._row(s, "Version (older firmware only)", width=12)
        ttk.Label(s, text="Signs it with keys/fw_sign.pem into firmware.xfw (same folder); boards accept only newer versions.").pack(anchor="w")
        self._buttons(s, ("Publish firmware", self.do_sign),
                      ("Firmware status", lambda: self.run_cmd(ota.cmd_status)))
        ttk.Label(s, text="Signs it and puts it on the update server (build/ota). Then announce it: change fw_update in ThingsBoard.").pack(anchor="w", pady=(4, 0))

    def refresh_push_list(self):
        self.push_list.delete(0, "end")
        for p in self._ports():
            self.push_list.insert("end", p)

    def do_push_many(self):
        ports = [self.push_list.get(i) for i in self.push_list.curselection()]
        if not ports:
            messagebox.showinfo("Push", "Select one or more boards in the list first.")
            return
        if self.srv_lbl.cget("text") == "stopped" and not messagebox.askyesno(
                "Push", "The update server looks stopped. Push anyway?"):
            return
        self._say(f"\n▶ push update to {len(ports)} board(s): {', '.join(ports)}")
        self.answers = {}

        def work():
            results = []
            for p in ports:
                self._say(f"\n── {p} ──")
                try:
                    r = ota.cmd_push(argparse.Namespace(port=p, ota_port=8443))
                    results.append((p, r or "done"))
                except SystemExit as e:
                    results.append((p, f"failed: {e.code}"))
                except Exception as e:
                    results.append((p, f"failed: {e}"))
            self._say("\nSummary:\n" + "\n".join(f"  {p}: {r}" for p, r in results))
        self._start(work)

    def do_sign(self):
        """Check the chosen .bin, find its version, then sign it into firmware.xfw next to it."""
        path = self.sign_file.get().strip()
        typed = self.sign_version.get().strip()
        try:
            data = Path(path).read_bytes()
            if data[:4] == b"XFW1":
                raise ValueError("this is already a signed package (.xfw); choose the .bin")
            check_firmware(path)
        except (OSError, ValueError) as e:
            messagebox.showerror("Sign firmware", f"{path}\n\nNot signed: {e}")
            return
        tag = ota.firmware_tag(data)                    # the firmware's own label (xfw.TAG)
        if tag:
            board, version = tag
            if typed and typed != version:
                messagebox.showinfo("Sign firmware", f"This firmware says it is version {version}; "
                                    f"that is used (not {typed}).")
            where = "read from the firmware"
        else:                                           # older firmware: no label inside
            board, version = board_of(data), typed or (ota.source_tag() or (None, ""))[1]
            if not version:
                messagebox.showerror("Sign firmware", "This firmware has no version label (it was built "
                                     "before the XPY-FW label).\nType its version in 'Version', e.g. 1.1.0.")
                return
            if version.encode() not in data and not messagebox.askyesno(
                    "Sign firmware", f"Version {version} does not appear inside this firmware.\n"
                                     "Was it built with that version? Sign it as " + version + " anyway?"):
                return
            where = "typed" if typed else "from xfw.py"
        self._say(f"Version {version} for {board} ({where})")

        def work():
            old = ota.IMAGE, ota.OTA_DIR
            ota.IMAGE = Path(path)                  # sign the chosen file ...
            ota.OTA_DIR = Path(path).parent         # ... into firmware.xfw next to it
            try:
                ota.cmd_build(argparse.Namespace(key=str(ota.FW_KEY), tamper_after=False,
                                                 tamper_before=False, variant="",
                                                 board=board, version=version))
            finally:
                ota.IMAGE, ota.OTA_DIR = old
            signed = Path(path).parent / "firmware.xfw"
            board_, version_, dest = ota.publish_firmware(signed)   # build/ota/firmware/<BOARD>.xfw
            self.q.put(("published",))
            self._say(f"Published firmware {version} for {board}: {dest}\n"
                      "Boards fetch it at their next check; to announce it now, change fw_update in ThingsBoard.")
        self._say(f"\n▶ publish firmware: {path}")
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
                    elif item[0] in ("services", "devices"):
                        box = self.svc_list if item[0] == "services" else self.dev_list
                        box.delete(0, "end")
                        for line in item[1]:
                            box.insert("end", line)
                    elif item[0] == "gw_id":
                        self.gw_id.delete(0, "end")
                        self.gw_id.insert(0, item[1])
                    elif item[0] == "server":
                        self.srv_lbl.configure(text=item[1])
                    elif item[0] == "wifi_scan":
                        self.scan_list.delete(*self.scan_list.get_children())
                        for n in item[1]:
                            self.scan_list.insert("", "end", values=(n["ssid"], f"{n['rssi']} dBm", n["security"],
                                                                     "★ yes" if n["saved"] else ""))
                    elif item[0] == "wifi_saved":
                        self.saved_list.delete(0, "end")
                        for name in item[1]:
                            self.saved_list.insert("end", name)
                    elif item[0] == "published":
                        self.refresh_published()
                else:
                    self.log.insert("end", item)
                    if not self.log_shown:              # new output while hidden: say so on the button
                        self.out_btn.configure(text="Show output •")
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

    def _wifi_picked(self, _e=None):
        sel = self.scan_list.selection()
        if sel:
            self.ssid.delete(0, "end")
            self.ssid.insert(0, self.scan_list.item(sel[0], "values")[0])
            self.wpass.delete(0, "end")
            self.wpass.focus_set()

    def do_wifi_scan(self):
        port = self.port.get()

        def work():
            nets = officer.wifi_scan(port)
            self.q.put(("wifi_scan", nets))
            self._say(f"{len(nets)} networks in range"
                      + (", saved ones: " + ", ".join(n["ssid"] for n in nets if n["saved"])
                         if any(n["saved"] for n in nets) else ", none of them saved"))
        self._say("\n▶ Wi-Fi scan (by the board)")
        self._start(work)

    def do_wifi_saved(self):
        port = self.port.get()

        def work():
            names = officer.wifi_saved(port)
            self.q.put(("wifi_saved", names))
            self._say("Saved: " + (", ".join(names) or "none"))
        self._say("\n▶ saved Wi-Fi networks")
        self._start(work)

    def _say_wifi(self, st):
        if st.get("connected"):
            self._say(f"Connected to {st['ssid']}, IP {st['ip']}" + (f", {st['rssi']} dBm" if "rssi" in st else ""))
        else:
            self._say("Not connected.")

    def do_wifi(self):
        """Save the network typed/selected (sealed) and connect to it."""
        if not self._need_pin() or not self.ssid.get().strip():
            if not self.ssid.get().strip():
                messagebox.showinfo("Wi-Fi", "Scan and select a network, or type its name.")
            return
        port, pin, ssid, pw, broker = (self.port.get(), self.pin.get(), self.ssid.get().strip(),
                                       self.wpass.get(), self.broker.get().strip())

        def work():
            if broker:                                  # also save the local broker (its CA: server/ca.crt)
                officer.run(port, "import xnet\n"
                            f"xnet.configure({pin!r}, {ssid!r}, {pw!r}, {broker!r}, 8883, "
                            f"bytes.fromhex({self._broker_ca().hex()!r}))\n"
                            'print("XPY:1")')
                names = officer.wifi_saved(port)
            else:
                names = officer.wifi_add(port, pin, ssid, pw)
            self.q.put(("wifi_saved", names))
            self._say(f"Saved (sealed): {ssid}. Saved networks: {', '.join(names)}")
            try:
                self._say_wifi(officer.wifi_connect(port, ssid))
            except officer.DeviceError as e:
                self._say(f"Saved, but could not connect now: {e}")
        self._say("\n▶ save + connect Wi-Fi")
        self._start(work)

    def do_wifi_connect(self):
        port = self.port.get()

        def work():
            self._say_wifi(officer.wifi_connect(port))
        self._say("\n▶ connect to the best saved Wi-Fi in range")
        self._start(work)

    def do_wifi_remove(self):
        sel = self.saved_list.curselection()
        if not sel:
            messagebox.showinfo("Wi-Fi", "Click 'Show saved', then select a saved network.")
            return
        if not self._need_pin():
            return
        ssid = self.saved_list.get(sel[0])
        if not messagebox.askyesno("Wi-Fi", f"Delete the saved network '{ssid}' from the board?"):
            return
        port, pin = self.port.get(), self.pin.get()

        def work():
            names = officer.wifi_remove(port, pin, ssid)
            self.q.put(("wifi_saved", names))
            self._say(f"Deleted {ssid}. Saved networks: {', '.join(names) or 'none'}")
        self._say("\n▶ delete saved Wi-Fi")
        self._start(work)

    def _broker_ca(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        c = x509.load_pem_x509_certificate((ROOT / "server" / "ca.crt").read_bytes())
        return c.public_bytes(serialization.Encoding.DER)

    def do_broker(self):
        """Save only the local broker IP (the saved Wi-Fi networks stay)."""
        if not self._need_pin():
            return
        port, pin, broker = self.port.get(), self.pin.get(), self.broker.get().strip()

        def work():
            ca = self._broker_ca() if broker else b""
            officer.run(port, "import xnet\n"
                        f"xnet.configure({pin!r}, '', '', {broker!r}, 8883, bytes.fromhex({ca.hex()!r}))\n"
                        'print("XPY:1")')
            self._say(f"Local broker saved (sealed): {broker or 'none'}")
        self._say("\n▶ local broker")
        self._start(work)

    def _apply_preset(self):
        p = PRESETS[self.preset.get()]
        self.proto.set(p["protocol"])
        self._show_protocol()
        self.header.configure(state="normal")
        if p.get("name"):
            self.sname.delete(0, "end")
            self.sname.insert(0, p["name"])
        for entry, key in ((self.host, "host"), (self.bport, "port"), (self.topic, "topic"),
                           (self.fields, "fields"), (self.header, "header")):
            entry.delete(0, "end")
            entry.insert(0, p[key])
        self._show_protocol()

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
            messagebox.showwarning("Cloud service", "Fill in: " + ", ".join(problems) +
                                   "\n(replace the <...> parts of a preset with your own values)")
            return
        port, pin = self.port.get(), self.pin.get()
        name = self.sname.get().strip() or "default"

        def work():
            officer.save_cloud(port, pin, vals["host"], vals["bport"], officer.load_ca(vals["ca"]),
                               vals["topic"], vals["cid"], vals["user"], vals["bpass"], vals["fields"],
                               proto, vals["key"], vals["header"], name)
            self.q.put(("services", self._service_lines(port)))
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
        addr = self.fw_addr.get().strip()
        if addr:                                    # any file at a given address, unchecked
            if erase:
                messagebox.showinfo("Erase + flash", "Erase + flash uses the automatic addresses.\n"
                                    "Clear 'Start address' first, or use 'Flash' to write one file.")
                return
            try:
                at = int(addr, 0)
                if at < 0 or at % 0x1000:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Flash", "Start address: a number like 0x0, 0x1000 or 0x8000 "
                                     "(a multiple of 0x1000).")
                return
            if not Path(path).is_file():
                messagebox.showerror("Flash", f"No such file: {path}")
                return
            size = Path(path).stat().st_size
            if not messagebox.askyesno("Flash", f"Write {Path(path).name} ({size} bytes) at {hex(at)}, "
                                       "without any check?\n\nA wrong file or address can stop the board "
                                       "from starting (fix it with Erase + flash).", icon="warning"):
                return
            self._run_esptool(port, "auto", [["write_flash", hex(at), str(path)]],
                              f"write {Path(path).name} at {hex(at)}")
            return
        try:
            image, desc, board = check_firmware(path)
        except (OSError, ValueError, KeyError) as e:
            messagebox.showerror("Firmware", f"{path}\n\nNot flashed: {e}")
            return
        chip, boot_at = BOARDS[board]
        # An erased chip also needs the bootloader and the partition table: taken from the
        # firmware's own folder first (e.g. on Windows), else from that board's last build
        here, build = Path(path).parent, build_dir(board)
        boot = next((p for p in (here / "bootloader.bin", build / "bootloader" / "bootloader.bin") if p.exists()), None)
        table = next((p for p in (here / "partition-table.bin", build / "partition_table" / "partition-table.bin")
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
                     ["write_flash", hex(boot_at), str(boot), "0x8000", str(table), hex(APP_ADDR), str(image)]]
        else:
            if not messagebox.askyesno("Flash", f"{desc}\n\nFlash it? Identity, keys, apps and settings are kept."):
                return
            # write slot ota_0, and clear "which slot boots" so the board starts this firmware
            steps = [["erase_region", hex(OTADATA[0]), hex(OTADATA[1])],
                     ["write_flash", hex(APP_ADDR), str(image)]]
        self._run_esptool(port, chip, steps, f"{'erase + flash' if erase else 'flash'}: {path}\n  {desc}")

    def do_erase(self):
        """Wipe the whole flash (esptool erase_flash); the chip type is detected."""
        port = self.port.get()
        if not messagebox.askyesno("Erase board", f"ERASE the whole board on {port}?\n\n"
                                   "Firmware, identity, keys, PIN, apps and settings are all deleted. "
                                   "The board will not start until a firmware is flashed again "
                                   "(use 'Erase + flash' or 'Flash' with the bootloader).", icon="warning"):
            return
        self._run_esptool(port, "auto", [["erase_flash"]], f"erase board on {port}",
                          done="Finished OK. The board is empty: flash a firmware next.")

    def _run_esptool(self, port, chip, steps, title, done="Finished OK. The board restarts with the new firmware."):
        """Run esptool steps in the background ("auto" = let esptool detect the chip)."""
        def work():
            try:
                import esptool                      # pip package (bundled in xpython.exe)
            except ImportError:
                esptool = None
            for step in steps:
                argv = ["--chip", chip, "--port", port] + step   # esptool refuses a different chip
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
            self._say(done)
        self._say(f"\n▶ {title}")
        self.answers = {}
        self._start(work)

    def do_publish_fw(self):
        """Choose a built firmware (.bin), then sign and publish it (same as the Firmware tab)."""
        p = filedialog.askopenfilename(initialdir=BUILD if BUILD.exists() else ROOT, title="Firmware to publish (.bin)",
                                       filetypes=[("Firmware image", "*.bin"), ("All files", "*")])
        if p:
            self.sign_file.delete(0, "end")
            self.sign_file.insert(0, p)
            self.do_sign()

    def do_publish_app(self, package=None):
        """Put a signed app package on the update server. Boards that HAVE this app install
        it at their next app check (if it is newer); boards without it ignore it."""
        if not package:
            package = filedialog.askopenfilename(initialdir=ROOT / "build" / "apps", title="App to publish (.xpk)",
                                                 filetypes=[("xPython app", "*.xpk")])
        if not package:
            return
        try:
            app, version, dest = ota.publish_app(package)
        except (OSError, ValueError, KeyError) as e:
            messagebox.showerror("Publish app", f"{package}\n\nNot published: {e}")
            return
        self.refresh_published()
        self._say(f"\n▶ publish app\nPublished {app} {version}: {dest}\n"
                  "Boards that have this app install it at their next check; "
                  "to announce it now, change app_update in ThingsBoard.")

    def _published(self):
        """[(kind, name, version, path)] on the update server."""
        out = []
        files = sorted((ota.OTA_DIR / "firmware").glob("*.xfw"))
        legacy = ota.OTA_DIR / "firmware.xfw"
        for fw in files + ([legacy] if legacy.exists() else []):
            kind = "firmware" if fw != legacy else "firmware (older boards)"
            try:
                h = ota.xfw_header(fw)
                board = h.get("board", "?")
                if fw != legacy and fw.stem != board:
                    board += " (wrong file name: not offered)"
                out.append((kind, board, h.get("version", "?"), fw))
            except (OSError, ValueError, struct.error):
                out.append((kind, "?", "unreadable", fw))
        for f in sorted((ota.OTA_DIR / "apps").glob("*.xpk")):
            try:
                app, version = ota.read_xpk(f)
                name = app if f.stem == app else f"{app} (wrong file name: not offered)"
            except (OSError, ValueError, KeyError):
                name, version = f.stem, "unreadable"
            out.append(("app", name, version, f))
        return out

    def refresh_published(self):
        self.pub_list.delete(*self.pub_list.get_children())
        for kind, name, version, path in self._published():
            self.pub_list.insert("", "end", values=(kind, name, version, str(path)))

    def do_unpublish(self):
        sel = self.pub_list.selection()
        if not sel:
            messagebox.showinfo("Published", "Select a firmware or an app in the list first.")
            return
        kind, name, version, path = self.pub_list.item(sel[0], "values")
        if not messagebox.askyesno("Remove", f"Remove {kind} {name} {version} from the update server?\n\n{path}\n\n"
                                   "Boards that already installed it keep it; others will not get it."):
            return
        try:
            Path(path).unlink()
        except OSError as e:
            messagebox.showerror("Remove", str(e))
            return
        self._say(f"\n▶ removed from the update server: {kind} {name} {version}")
        self.refresh_published()

    def do_show_published(self):
        self.refresh_published()
        lines = ["\n▶ published on the update server (" + str(ota.OTA_DIR) + ")"]
        for kind, name, version, path in self._published():
            lines.append(f"{kind}: {name} {version}")
        if len(lines) == 1:
            lines.append("nothing")
        self._say("\n".join(lines))

    def do_serve(self):
        if self.server and self.server.poll() is None:
            return
        folder = ota.OTA_DIR                        # firmware.xfw + apps/ (Publish puts them there)
        if not list((folder / "firmware").glob("*.xfw")) and not list((folder / "apps").glob("*.xpk")):
            self._say(f"Note: nothing is published yet in {folder} (use Publish firmware / Publish app).")
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
