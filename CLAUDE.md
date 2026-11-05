# xPython — project notes for Claude

## What this is
Master's thesis project (paper target: end of 2026). Rebuilding and extending **xPython**, a
secure-by-design OS for IoT on **ESP32 only** (no STM32), based on the paper "xPython: Novel Secure
Real-Time Operating System for IoT Subsystems Development" (Elalem, Sobh, Bahaa-Eldin, JAC-ECC 2023).
Built on **MicroPython v1.29.0** + **ESP-IDF v5.5.x** (check with `idf.py --version`).
Repo: github.com/ahmedrdn/xpython (PUBLIC). Local path: `~/xpython`.

## How I like to work
- Explain simply, concept first. I learn module by module: goal → main functions → data flow →
  connections to other modules → how to test it myself in the REPL.
- I test things myself (no demo scripts). Give short REPL steps with the expected result.
- Give complete, paste-ready code for files I edit in VS Code — not terminal heredocs
  (the terminal can freeze my machine).
- I often ask for explanations as an organized PDF document: follow "Making PDF guides" below.

## Layout
- `modules/` — all xPython modules (C modules have micropython.mk + micropython.cmake):
  - C: `xcrypto` (mbedTLS crypto + xcrypto.h C API), `xkeys` (key store in NVS, labels, no export),
    `xinit` (identity, SO PIN, life cycle BLANK→PERSONALIZED→OPERATIONAL, LOCKED after 5 wrong PINs,
    trust anchors vendor/app/fw, device certificate), `xpolicy` (app sandbox: open/import/keys/publish,
    also provides `xmsg`), `xwatch` (app time limit)
  - Python, frozen into firmware: `xsfs` (sealed files: AES-GCM, path as AAD), `xloader` (signed .xpk
    apps), `xexec` (runs apps, REPL lock, unlock window), `xnet` (Wi-Fi, NTP, mutual-TLS MQTT),
    `xota` (signed OTA, A/B slots, rollback), `xfw` (VERSION, BOARD, SELF_TEST_FAIL)
- `boards/XPY_ESP32/` — board: manifest.py, sdkconfig.xpy (stage 1 security), partitions-xpy-ota.csv;
  secure-boot variants SB (stage 2), SBFE, REL with sdkconfig.secureboot/.nobt/.flashenc/.release,
  partitions-xpy-secure.csv (partition table at 0xE000)
- `tools/` — PC tools: `xpy-officer/xpy_officer.py` (status, provision, reset, devmode, autostart,
  unlock, netconfig, nettest, netcert), `xpy-pack/xpy_pack.py` (build/install/run .xpk),
  `xpy-ota/xpy_ota.py` (build [--variant], serve, push, status)
- `apps/` (hello, sensor), `tests/test_*.py`, `demos/`, `devices/` (provisioning register)
- NOT in git: `micropython/`, `esp-idf/`, `keys/`, `server/`, `build/`, `*.xpk`

## Build and run (from ~/xpython)
- PC build + tests: VS Code task "PC: build + test"
- PC REPL:
  `MICROPYPATH=$PWD/modules/xfw:$PWD/modules/xsfs:$PWD/modules/xloader:$PWD/modules/xexec:$PWD/modules/xnet:$PWD/modules/xota:.frozen micropython/ports/unix/build-standard/micropython`
  (on PC, xkeys/xinit live in RAM: everything resets when the REPL closes)
- ESP32: VS Code tasks "ESP32: build", "ESP32: build + flash"; board REPL: `mpremote connect /dev/ttyUSB0 repl`
- Boards: A = provisioned, OPERATIONAL, dev mode on (/dev/ttyUSB0). B = spare (/dev/ttyUSB1).

## Safety rules
- Never commit or print anything from `keys/` or `server/*.key` (the repo is public).
- Do NOT run `tests/test_*.py` on board A: they call xinit.reset() and install throwaway anchors.
- Secure boot burns eFuses permanently. It is PAUSED by my decision; only stage 2 (SB variant) is planned,
  on a spare board, after backing up `keys/secure_boot_signing_key.pem`. Never run it without me asking.
- Never push two failing firmwares in a row over OTA (both slots can end up ABORTED; recovery:
  `esptool.py erase_region 0xd000 0x2000`).

## Where I am
- Concept guides done (PDF): Module 1 xcrypto, 2 xkeys, 3 xinit, 4 xsfs.
  Next: Module 5 xloader, then xpolicy+xwatch, xexec, xnet, xota.
- Known findings to remember (for the thesis evaluation / future work):
  - xcrypto: ECDSA signing uses a random nonce (use deterministic ECDSA, RFC 6979);
    xcrypto.random/ecdsa_keygen don't enable the noise source when radios are off (affects xnet TLS key).
  - xsfs: rollback to an older valid sealed copy is not detected; names/sizes visible; 16 KB per file.
  - xkeys: list() shows all labels to a running app (minor). memset wipes should be mbedtls_platform_zeroize.
  - xexec: Ctrl-C during boot (before kbd_intr(-1)) may reach the REPL; LOCKED state → OTA self-test
    fails → reboot loop. Needs a clear LOCKED policy.
  - No flash encryption → a flash dump reveals NVS keys (and sealed data).
  - Device certificate is only checked at provisioning; idea: use it to bind the xnet TLS key to the
    device (netcert) and for a future gateway "join" protocol (challenge + certificate).
- Local branch `demo-lab` from a previous session (demos/, secure-boot files) may not be on GitHub.

## Making PDF guides (always follow this)
- Use the kit in `docs/pdfkit/`: never invent a new design, never use reportlab/markdown-to-PDF.
- Write the guide as an HTML fragment in `docs/guides/<name>.html`, starting at `<h1>`, by copying
  `docs/pdfkit/template.html`. `docs/guides/module4_xsfs.html` is a finished example: match its style.
- Build: `python3 docs/pdfkit/make_pdf.py docs/guides/<name>.html` (needs `pip install weasyprint`).
- Building blocks (all styled by `docs/pdfkit/xpy.css`): `h1` + `p.sub` (subtitle + date), `div.note`
  (key idea, purple), `div.warn` (caution, amber), `div.ok` / `div.bad` (expected success / attack result),
  tables with `th` headers, `pre` for code (expected result as a `#` comment), `figure` + inline `svg` +
  `figcaption`, `p.meta` for the closing "Next:" line.
- Diagrams: inline SVG, viewBox width 680, font-size 12, rounded rects (rx 6). Colours only from the
  template: gray #F1EFE8/#5F5E5A (input), purple #EEEDFE/#534AB7 (processing), teal #E1F5EE/#0F6E56
  (success), coral #FAECE7/#993C1D (error), amber #FAEEDA/#BA7517 (PC side / caution). Text must fit
  inside its box.
- Structure for module guides: 1 Goal → 2 Main functions → 3 Data flow → 4 Who uses it →
  5 Test it yourself (REPL steps, PC vs board, what is safe) → Limits/observations → Summary table.
- Before sending: run every REPL step on the PC build and say so in a `div.note`; open the PDF and check
  that nothing overflows (tables, code lines, diagram text).
