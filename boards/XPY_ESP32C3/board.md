# XPY_ESP32C3: xPython on the ESP32-C3

The same xPython as XPY_ESP32 (same modules, same partition layout, same version), built for the
ESP32-C3 (RISC-V, Wi-Fi 4, 4 MB flash, e.g. the C3 with embedded flash). Differences:

* Bluetooth is switched off, as on the C6: xPython uses Wi-Fi and ESP-NOW only. 17 % of the
  firmware slot is free.
* The version label says `XPY_ESP32C3`, so a C3 accepts only C3 updates.
* Flashing: chip `esp32c3`, bootloader at `0x0`. The GUI does this by itself.
* No PSRAM and about 400 KB RAM: fine as a device; not meant as a gateway.

Build once: `./esp-idf/install.sh esp32c3` (the RISC-V compiler, shared with the C6), then the VS
Code task "ESP32-C3: build". The files are in `micropython/ports/esp32/build-XPY_ESP32C3/`.
