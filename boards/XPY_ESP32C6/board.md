# XPY_ESP32C6: xPython on the ESP32-C6

The same xPython as XPY_ESP32 (same modules, same partition layout, same version), built for the
ESP32-C6 (RISC-V, Wi-Fi 6). Differences:

* Bluetooth is switched off: xPython uses Wi-Fi and ESP-NOW only. With BLE the firmware did not fit
  one OTA slot (68 KB too big); without it, 14 % of the slot is free.
* The version label says `XPY_ESP32C6`, so a C6 refuses ESP32 updates and an ESP32 refuses C6 updates.
* Flashing: chip `esp32c6`, bootloader at `0x0` (the ESP32 uses `0x1000`). The GUI does this by itself.
* ESP-NOW works between a C6 and a classic ESP32 on the same Wi-Fi channel, so they can share a gateway.

Build once: `./esp-idf/install.sh esp32c6` (adds the RISC-V compiler), then the VS Code task
"ESP32-C6: build". The files are in `micropython/ports/esp32/build-XPY_ESP32C6/`.
