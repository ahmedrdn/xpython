# XPY_ESP32S3: xPython on the ESP32-S3 (16 MB flash, 8 MB octal PSRAM, e.g. N16R8)

The same xPython as XPY_ESP32 (same modules, same firmware slots, same version), built for the ESP32-S3.
Differences:

* 8 MB PSRAM (octal): MicroPython's heap lives there, so apps and the gateway have far more memory.
* 16 MB flash: the two firmware slots are the same as on the 4 MB boards (0x10000 and 0x1E0000), only the
  file system is bigger (about 12 MB).
* The version label says `XPY_ESP32S3`, so an S3 accepts only S3 updates.
* Flashing: chip `esp32s3`, bootloader at `0x0`. The GUI does this by itself.
* Bluetooth stays on; 10 % of the firmware slot is free.

Build once: `./esp-idf/install.sh esp32s3`, then the VS Code task "ESP32-S3: build".
The files are in `micropython/ports/esp32/build-XPY_ESP32S3/`.
