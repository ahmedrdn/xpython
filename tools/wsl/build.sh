#!/bin/bash
# Build the xPython firmware in WSL and copy it to Windows:  Documents\xPython\firmware
# Run from the xpython folder:   bash tools/wsl/build.sh
set -e
cd "$(dirname "$0")/../.."
source esp-idf/export.sh > /dev/null
make -C micropython/ports/esp32 BOARD=XPY_ESP32 BOARD_DIR=$PWD/boards/XPY_ESP32 \
     USER_C_MODULES=$PWD/modules/micropython.cmake

B=micropython/ports/esp32/build-XPY_ESP32
DOCS=$(powershell.exe -NoProfile -Command '[Environment]::GetFolderPath("MyDocuments")' | tr -d '\r')
OUT="$(wslpath "$DOCS")/xPython/firmware"
mkdir -p "$OUT"
cp $B/micropython.bin $B/bootloader/bootloader.bin $B/partition_table/partition-table.bin "$OUT/"
echo
echo "Firmware copied to: $DOCS\\xPython\\firmware"
echo "  micropython.bin      <- choose this file in the GUI (Firmware tab)"
echo "  bootloader.bin, partition-table.bin  (used by Erase + flash)"
