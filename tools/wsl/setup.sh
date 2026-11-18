#!/bin/bash
# One-time setup of the xPython firmware build inside WSL (Ubuntu on Windows).
# Run from the xpython folder:   bash tools/wsl/setup.sh
# Downloads MicroPython and ESP-IDF next to the xpython code (they are not in git).
set -e
cd "$(dirname "$0")/../.."
MP_VERSION=v1.29.0
IDF_VERSION=${IDF_VERSION:-v5.5.2}      # use the same version as before (old machine: idf.py --version)

echo "== 1/4 Ubuntu packages"
sudo apt-get update
sudo apt-get install -y git wget flex bison gperf python3 python3-pip python3-venv cmake \
     ninja-build ccache libffi-dev libssl-dev dfu-util libusb-1.0-0 build-essential zip

echo "== 2/4 MicroPython $MP_VERSION"
[ -d micropython ] || git clone -b $MP_VERSION --depth 1 https://github.com/micropython/micropython
make -C micropython/mpy-cross

echo "== 3/4 ESP-IDF $IDF_VERSION (takes a while)"
[ -d esp-idf ] || git clone -b $IDF_VERSION --depth 1 --recursive --shallow-submodules https://github.com/espressif/esp-idf
./esp-idf/install.sh esp32

echo "== 4/4 MicroPython's ESP32 libraries"
source esp-idf/export.sh > /dev/null
make -C micropython/ports/esp32 BOARD=XPY_ESP32 BOARD_DIR=$PWD/boards/XPY_ESP32 submodules

echo "Setup done. Build the firmware with:  bash tools/wsl/build.sh"
