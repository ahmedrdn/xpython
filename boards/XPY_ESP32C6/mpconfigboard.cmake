# xPython on the ESP32-C6 (RISC-V, Wi-Fi 6, BLE 5, 4 MB flash or more)
include(boards/mpconfigboard_esp32c6_common.cmake)

list(APPEND SDKCONFIG_DEFAULTS
    boards/sdkconfig.csi
    ${MICROPY_BOARD_DIR}/sdkconfig.xpy
)
set(MICROPY_FROZEN_MANIFEST ${MICROPY_BOARD_DIR}/manifest.py)
