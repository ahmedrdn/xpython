# xPython on the ESP32-C3 (RISC-V, Wi-Fi 4, BLE 5, 4 MB flash)
include(boards/mpconfigboard_esp32c3_common.cmake)

list(APPEND SDKCONFIG_DEFAULTS
    boards/sdkconfig.csi
    ${MICROPY_BOARD_DIR}/sdkconfig.xpy
)
set(MICROPY_FROZEN_MANIFEST ${MICROPY_BOARD_DIR}/manifest.py)
