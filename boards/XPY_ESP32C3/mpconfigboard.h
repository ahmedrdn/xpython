// xPython on a generic ESP32-C3 board with 4 MB (or more) of flash.
#define MICROPY_HW_BOARD_NAME               "xPython ESP32-C3"
#define MICROPY_HW_MCU_NAME                 "ESP32-C3"

// REPL on the UART (boards with a USB-to-serial chip). Boards that use the C3's own
// USB port show the REPL there too.
#define MICROPY_HW_ENABLE_UART_REPL         (1)

// No Bluetooth (see sdkconfig.xpy): xPython uses Wi-Fi and ESP-NOW. Keeps the firmware
// small enough for one OTA slot.
#define MICROPY_PY_BLUETOOTH                (0)
