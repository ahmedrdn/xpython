// xPython on an ESP32-S3 board with 16 MB flash and 8 MB octal PSRAM (N16R8).
#define MICROPY_HW_BOARD_NAME               "xPython ESP32-S3 (16 MB flash, 8 MB PSRAM)"
#define MICROPY_HW_MCU_NAME                 "ESP32-S3"

// REPL on the UART port (USB-to-serial chip) as well as on the S3's own USB port.
#define MICROPY_HW_ENABLE_UART_REPL         (1)
