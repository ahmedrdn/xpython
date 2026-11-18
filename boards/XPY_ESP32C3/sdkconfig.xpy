# xPython security, stage 1: signed firmware, no eFuses burned (same as XPY_ESP32)
CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y
CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y
CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y
CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y
CONFIG_SECURE_BOOT_SIGNING_KEY="/home/ahmed/xpython/keys/secure_boot_signing_key.pem"
# OTA: the same two firmware slots + file system as XPY_ESP32 (4 MB flash)
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="/home/ahmed/xpython/boards/XPY_ESP32/partitions-xpy-ota.csv"
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y
# The firmware must fit one 1.8 MB slot
CONFIG_COMPILER_OPTIMIZATION_SIZE=y
# Bluetooth off: xPython uses Wi-Fi and ESP-NOW, not BLE. Saves ~200 KB, so the
# firmware fits one OTA slot (with BLE the C3 firmware is 68 KB too big).
CONFIG_BT_ENABLED=n
