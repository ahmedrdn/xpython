# xPython security, stage 1: signed firmware, no eFuses burned
CONFIG_ESP32_REV_MIN_3=y
CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y
CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y
CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y
CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y
CONFIG_SECURE_BOOT_SIGNING_KEY="/home/ahmed/xpython/keys/secure_boot_signing_key.pem"
# OTA: two firmware slots, and automatic rollback if a new firmware isn't confirmed
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="/home/ahmed/xpython/boards/XPY_ESP32/partitions-xpy-ota.csv"
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
