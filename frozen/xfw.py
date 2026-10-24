# xfw: the firmware's identity (frozen into the firmware).
# Raise VERSION for every firmware you release: OTA only accepts newer versions.
VERSION = "1.0.1"
BOARD = "XPY_ESP32"

# For the rollback test ONLY: a firmware built with True fails its self-test,
# so the device must roll back to the previous firmware.
SELF_TEST_FAIL = False