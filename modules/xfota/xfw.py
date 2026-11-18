# xfw: facts about this firmware (frozen into it).
# TAG is kept as ONE literal string so it appears unchanged inside the firmware image:
# the PC tools read the board and version from the .bin itself (no source code needed).
# To release a new firmware, raise the version here, then build.
TAG = "XPY-FW:XPY_ESP32:1.6.5"
BOARD, VERSION = TAG.split(":")[1:]
SELF_TEST_FAIL = False  # set to True to fail the self-test and force rollback
