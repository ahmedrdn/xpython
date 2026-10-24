include("$(PORT_DIR)/boards/manifest.py")
module("xsfs.py", base_path="$(BOARD_DIR)/../../frozen")
module("xloader.py", base_path="$(BOARD_DIR)/../../frozen")
module("xexec.py", base_path="$(BOARD_DIR)/../../frozen")