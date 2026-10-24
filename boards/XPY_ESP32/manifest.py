include("$(PORT_DIR)/boards/manifest.py")

# xPython modules written in Python: frozen into the firmware
for name in ("xfw", "xsfs", "xloader", "xexec", "xnet", "xota"):
    module(name + ".py", base_path="$(BOARD_DIR)/../../modules/" + name)