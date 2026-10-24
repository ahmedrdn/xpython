# Show the ESP32's OTA boot records (the otadata partition).
import esp32, struct

p = esp32.Partition.find(esp32.Partition.TYPE_DATA, label="otadata")[0]
names = {0: "NEW", 1: "PENDING_VERIFY", 2: "VALID", 3: "INVALID",
         4: "ABORTED", 0xFFFFFFFF: "UNDEFINED"}
buf = bytearray(4096)
for sector in (0, 1):
    p.readblocks(sector, buf)
    seq = struct.unpack_from("<I", buf, 0)[0]       # sequence number: picks the slot
    state = struct.unpack_from("<I", buf, 24)[0]    # trial state of that boot choice
    print("record", sector, "| seq", hex(seq), "| state", names.get(state, hex(state)))
print("running:", esp32.Partition(esp32.Partition.RUNNING).info()[4])