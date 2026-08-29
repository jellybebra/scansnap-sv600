# Dump raw scalar interpretations at supplied virtual addresses.
# @category ScanSnap

import struct


memory = currentProgram.getMemory()

for text in getScriptArgs():
    address = currentProgram.getAddressFactory().getAddress(text)
    if address is None:
        printerr("Invalid address: {}".format(text))
        continue
    data = bytearray(8)
    memory.getBytes(address, data)
    raw = bytes(data)
    println(
        "{} raw={} u32={} i32={} f32={!r} f64={!r}".format(
            address,
            raw.hex(),
            struct.unpack("<I", raw[:4])[0],
            struct.unpack("<i", raw[:4])[0],
            struct.unpack("<f", raw[:4])[0],
            struct.unpack("<d", raw)[0],
        )
    )
