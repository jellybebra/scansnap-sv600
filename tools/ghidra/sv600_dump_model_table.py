# Dump the PfuSsImgCtl model table used by FUN_10021df0.
# @category ScanSnap

from ghidra.program.model.address import Address


args = getScriptArgs()
base_text = args[0] if args else "101bf510"
entry_size = int(args[1], 0) if len(args) > 1 else 0x60
max_entries = int(args[2], 0) if len(args) > 2 else 64

memory = currentProgram.getMemory()
base = toAddr(base_text)


def read_u32(address):
    return sum(
        (memory.getByte(address.add(index)) & 0xff) << (index * 8)
        for index in range(4)
    )


def read_c_string(address, limit):
    chars = []
    for offset in range(limit):
        value = memory.getByte(address.add(offset)) & 0xff
        if value == 0:
            break
        chars.append(chr(value) if 0x20 <= value < 0x7f else ".")
    return "".join(chars)


def read_ascii_runs(address, limit):
    runs = []
    start = None
    chars = []
    for offset in range(limit + 1):
        value = 0 if offset == limit else memory.getByte(address.add(offset)) & 0xff
        if 0x20 <= value < 0x7f:
            if start is None:
                start = offset
            chars.append(chr(value))
        else:
            if start is not None and len(chars) >= 2:
                runs.append("+0x{:02x}={!r}".format(start, "".join(chars)))
            start = None
            chars = []
    return ", ".join(runs)


for index in range(max_entries):
    entry = base.add(index * entry_size)
    model_type = read_u32(entry)
    if model_type == 0xffffffff:
        println("{:02d} {} type=-1 END".format(index, entry))
        break
    println(
        "{:02d} {} type=0x{:08x} name={!r}".format(
            index, entry, model_type, read_ascii_runs(entry, entry_size)
        )
    )
