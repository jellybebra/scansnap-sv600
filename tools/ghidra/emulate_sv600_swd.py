#!/usr/bin/env python3
"""Emulate the SV600 Windows minidriver's SendSWDData transformation.

The function at 0x1c38eb30 converts a generic 72-byte SET WINDOW block into
the device-specific Comet block.  Execution stops at the transport builder
(0x1c382dc0) and prints the exact outgoing payload without running Windows.
"""

import argparse
import struct

import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
)


SEND_SWD_DATA = 0x1C38EB30
BUILD_COMMAND = 0x1C382DC0
LOG_FLAGS = 0x1C425144
OBJECT_BASE = 0x50000000
INPUT_BASE = 0x60000000
STACK_BASE = 0x70000000
PAGE_SIZE = 0x1000


def align_up(value, alignment=PAGE_SIZE):
    return (value + alignment - 1) & ~(alignment - 1)


def put_u16(uc, address, value):
    uc.mem_write(address, struct.pack("<H", value & 0xFFFF))


def put_u32(uc, address, value):
    uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))


def put_u64(uc, address, value):
    uc.mem_write(address, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))


def make_intermediate_window(width, height, resolution):
    payload = bytearray(72)
    payload[7] = 0x40
    struct.pack_into(">H", payload, 10, resolution)
    struct.pack_into(">H", payload, 12, resolution)
    struct.pack_into(">I", payload, 14, 0)
    struct.pack_into(">I", payload, 18, 0)
    struct.pack_into(">I", payload, 22, width)
    struct.pack_into(">I", payload, 26, height)
    payload[33] = 0x05
    payload[34] = 0x08
    return payload


def emulate(args):
    pe = pefile.PE(args.dll, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image = pe.get_memory_mapped_image()
    image_size = align_up(max(len(image), pe.OPTIONAL_HEADER.SizeOfImage))

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(image_base, image_size)
    uc.mem_write(image_base, image)
    uc.mem_map(OBJECT_BASE, 0x300000)
    uc.mem_map(INPUT_BASE, PAGE_SIZE)
    uc.mem_map(STACK_BASE, 0x20000)

    # The raw PE contains the pre-loader IAT and debug defaults.  Disable the
    # optional logging branch so emulation stays inside the transformation.
    put_u32(uc, LOG_FLAGS, 0)

    # Fields read by the model-6000 path.  Large sensor bounds prevent the
    # emulation fixture from clipping the requested 100 mm test window.
    put_u32(uc, OBJECT_BASE + 0x2C9828, 6000)
    put_u16(uc, OBJECT_BASE + 0x1DCA, args.compression_enabled)
    put_u16(uc, OBJECT_BASE + 0x1DCE, args.resolution_quirk)
    put_u16(uc, OBJECT_BASE + 0x1DD0, args.rif_enabled)
    put_u16(uc, OBJECT_BASE + 0x227A, args.max_x)
    put_u16(uc, OBJECT_BASE + 0x227C, args.max_y)
    put_u16(uc, OBJECT_BASE + 0x2280, args.max_y)
    put_u16(uc, OBJECT_BASE + 0x2282, args.max_x)

    intermediate = make_intermediate_window(
        args.width, args.height, args.resolution
    )
    uc.mem_write(INPUT_BASE, bytes(intermediate))

    rsp = STACK_BASE + 0x1F000
    put_u64(uc, rsp, 0)
    # Windows x64 ABI: arguments five and six follow the 32-byte shadow area.
    put_u64(uc, rsp + 0x28, args.vendor_selector)
    put_u64(uc, rsp + 0x30, args.param6)
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RCX, OBJECT_BASE)
    uc.reg_write(UC_X86_REG_RDX, INPUT_BASE)
    uc.reg_write(UC_X86_REG_R8, len(intermediate))
    uc.reg_write(UC_X86_REG_R9, args.side)

    captured = {}
    recent_addresses = []

    def hook_code(engine, address, size, _user_data):
        recent_addresses.append(address)
        if len(recent_addresses) > 12:
            del recent_addresses[0]
        if address != BUILD_COMMAND:
            return
        command = engine.reg_read(UC_X86_REG_RDX)
        call_rsp = engine.reg_read(UC_X86_REG_RSP)
        out_ptr = struct.unpack(
            "<Q", engine.mem_read(call_rsp + 0x28, 8)
        )[0]
        out_len = struct.unpack(
            "<Q", engine.mem_read(call_rsp + 0x30, 8)
        )[0]
        captured["command"] = command
        captured["payload"] = bytes(engine.mem_read(out_ptr, out_len))
        engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)
    try:
        uc.emu_start(SEND_SWD_DATA, 0, count=200000)
    except UcError as error:
        rip = uc.reg_read(UC_X86_REG_RIP)
        rsp_at_error = uc.reg_read(UC_X86_REG_RSP)
        raise RuntimeError(
            "emulation failed at RIP=0x{:x}, RSP=0x{:x}: {}; recent={}".format(
                rip,
                rsp_at_error,
                error,
                ",".join("0x{:x}".format(address) for address in recent_addresses),
            )
        ) from error

    if not captured:
        raise RuntimeError("SendSWDData did not reach the command builder")

    payload = captured["payload"]
    print("command=0x{:02x} length={}".format(captured["command"], len(payload)))
    for offset in range(0, len(payload), 16):
        chunk = payload[offset : offset + 16]
        print("{:03x}: {}".format(offset, " ".join("{:02x}".format(b) for b in chunk)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dll")
    parser.add_argument("--width", type=int, default=1181)
    parser.add_argument("--height", type=int, default=1180)
    parser.add_argument("--resolution", type=int, default=300)
    parser.add_argument("--side", type=int, choices=(0, 1, 2), default=0)
    parser.add_argument("--vendor-selector", type=int, default=0)
    parser.add_argument("--param6", type=int, default=1)
    parser.add_argument("--compression-enabled", type=int, default=1)
    parser.add_argument("--resolution-quirk", type=int, default=0)
    parser.add_argument("--rif-enabled", type=int, default=1)
    parser.add_argument("--max-x", type=int, default=20000)
    parser.add_argument("--max-y", type=int, default=20000)
    emulate(parser.parse_args())


if __name__ == "__main__":
    main()
