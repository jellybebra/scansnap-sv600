#!/usr/bin/env python3
"""Reproduce the SV600 factory per-channel optical remap for analysis.

The map is embedded in the original SV600u-x64.dll.  This tool deliberately
requires that DLL as an input and never copies it into the project.  The
interpolation and fixed-point conversion mirror the 300 dpi manual kernel in
the minidriver and are useful for checking the clean-room SANE port against a
captured Windows boundary image.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

import numpy as np
from PIL import Image


TABLE_RVA = 0x128270
TABLE_ROWS = 4700
TABLE_COLUMNS = 6
OUTPUT_LINES = 2781
VERTICAL_ONE = 1 << 12
HORIZONTAL_ONE = 1 << 19


def pe_rva_to_file_offset(image: bytes, rva: int) -> int:
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("not a PE image")

    section_count = struct.unpack_from("<H", image, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe_offset + 20)[0]
    section_offset = pe_offset + 24 + optional_size
    for index in range(section_count):
        entry = section_offset + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", image, entry + 8
        )
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta >= raw_size:
                raise ValueError(f"RVA 0x{rva:x} points past raw section data")
            return raw_offset + delta
    raise ValueError(f"RVA 0x{rva:x} is not in a PE section")


def load_factory_table(dll_path: Path) -> np.ndarray:
    image = dll_path.read_bytes()
    offset = pe_rva_to_file_offset(image, TABLE_RVA)
    byte_count = TABLE_ROWS * TABLE_COLUMNS * 4
    table = np.frombuffer(image, dtype="<f4", count=TABLE_ROWS * TABLE_COLUMNS,
                          offset=offset)
    if table.nbytes != byte_count:
        raise ValueError("the factory table is truncated")
    table = table.reshape(TABLE_ROWS, TABLE_COLUMNS).copy()

    expected_first = np.array(
        [0.7022366, 0.0, -0.71024567, 0.94728684, 0.9466673, 0.94604826],
        dtype=np.float32,
    )
    if not np.array_equal(table[0], expected_first):
        raise ValueError("the DLL does not contain the known SV600 factory table")
    return table


def bilinear_channel(
    source: np.ndarray,
    output_y: np.ndarray,
    horizontal_step: np.ndarray,
) -> np.ndarray:
    source_height, source_width = source.shape
    output_height = output_y.shape[0]
    result = np.empty((output_height, source_width), dtype=np.uint8)
    center = source_width // 2
    output_x = np.arange(source_width, dtype=np.int64)

    for y in range(output_height):
        step = int(horizontal_step[y])
        # Exact center-based starting accumulator used by FUN_1c3ac460.
        x_fixed = (
            (step >> 1)
            + center * HORIZONTAL_ONE
            - (HORIZONTAL_ONE >> 1)
            - step * center
            + output_x * step
        )
        raw_x0 = x_fixed >> 19
        x_fraction = x_fixed & (HORIZONTAL_ONE - 1)
        x0 = np.clip(raw_x0, 0, source_width - 1)
        x_fraction = np.where(
            (raw_x0 < 0) | (raw_x0 >= source_width - 1), 0, x_fraction
        )
        x1 = np.clip(x0 + 1, 0, source_width - 1)

        y_fixed = int(output_y[y])
        y0 = y_fixed >> 12
        y_fraction = y_fixed & (VERTICAL_ONE - 1)
        if y0 < 0:
            y0 = 0
            y_fraction = 0
        elif y0 >= source_height - 1:
            y0 = source_height - 1
            y_fraction = 0
        y1 = min(y0 + 1, source_height - 1)

        top_left = source[y0, x0].astype(np.int64)
        top_right = source[y0, x1].astype(np.int64)
        if not y_fraction:
            value = (
                top_left * (HORIZONTAL_ONE - x_fraction)
                + top_right * x_fraction
            ) >> 19
        else:
            bottom_left = source[y1, x0].astype(np.int64)
            bottom_right = source[y1, x1].astype(np.int64)
            x_fraction_q12 = x_fraction >> 7
            value = (
                bottom_left * (VERTICAL_ONE - x_fraction_q12) * y_fraction
                + bottom_right * x_fraction_q12 * y_fraction
                + top_right * x_fraction_q12
                * (VERTICAL_ONE - y_fraction)
                + top_left * (VERTICAL_ONE - x_fraction_q12)
                * (VERTICAL_ONE - y_fraction)
            ) >> 24
        result[y] = np.clip(value, 0, 255).astype(np.uint8)
    return result


def correct(source: np.ndarray, table: np.ndarray, output_lines: int) -> np.ndarray:
    if source.ndim != 3 or source.shape[2] != 3 or source.dtype != np.uint8:
        raise ValueError("input must be an 8-bit RGB image")
    if output_lines > source.shape[0] or output_lines > table.shape[0]:
        raise ValueError("requested output exceeds source or correction map")

    rows = table[:output_lines]
    # C casts in MakeHorizonDistortionValue truncate toward zero.
    vertical_offset = np.trunc(rows[:, :3] * VERTICAL_ONE).astype(np.int64)
    horizontal_step = np.trunc(rows[:, 3:] * HORIZONTAL_ONE).astype(np.int64)
    base_y = np.arange(output_lines, dtype=np.int64) * VERTICAL_ONE

    result = np.empty((output_lines, source.shape[1], 3), dtype=np.uint8)
    for channel in range(3):
        result[:, :, channel] = bilinear_channel(
            source[:, :, channel],
            base_y + vertical_offset[:, channel],
            horizontal_step[:, channel],
        )
    return result


def emit_c_deltas(dll_path: Path, output_path: Path) -> None:
    # Keep the complete factory table in the backend.  Flat A3 needs more
    # corrected depth lines than the A4 driver-boundary fixture, while the
    # prototype's default output remains that observed 2781-line A4 boundary.
    table = load_factory_table(dll_path)[:TABLE_ROWS]
    fixed = np.concatenate(
        (
            np.trunc(table[:, :3] * VERTICAL_ONE),
            np.trunc(table[:, 3:] * HORIZONTAL_ONE),
        ),
        axis=1,
    ).astype(np.int32)
    # Green has no vertical displacement.  Store the remaining five columns
    # as exact signed byte deltas; all factory row-to-row changes fit int8.
    compact = fixed[:, [0, 2, 3, 4, 5]]
    deltas = np.diff(compact, axis=0)
    if np.any(deltas < -128) or np.any(deltas > 127):
        raise ValueError("factory-map deltas no longer fit signed bytes")

    dll_hash = hashlib.sha256(dll_path.read_bytes()).hexdigest().upper()
    map_hash = hashlib.sha256(fixed.astype("<i4").tobytes()).hexdigest()
    lines = [
        "/* Generated by tools/prototype_sv600_optical_correction.py.",
        f" * Source SV600u-x64.dll SHA-256: {dll_hash}",
        f" * Expanded {TABLE_ROWS}x6 fixed-point map SHA-256: {map_hash}",
        " * Columns: vertical R/B (Q12), horizontal R/G/B (Q19).",
        " */",
        f"#define SV600_FACTORY_MAP_ROWS {TABLE_ROWS}",
        "static const int32_t sv600_factory_map_first[5] = {",
        "  " + ", ".join(str(value) for value in compact[0]) + "",
        "};",
        "static const int8_t sv600_factory_map_deltas",
        "  [SV600_FACTORY_MAP_ROWS - 1][5] = {",
    ]
    lines.extend(
        "  {" + ",".join(str(value) for value in row) + "},"
        for row in deltas
    )
    lines.extend(["};", ""])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="ascii", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dll", type=Path, help="original SV600u-x64.dll")
    parser.add_argument("input", type=Path, nargs="?",
                        help="firmware-level RGB image")
    parser.add_argument("output", type=Path, nargs="?",
                        help="corrected RGB image")
    parser.add_argument("--lines", type=int, default=OUTPUT_LINES)
    parser.add_argument("--emit-c-deltas", type=Path,
                        help="write the compact clean-room C correction map")
    args = parser.parse_args()

    if args.emit_c_deltas:
        emit_c_deltas(args.dll, args.emit_c_deltas)
        return
    if args.input is None or args.output is None:
        parser.error("input and output are required unless --emit-c-deltas is used")

    table = load_factory_table(args.dll)
    source = np.asarray(Image.open(args.input).convert("RGB"))
    result = correct(source, table, args.lines)
    Image.fromarray(result, "RGB").save(args.output)


if __name__ == "__main__":
    main()
