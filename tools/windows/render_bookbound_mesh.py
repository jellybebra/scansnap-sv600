"""Replay ScanSnap's captured CMesh::SinglePageTransform mapping.

This is a research verifier for meshes dumped by trace_bookbound_oracle.py.  It
does not generate the mesh; it mirrors the fixed-point bilinear renderer found
in the original 32-bit bookbound.dll.
"""

from __future__ import annotations

import argparse
import pathlib
import struct

import numpy as np


def read_values(path: pathlib.Path, dtype: str) -> np.ndarray:
    return np.fromfile(path, dtype=dtype)


def find_one(directory: pathlib.Path, suffix: str) -> pathlib.Path:
    paths = list(directory.glob(f"*-{suffix}.bin"))
    if len(paths) != 1:
        raise ValueError(f"expected one *-{suffix}.bin in {directory}, got {paths}")
    return paths[0]


def read_ppm(path: pathlib.Path) -> np.ndarray:
    data = path.read_bytes()
    if not data.startswith(b"P6"):
        raise ValueError(f"{path}: not a P6 PPM")
    cursor = 2
    numbers: list[int] = []
    while len(numbers) < 3:
        while data[cursor] in b" \t\r\n":
            cursor += 1
        if data[cursor] == ord("#"):
            cursor = data.index(b"\n", cursor) + 1
            continue
        end = cursor
        while data[end] in b"0123456789":
            end += 1
        numbers.append(int(data[cursor:end]))
        cursor = end
    while data[cursor] in b" \t\r\n":
        cursor += 1
    width, height, maximum = numbers
    if maximum != 255:
        raise ValueError(f"{path}: unsupported maximum {maximum}")
    pixels = np.frombuffer(data, dtype=np.uint8, offset=cursor)
    expected = width * height * 3
    if pixels.size != expected:
        raise ValueError(f"{path}: expected {expected} pixel bytes, got {pixels.size}")
    return pixels.reshape(height, width, 3)


def write_ppm(path: pathlib.Path, pixels: np.ndarray) -> None:
    height, width, channels = pixels.shape
    if channels != 3 or pixels.dtype != np.uint8:
        raise ValueError("expected uint8 RGB pixels")
    with path.open("wb") as stream:
        stream.write(f"P6\n{width} {height}\n255\n".encode("ascii"))
        stream.write(pixels.tobytes())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace_dir", type=pathlib.Path)
    parser.add_argument("input_ppm", type=pathlib.Path)
    parser.add_argument("output_ppm", type=pathlib.Path)
    args = parser.parse_args()

    directory = args.trace_dir.resolve()
    source = read_ppm(args.input_ppm)
    height, width, _ = source.shape
    column_map = read_values(find_one(directory, "column-map"), "<f8")
    boundaries = read_values(find_one(directory, "row-boundaries"), "<i4")
    rows = []
    for row in range(len(boundaries)):
        xs = read_values(find_one(directory, f"row-{row}-x"), "<f8")
        ys = read_values(find_one(directory, f"row-{row}-y"), "<f8")
        if len(xs) != width or len(ys) != width:
            raise ValueError(f"row {row}: expected {width} mesh points")
        rows.append((xs, ys))

    destination = np.zeros_like(source)
    mapped_width = len(column_map)
    column_integer = np.trunc(column_map).astype(np.int64)
    column_fraction = column_map - column_integer
    if np.any(column_integer < 0) or np.any(column_integer + 1 >= width):
        raise ValueError("column map falls outside source")

    for band in range(len(boundaries) - 1):
        start = int(boundaries[band])
        end = int(boundaries[band + 1])
        span = end - start
        if span <= 0:
            continue
        x0s, y0s = rows[band]
        x1s, y1s = rows[band + 1]
        inverse_fraction = 1.0 - column_fraction
        x0 = (
            inverse_fraction * x0s[column_integer]
            + column_fraction * x0s[column_integer + 1]
        )
        y0 = (
            inverse_fraction * y0s[column_integer]
            + column_fraction * y0s[column_integer + 1]
        )
        x1 = (
            inverse_fraction * x1s[column_integer]
            + column_fraction * x1s[column_integer + 1]
        )
        y1 = (
            inverse_fraction * y1s[column_integer]
            + column_fraction * y1s[column_integer + 1]
        )
        x_fixed = np.trunc(x0 * 65536.0).astype(np.int64)
        y_fixed = np.trunc(y0 * 32768.0).astype(np.int64)
        x_step = np.trunc((x1 - x0) * 65536.0 / span).astype(np.int64)
        y_step = np.trunc((y1 - y0) * 32768.0 / span).astype(np.int64)

        for output_y in range(start, end):
            source_x = x_fixed >> 16
            source_y = y_fixed >> 15
            fraction_x = x_fixed & 0xFFFF
            fraction_y = y_fixed & 0x7FFF
            if (
                np.any(source_x < 0)
                or np.any(source_x + 1 >= width)
                or np.any(source_y < 0)
                or np.any(source_y + 1 >= height)
            ):
                raise ValueError(f"band {band}, y {output_y}: source point out of range")
            weight_10 = ((65536 - fraction_x) * fraction_y) >> 9
            weight_01 = ((32768 - fraction_y) * fraction_x) >> 9
            weight_11 = (fraction_y * fraction_x) >> 9
            weight_00 = ((32768 - fraction_y) * (65536 - fraction_x)) >> 9
            upper_left = source[source_y, source_x].astype(np.int64)
            lower_left = source[source_y + 1, source_x].astype(np.int64)
            upper_right = source[source_y, source_x + 1].astype(np.int64)
            lower_right = source[source_y + 1, source_x + 1].astype(np.int64)
            value = (
                lower_right * weight_11[:, None]
                + lower_left * weight_10[:, None]
                + upper_right * weight_01[:, None]
                + upper_left * weight_00[:, None]
            ) >> 22
            destination[output_y, :mapped_width] = value.astype(np.uint8)
            x_fixed += x_step
            y_fixed += y_step

    write_ppm(args.output_ppm, destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
