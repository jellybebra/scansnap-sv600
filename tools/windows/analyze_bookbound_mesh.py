"""Summarize a page-transform mesh captured by trace_bookbound_oracle.py."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import struct


def read_values(path: pathlib.Path, code: str) -> tuple[int | float, ...]:
    data = path.read_bytes()
    size = struct.calcsize(code)
    if len(data) % size:
        raise ValueError(f"{path}: {len(data)} bytes is not a multiple of {size}")
    return struct.unpack(f"<{len(data) // size}{code}", data)


def find_one(directory: pathlib.Path, suffix: str) -> pathlib.Path:
    paths = list(directory.glob(f"*-{suffix}.bin"))
    if len(paths) != 1:
        raise ValueError(f"expected one *-{suffix}.bin in {directory}, got {paths}")
    return paths[0]


def describe(values: tuple[float, ...]) -> str:
    return (
        f"min={min(values):.9f} max={max(values):.9f} "
        f"first={values[0]:.9f} last={values[-1]:.9f}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace_dir", type=pathlib.Path)
    args = parser.parse_args()
    directory = args.trace_dir.resolve()

    column_map = read_values(find_one(directory, "column-map"), "d")
    boundaries = read_values(find_one(directory, "row-boundaries"), "i")
    print(f"column-map: count={len(column_map)} {describe(column_map)}")
    print(f"row-boundaries: {boundaries}")

    width = None
    for row in range(len(boundaries)):
        x_path = find_one(directory, f"row-{row}-x")
        y_path = find_one(directory, f"row-{row}-y")
        xs = read_values(x_path, "d")
        ys = read_values(y_path, "d")
        if width is None:
            width = len(xs)
        if len(xs) != width or len(ys) != width:
            raise ValueError(f"row {row}: inconsistent width")
        x_linear_error = max(abs(value - index) for index, value in enumerate(xs))
        y_mean = sum(ys) / len(ys)
        y_spread = max(abs(value - y_mean) for value in ys)
        digest = hashlib.sha256(x_path.read_bytes() + y_path.read_bytes()).hexdigest()
        print(
            f"row {row:02d}: x[{describe(xs)}] max|x-index|={x_linear_error:.6f}; "
            f"y[{describe(ys)}] mean={y_mean:.6f} spread={y_spread:.6f}; "
            f"sha256={digest[:16]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
