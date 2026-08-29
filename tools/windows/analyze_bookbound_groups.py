"""Summarize polylines passed from PFU's grouping stage to interpolation."""

from __future__ import annotations

import argparse
import pathlib
import re
import struct


PATTERN = re.compile(r"-group-(\d+)-(\d+)-x\.bin$")


def floats(path: pathlib.Path) -> tuple[float, ...]:
    data = path.read_bytes()
    return struct.unpack(f"<{len(data) // 4}f", data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace_dir", type=pathlib.Path)
    args = parser.parse_args()
    directory = args.trace_dir.resolve()
    lines = []
    for x_path in directory.glob("*-InterpolateLine-enter-group-*-*-x.bin"):
        match = PATTERN.search(x_path.name)
        if not match:
            continue
        page, line = (int(value) for value in match.groups())
        y_paths = list(
            directory.glob(f"*-InterpolateLine-enter-group-{page}-{line}-y.bin")
        )
        if len(y_paths) != 1:
            raise ValueError(f"missing y data for {x_path}")
        lines.append((page, line, x_path, y_paths[0]))
    for page, line, x_path, y_path in sorted(lines):
        xs = floats(x_path)
        ys = floats(y_path)
        if len(xs) != len(ys):
            raise ValueError(f"line {page}:{line}: x/y lengths differ")
        print(
            f"{page}:{line:02d} n={len(xs)} "
            f"x={xs[0]:.3f}..{xs[-1]:.3f} "
            f"y={ys[0]:.3f}..{ys[-1]:.3f} "
            f"y-min={min(ys):.3f} y-max={max(ys):.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
