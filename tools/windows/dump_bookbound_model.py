"""Inspect the flat line records written by AutoBBLINEModelExtraction."""

from __future__ import annotations

import argparse
import pathlib
import struct


MODEL_BYTES = 0x494AF8
LINE_BASE = 0x64
LINE_BYTES = 0x5DD0
PAGE_LINE_CAPACITY = 100


def ints(data: bytes, offset: int, count: int) -> tuple[int, ...]:
    return struct.unpack_from(f"<{count}i", data, offset)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=pathlib.Path)
    args = parser.parse_args()
    data = args.model.read_bytes()
    if len(data) != MODEL_BYTES:
        raise ValueError(f"expected {MODEL_BYTES} bytes, got {len(data)}")

    print("corner-x", ints(data, 0, 6))
    print("corner-y", ints(data, 0x18, 6))
    print("boundary-counts", ints(data, 0x50, 4))
    print("line-counts", ints(data, 0x494AE4, 2))
    print("tail", ints(data, 0x494AEC, 3))
    for page, count in enumerate(ints(data, 0x494AE4, 2)):
        print(f"page {page}: {count} lines")
        for line in range(count):
            offset = LINE_BASE + (page * PAGE_LINE_CAPACITY + line) * LINE_BYTES
            x0, x1, y0, y1 = ints(data, offset, 4)
            point_count = max(0, min(6000, x1 - x0 + 1))
            if point_count:
                points = struct.unpack_from(f"<{point_count}f", data, offset + 0x10)
                minimum = min(points)
                maximum = max(points)
                middle = points[point_count // 2]
                summary = (
                    f"points={point_count} min={minimum:.4f} "
                    f"mid={middle:.4f} max={maximum:.4f}"
                )
            else:
                summary = "points=0"
            print(
                f"  {line:02d}: x={x0}..{x1} y={y0}..{y1} {summary}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
