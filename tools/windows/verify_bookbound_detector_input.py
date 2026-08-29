"""Verify ScanSnap's grayscale/downscale input to its LSD line detector."""

from __future__ import annotations

import argparse
import pathlib

import numpy as np

from render_bookbound_mesh import read_ppm


def report(name: str, expected: np.ndarray, candidate: np.ndarray) -> None:
    difference = np.abs(expected.astype(np.int16) - candidate.astype(np.int16))
    print(
        f"{name}: equal={np.array_equal(expected, candidate)} "
        f"matching={np.count_nonzero(difference == 0)}/{difference.size} "
        f"max={difference.max()} mean={difference.mean():.9f}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_ppm", type=pathlib.Path)
    parser.add_argument("left", type=pathlib.Path)
    parser.add_argument("right", type=pathlib.Path)
    args = parser.parse_args()

    source = read_ppm(args.input_ppm)
    expected = np.column_stack(
        (
            np.fromfile(args.left, dtype=np.uint8).reshape(1753, 1240),
            np.fromfile(args.right, dtype=np.uint8).reshape(1753, 1240),
        )
    )
    gray = (
        source[..., 0].astype(np.uint32) * 0x75
        + source[..., 1].astype(np.uint32) * 0x259
        + source[..., 2].astype(np.uint32) * 0x132
    ) >> 10
    report("even coordinates", expected, gray[0:3506:2, 0:4960:2].astype(np.uint8))

    source_y = np.trunc(np.arange(1753) * 3506.0 / 1753).astype(np.int64)
    source_x = np.trunc(np.arange(2480) * 4961.0 / 2480).astype(np.int64)
    report("floor ratio", expected, gray[source_y[:, None], source_x].astype(np.uint8))

    source_y = np.rint(np.arange(1753) * 3506.0 / 1753).astype(np.int64)
    source_x = np.rint(np.arange(2480) * 4961.0 / 2480).astype(np.int64)
    report("nearest ratio", expected, gray[source_y[:, None], source_x].astype(np.uint8))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
