"""Compare two internal page-transform meshes captured from bookbound.dll."""

from __future__ import annotations

import argparse
import pathlib

import numpy as np


def find_one(directory: pathlib.Path, suffix: str) -> pathlib.Path:
    paths = list(directory.glob(f"*-{suffix}.bin"))
    if len(paths) != 1:
        raise ValueError(f"expected one *-{suffix}.bin in {directory}, got {paths}")
    return paths[0]


def values(directory: pathlib.Path, suffix: str, dtype: str) -> np.ndarray:
    return np.fromfile(find_one(directory, suffix), dtype=dtype)


def difference(left: np.ndarray, right: np.ndarray) -> str:
    if left.shape != right.shape:
        return f"shapes={left.shape}/{right.shape}"
    delta = np.abs(left.astype(np.float64) - right.astype(np.float64))
    return (
        f"equal={np.array_equal(left, right)} "
        f"max={delta.max():.9f} mean={delta.mean():.9f} "
        f"changed={np.count_nonzero(delta)}/{delta.size}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", type=pathlib.Path)
    parser.add_argument("candidate", type=pathlib.Path)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    reference = args.reference.resolve()
    candidate = args.candidate.resolve()

    print(
        "column-map:",
        difference(
            values(reference, "column-map", "<f8"),
            values(candidate, "column-map", "<f8"),
        ),
    )
    left_boundaries = values(reference, "row-boundaries", "<i4")
    right_boundaries = values(candidate, "row-boundaries", "<i4")
    print("boundaries:", difference(left_boundaries, right_boundaries))
    print("  reference:", tuple(left_boundaries))
    print("  candidate:", tuple(right_boundaries))
    row_count = min(len(left_boundaries), len(right_boundaries))
    x_maximum = 0.0
    y_maximum = 0.0
    y_mean_sum = 0.0
    y_value_count = 0
    for row in range(row_count):
        left_x = values(reference, f"row-{row}-x", "<f8")
        right_x = values(candidate, f"row-{row}-x", "<f8")
        left_y = values(reference, f"row-{row}-y", "<f8")
        right_y = values(candidate, f"row-{row}-y", "<f8")
        x_delta = np.abs(left_x.astype(np.float64) - right_x.astype(np.float64))
        y_delta = np.abs(left_y.astype(np.float64) - right_y.astype(np.float64))
        x_maximum = max(x_maximum, float(x_delta.max()))
        y_maximum = max(y_maximum, float(y_delta.max()))
        y_mean_sum += float(y_delta.sum())
        y_value_count += y_delta.size
        if not args.summary:
            print(
                f"row {row:02d}: x[{difference(left_x, right_x)}] "
                f"y[{difference(left_y, right_y)}]"
            )
    print(
        f"all rows: max-x={x_maximum:.12g} max-y={y_maximum:.9f} "
        f"mean-y={y_mean_sum / y_value_count:.9f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
