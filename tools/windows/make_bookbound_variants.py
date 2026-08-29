"""Create controlled PPM inputs for studying bookbound.dll mesh extraction."""

from __future__ import annotations

import argparse
import pathlib

import numpy as np

from render_bookbound_mesh import read_ppm, write_ppm


def shifted(source: np.ndarray, dx: int, dy: int) -> np.ndarray:
    height, width, _ = source.shape
    result = np.full_like(source, 255)
    source_x0 = max(0, -dx)
    source_y0 = max(0, -dy)
    target_x0 = max(0, dx)
    target_y0 = max(0, dy)
    copy_width = min(width - source_x0, width - target_x0)
    copy_height = min(height - source_y0, height - target_y0)
    result[
        target_y0 : target_y0 + copy_height,
        target_x0 : target_x0 + copy_width,
    ] = source[
        source_y0 : source_y0 + copy_height,
        source_x0 : source_x0 + copy_width,
    ]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_ppm", type=pathlib.Path)
    parser.add_argument("output_dir", type=pathlib.Path)
    args = parser.parse_args()

    source = read_ppm(args.input_ppm)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    variants: dict[str, np.ndarray] = {
        "gray": np.repeat(
            np.rint(
                source[..., 0] * 0.299
                + source[..., 1] * 0.587
                + source[..., 2] * 0.114
            ).astype(np.uint8)[..., None],
            3,
            axis=2,
        ),
        "bright": np.clip(
            (source.astype(np.float64) / 255.0) ** (1.0 / 1.8) * 255.0,
            0,
            255,
        ).astype(np.uint8),
        "shift-x-plus-120": shifted(source, 120, 0),
        "shift-y-plus-80": shifted(source, 0, 80),
        "flip-x": source[:, ::-1].copy(),
        "left-white": source.copy(),
        "right-white": source.copy(),
        "blank-white": np.full_like(source, 255),
    }
    variants["left-white"][:, : source.shape[1] // 2] = 255
    variants["right-white"][:, source.shape[1] // 2 :] = 255
    for name, pixels in variants.items():
        write_ppm(output / f"{name}.ppm", pixels)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
