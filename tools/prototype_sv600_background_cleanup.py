#!/usr/bin/env python3
"""Preview the fixed-page edge-background cleanup used by the SANE backend."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw


def cleanup(
    image: Image.Image, resolution: int = 300
) -> tuple[Image.Image, dict[str, int | float | bool]]:
    rgb = np.asarray(image.convert("RGB")).copy()
    red = rgb[:, :, 0].astype(np.uint16)
    green = rgb[:, :, 1].astype(np.uint16)
    blue = rgb[:, :, 2].astype(np.uint16)
    luminance = (77 * red + 150 * green + 29 * blue) >> 8
    chroma = rgb.max(axis=2).astype(np.int16) - rgb.min(axis=2)

    histogram = np.bincount(luminance.ravel(), minlength=256)
    percentile_target = (luminance.size * 95 + 99) // 100
    paper_peak = int(np.searchsorted(np.cumsum(histogram), percentile_target))
    dark_threshold = min(160, max(128, paper_peak - 95))
    color_threshold = min(220, max(180, paper_peak - 35))

    candidate = (luminance < dark_threshold) | (
        (chroma > 25) & (luminance < color_threshold)
    )
    radius = max(2, resolution // 100)
    core = np.zeros(candidate.shape, dtype=bool)
    center = candidate[radius:-radius, radius:-radius]
    core[radius:-radius, radius:-radius] = (
        center
        & candidate[radius:-radius, :-2 * radius]
        & candidate[radius:-radius, 2 * radius:]
        & candidate[:-2 * radius, radius:-radius]
        & candidate[2 * radius:, radius:-radius]
    )

    # Connect a thick component's eroded core to the artificial outside only
    # through the narrow source band that originally touched that edge.
    floodable = core.copy()
    floodable[: radius + 1] |= candidate[: radius + 1]
    floodable[-radius - 1 :] |= candidate[-radius - 1 :]
    floodable[:, : radius + 1] |= candidate[:, : radius + 1]
    floodable[:, -radius - 1 :] |= candidate[:, -radius - 1 :]
    barrier = Image.fromarray(
        np.where(floodable, 0, 255).astype(np.uint8), "L"
    )
    padded = Image.new("L", (barrier.width + 2, barrier.height + 2), 0)
    padded.paste(barrier, (1, 1))
    ImageDraw.floodfill(padded, (0, 0), 128)
    connected = (np.asarray(padded)[1:-1, 1:-1] == 128) & floodable

    # Restore the eroded table boundary without allowing a thin stroke to
    # carry the flood farther than the erosion radius.
    for _ in range(radius):
        expanded = connected.copy()
        expanded[1:] |= connected[:-1]
        expanded[:-1] |= connected[1:]
        expanded[:, 1:] |= connected[:, :-1]
        expanded[:, :-1] |= connected[:, 1:]
        connected = expanded & candidate

    # Clear exactly two output pixels without allowing that technical rim to
    # carry the flood into content.  This removes the SV600's penultimate
    # black column while sacrificing at most 0.34 mm at 150 dpi.
    rim = 2
    connected[:rim] = True
    connected[-rim:] = True
    connected[:, :rim] = True
    connected[:, -rim:] = True

    connected_pixels = int(connected.sum())
    applied = connected_pixels <= luminance.size * 5 // 8
    if applied:
        rgb[connected] = 255

    return Image.fromarray(rgb, "RGB"), {
        "paper_peak": paper_peak,
        "dark_threshold": dark_threshold,
        "color_threshold": color_threshold,
        "radius": radius,
        "connected_pixels": connected_pixels,
        "connected_percent": connected_pixels * 100.0 / luminance.size,
        "applied": applied,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--resolution", type=int, default=300)
    args = parser.parse_args()

    with Image.open(args.input) as source:
        cleaned, diagnostics = cleanup(source, args.resolution)
    cleaned.save(args.output)
    print(" ".join(f"{key}={value}" for key, value in diagnostics.items()))


if __name__ == "__main__":
    main()
