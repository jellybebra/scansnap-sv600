"""Compare PFU's captured LineDetector output with OpenCV's LSD."""

from __future__ import annotations

import argparse
import pathlib
import struct

import cv2
import numpy as np


def endpoint_distance(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    direct = np.linalg.norm(left[:, :2] - right[:2], axis=1) + np.linalg.norm(
        left[:, 2:4] - right[2:4], axis=1
    )
    reversed_distance = np.linalg.norm(
        left[:, :2] - right[2:4], axis=1
    ) + np.linalg.norm(left[:, 2:4] - right[:2], axis=1)
    return np.minimum(direct, reversed_distance) / 2.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("segments", type=pathlib.Path)
    parser.add_argument("width", type=int)
    parser.add_argument("height", type=int)
    parser.add_argument("--log-eps", type=float, default=-1.0)
    parser.add_argument("--reference", type=pathlib.Path)
    args = parser.parse_args()

    image = np.fromfile(args.input, dtype=np.uint8).reshape(args.height, args.width)
    expected = np.fromfile(args.segments, dtype="<f4").reshape(-1, 5)
    detector = cv2.createLineSegmentDetector(
        cv2.LSD_REFINE_ADV,
        0.5,
        0.6,
        2.0,
        22.5,
        args.log_eps,
        0.7,
        1024,
    )
    detected, widths, _precisions, _nfas = detector.detect(image)
    actual = detected.reshape(-1, 4) if detected is not None else np.empty((0, 4))
    print(f"PFU={len(expected)} OpenCV={len(actual)}")
    print("PFU first:")
    print(expected[:10])
    print("OpenCV first:")
    print(np.column_stack((actual[:10], widths.reshape(-1)[:10])))
    if len(actual):
        nearest = []
        for line in expected:
            nearest.append(float(endpoint_distance(actual, line).min()))
        nearest_array = np.asarray(nearest)
        print(
            "PFU -> nearest OpenCV endpoint error: "
            f"median={np.median(nearest_array):.6f} "
            f"p90={np.percentile(nearest_array, 90):.6f} "
            f"max={nearest_array.max():.6f}"
        )
        for threshold in (0.25, 0.5, 1.0, 2.0, 5.0):
            print(
                f"  <= {threshold:.2f}px: "
                f"{np.count_nonzero(nearest_array <= threshold)}/{len(nearest_array)}"
            )
    if args.reference:
        data = args.reference.read_bytes()
        reference_count = struct.unpack_from("<i", data)[0]
        reference = np.frombuffer(data, dtype="<f8", offset=4).reshape(-1, 7)
        if len(reference) != reference_count:
            raise ValueError("reference LSD count does not match its payload")
        nearest = np.asarray(
            [float(endpoint_distance(reference[:, :4], line).min()) for line in expected]
        )
        print(f"Reference LSD={reference_count}")
        print(
            "PFU -> nearest reference endpoint error: "
            f"median={np.median(nearest):.6f} "
            f"p90={np.percentile(nearest, 90):.6f} max={nearest.max():.6f}"
        )
        for threshold in (0.25, 0.5, 1.0, 2.0, 5.0):
            print(
                f"  <= {threshold:.2f}px: "
                f"{np.count_nonzero(nearest <= threshold)}/{len(nearest)}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
