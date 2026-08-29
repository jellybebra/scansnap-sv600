#!/usr/bin/env python3
"""Reconstruct full SV600 RGB frames from captured minidriver chunks.

``trace_sv600_minidriver.py --capture-pixels`` records overlapping buffers.
The source chunks are placed at their reported ``firstLine``.  For corrected
output the vendor kernel keeps 25 context rows at each interior edge: the
first block contributes its first 200 rows, interior blocks rows 25..224, and
the final block rows 25 through the end.
"""

from __future__ import annotations

import argparse
import json
import pathlib

import numpy as np


def write_ppm(path: pathlib.Path, pixels: np.ndarray) -> None:
    height, width, channels = pixels.shape
    if pixels.dtype != np.uint8 or channels != 3:
        raise ValueError("expected uint8 RGB pixels")
    with path.open("wb") as stream:
        stream.write(f"P6\n{width} {height}\n255\n".encode("ascii"))
        stream.write(pixels.tobytes())


def captured_events(directory: pathlib.Path, event_name: str) -> list[dict]:
    result = []
    for line in (directory / "events.jsonl").read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        message = record.get("message", {})
        payload = message.get("payload", {})
        if message.get("type") == "send" and payload.get("event") == event_name:
            result.append({**payload, "file": directory / record["payload"]})
    return sorted(result, key=lambda item: item["firstLine"])


def pixels(event: dict, descriptor_name: str) -> np.ndarray:
    descriptor = event[descriptor_name]
    width = descriptor["width"]
    lines = descriptor["lines"]
    stride = descriptor["stride"]
    data = np.fromfile(event["file"], dtype=np.uint8)
    if data.size != descriptor["bytes"] or stride < width * 3:
        raise ValueError(f"invalid capture {event['file']}")
    return data.reshape(lines, stride)[:, : width * 3].reshape(lines, width, 3)


def reconstruct_source(events: list[dict]) -> tuple[np.ndarray, int]:
    height = max(event["firstLine"] + event["lines"] for event in events)
    width = events[0]["source"]["width"]
    frame = np.empty((height, width, 3), dtype=np.uint8)
    written = np.zeros(height, dtype=bool)
    mismatch = 0
    for event in events:
        block = pixels(event, "source")
        first = event["firstLine"]
        for row in range(event["lines"]):
            output_row = first + row
            if written[output_row]:
                mismatch += int(np.count_nonzero(frame[output_row] != block[row]))
            else:
                frame[output_row] = block[row]
                written[output_row] = True
    if not np.all(written):
        raise ValueError("source chunks leave gaps")
    return frame, mismatch


def reconstruct_destination(events: list[dict]) -> np.ndarray:
    height = max(event["firstLine"] + event["lines"] for event in events)
    width = events[0]["destination"]["width"]
    frame = np.empty((height, width, 3), dtype=np.uint8)
    written = np.zeros(height, dtype=bool)
    for index, event in enumerate(events):
        block = pixels(event, "destination")
        if index == 0:
            local_first = 0
            local_last = events[index + 1]["firstLine"] - event["firstLine"] + 25
        elif index + 1 == len(events):
            local_first = 25
            local_last = event["lines"]
        else:
            local_first = 25
            local_last = 225
        output_first = event["firstLine"] + local_first
        output_last = event["firstLine"] + local_last
        if np.any(written[output_first:output_last]):
            raise ValueError("destination selections overlap")
        frame[output_first:output_last] = block[local_first:local_last]
        written[output_first:output_last] = True
    if not np.all(written):
        gaps = np.flatnonzero(~written)
        raise ValueError(f"destination chunks leave gaps: {gaps[:20]}")
    return frame


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace_dir", type=pathlib.Path)
    parser.add_argument("output_prefix", type=pathlib.Path)
    args = parser.parse_args()

    before = captured_events(args.trace_dir, "correction-pixels-before")
    after = captured_events(args.trace_dir, "correction-pixels-after")
    if not before or len(before) != len(after):
        raise ValueError(f"incomplete capture: before={len(before)} after={len(after)}")
    source, mismatch = reconstruct_source(before)
    destination = reconstruct_destination(after)
    write_ppm(args.output_prefix.with_suffix(".before.ppm"), source)
    write_ppm(args.output_prefix.with_suffix(".after.ppm"), destination)
    print(
        f"chunks={len(before)} source={source.shape[1]}x{source.shape[0]} "
        f"destination={destination.shape[1]}x{destination.shape[0]} "
        f"source-overlap-channel-mismatches={mismatch}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
