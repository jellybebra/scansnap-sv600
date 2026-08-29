#!/usr/bin/env python3
"""Dump the live SV600 optical-correction tables from the Windows minidriver.

The context address is reported by ``trace_sv600_minidriver.py``.  This tool
only reads the already initialized driver process and writes the six arrays
consumed by FUN_1c3ac9c0/FUN_1c3acf20 for clean-room comparison.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import threading

import frida


AGENT = r"""
const context = ptr(CONTEXT_ADDRESS);
const mapLines = context.add(0x2cd7a0).readS32();
const fields = {
  context: context.toString(),
  model: context.add(0x2ca2f8).readS32(),
  correctionMode: context.add(0x2760).readS16(),
  opticalMode: context.add(0x2782).readS16(),
  workerMode: context.add(0x2784).readS16(),
  mapLines: mapLines,
  sourceLine0: context.add(0x2cd830).readS32(),
  sourceLine1: context.add(0x2cd838).readS32(),
  horizontalMagnificationPercent: context.add(0x2cd7d8).readDouble(),
  secondaryMagnificationPercent: context.add(0x2cd7e0).readDouble(),
};

const arrays = [
  ["horizontal-r", 0x2cd7a8],
  ["horizontal-g", 0x2cd7b0],
  ["horizontal-b", 0x2cd7b8],
  ["vertical-r", 0x2cd7c0],
  ["vertical-g", 0x2cd7c8],
  ["vertical-b", 0x2cd7d0],
];

send({event: "fields", fields: fields});
const windows = [
  ["pipeline", 0x2cd600, 0x400],
  ["scan-descriptors", 0x2cdd80, 0x700],
  ["wia-transfer", 0x2ce600, 0x300],
];
for (const entry of windows) {
  send({event: "window", name: entry[0], offset: entry[1], bytes: entry[2]},
       context.add(entry[1]).readByteArray(entry[2]));
}
for (const entry of arrays) {
  const pointer = context.add(entry[1]).readPointer();
  send({
    event: "array",
    name: entry[0],
    pointer: pointer.toString(),
    elements: mapLines,
  }, pointer.isNull() ? null : pointer.readByteArray(mapLines * 4));
}
send({event: "done"});
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--process", type=int, required=True)
    parser.add_argument("--context", required=True)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    completed = threading.Event()
    metadata: dict[str, object] = {}

    def handler(message, data) -> None:
        if message.get("type") != "send":
            raise RuntimeError(json.dumps(message, ensure_ascii=False))
        payload = message["payload"]
        event = payload["event"]
        if event == "fields":
            metadata.update(payload["fields"])
        elif event == "window":
            name = payload["name"]
            filename = f"context-{name}.bin"
            if data is not None:
                (args.output / filename).write_bytes(bytes(data))
            metadata.setdefault("windows", {})[name] = {
                "offset": payload["offset"],
                "bytes": payload["bytes"],
                "file": filename if data is not None else None,
            }
        elif event == "array":
            name = payload["name"]
            record = {
                "pointer": payload["pointer"],
                "elements": payload["elements"],
            }
            if data is not None:
                record["file"] = f"{name}.bin"
                (args.output / f"{name}.bin").write_bytes(bytes(data))
            else:
                record["file"] = None
            metadata.setdefault("arrays", {})[name] = record
        elif event == "done":
            completed.set()

    session = frida.attach(args.process)
    source = AGENT.replace("CONTEXT_ADDRESS", json.dumps(args.context))
    script = session.create_script(source)
    script.on("message", handler)
    script.load()
    if not completed.wait(10):
        raise TimeoutError("the minidriver did not return its correction tables")
    script.unload()
    session.detach()
    (args.output / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
