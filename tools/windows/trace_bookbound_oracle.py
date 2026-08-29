"""Launch the 32-bit bookbound research oracle and trace internal mesh calls."""

from __future__ import annotations

import argparse
import json
import pathlib
import threading
import time

import frida


AGENT_SOURCE = r"""
let dumpedPageMesh = false;
let lineDetectorCall = 0;
let dumpedLineDetectorGlobals = false;
const reportedConfiguration = {};
const pendingDoubleConfiguration = {};

const targets = [
  {name: "GroupLines", offset: 0x1b510, objectBytes: 0, stackBytes: 0x40},
  {name: "GroupLines2", offset: 0x1d1a0, objectBytes: 0, stackBytes: 0x40},
  {name: "InterpolateLine", offset: 0x20f10, objectBytes: 0, stackBytes: 0x40},
  {name: "ContentMesh", offset: 0x311c0, objectBytes: 0x100, stackBytes: 0x80},
  {name: "MeshTransform", offset: 0x30bf0, objectBytes: 0x100, stackBytes: 0x80},
  {name: "TransformPrepare", offset: 0x2f810, objectBytes: 0x100, stackBytes: 0x100},
  {name: "PageTransform", offset: 0x288e0, objectBytes: 0, stackBytes: 0x100},
  {name: "PageTransformSingle", offset: 0x27ac0, objectBytes: 0x100, stackBytes: 0x100},
];

function read(address, bytes) {
  try {
    if (address.isNull()) return null;
    return address.readByteArray(bytes);
  } catch (error) {
    send({event: "error", message: String(error), address: address.toString()});
    return null;
  }
}

function emitPointer(name, phase, kind, address, bytes) {
  const data = read(address, bytes);
  if (data !== null) {
    send({
      event: "pointer",
      name: name,
      phase: phase,
      kind: kind,
      address: address.toString(),
      bytes: bytes,
      threadId: Process.getCurrentThreadId(),
    }, data);
  }
}

Process.attachModuleObserver({
  onAdded(module) {
    if (module.name.toLowerCase() !== "bookbound.dll") return;
    send({event: "module", name: module.name, base: module.base.toString()});

    function readConfigurationString(value) {
      try {
        return value.isNull() ? "" : value.readCString();
      } catch (error) {
        return "<unreadable:" + value.toString() + ">";
      }
    }

    function reportConfiguration(kind, section, key, value) {
      const identity = kind + "\u0000" + section + "\u0000" + key;
      if (reportedConfiguration[identity] === value) return;
      reportedConfiguration[identity] = value;
      send({
        event: "configuration",
        kind: kind,
        section: section,
        key: key,
        value: value,
      });
    }

    Interceptor.attach(module.base.add(0x8140), {
      onEnter(args) {
        this.section = readConfigurationString(args[0]);
        this.key = readConfigurationString(args[1]);
      },
      onLeave(retval) {
        reportConfiguration(
          "int", this.section, this.key, retval.toInt32()
        );
      },
    });

    Interceptor.attach(module.base.add(0x82f0), {
      onEnter(args) {
        this.section = readConfigurationString(args[0]);
        this.key = readConfigurationString(args[1]);
        this.configurationThreadId = Process.getCurrentThreadId();
        pendingDoubleConfiguration[this.configurationThreadId] = {
          section: this.section,
          key: this.key,
        };
      },
      onLeave(_retval) {
        delete pendingDoubleConfiguration[this.configurationThreadId];
      },
    });

    /* The x86 ABI returns a double through x87 ST(0), which Frida's ia32
     * CpuContext does not expose.  IniFile::getDoubleValue obtains the map
     * iterator through this helper; the matched node contains the exact
     * double at +0x30, so capture it before the getter loads ST(0). */
    Interceptor.attach(module.base.add(0x46d0), {
      onEnter(args) {
        this.configurationThreadId = Process.getCurrentThreadId();
        this.outputIterator = args[0];
        this.configuration =
          pendingDoubleConfiguration[this.configurationThreadId];
      },
      onLeave(_retval) {
        if (this.configuration === undefined) return;
        try {
          const node = this.outputIterator.add(4).readPointer();
          const value = node.add(0x30).readDouble();
          reportConfiguration(
            "double",
            this.configuration.section,
            this.configuration.key,
            value
          );
        } catch (error) {
          send({
            event: "error",
            name: "DoubleConfigurationMap",
            message: String(error),
          });
        }
      },
    });
    for (const target of targets) {
      const address = module.base.add(target.offset);
      Interceptor.attach(address, {
        onEnter(args) {
          this.object = this.context.ecx;
          send({
            event: "call",
            name: target.name,
            address: address.toString(),
            object: this.object.toString(),
            threadId: Process.getCurrentThreadId(),
          });
          emitPointer(
            target.name,
            "enter",
            "stack",
            this.context.sp.add(Process.pointerSize),
            target.stackBytes
          );
          if (target.objectBytes)
            emitPointer(
              target.name, "enter", "object", this.object, target.objectBytes
            );
          if (target.name === "InterpolateLine") {
            const leftCount = args[3].toInt32();
            const rightCount = args[4].toInt32();
            const sourceWidth = args[5].toInt32();
            send({
              event: "grouped-lines",
              leftCount: leftCount,
              rightCount: rightCount,
              sourceWidth: sourceWidth,
            });
            if (leftCount >= 0 && leftCount <= 330 &&
                rightCount >= 0 && rightCount <= 330 &&
                sourceWidth > 0 && sourceWidth <= 8000) {
              emitPointer(
                target.name, "enter", "group-counts", args[2], 660 * 4
              );
              emitPointer(
                target.name, "enter", "group-x-pointers", args[0], 660 * 4
              );
              emitPointer(
                target.name, "enter", "group-y-pointers", args[1], 660 * 4
              );
              const groups = [
                {base: 0, count: leftCount, page: 0},
                {base: 330, count: rightCount, page: 1},
              ];
              for (const group of groups) {
                for (let line = 0; line < group.count; line++) {
                  const index = group.base + line;
                  const count = args[2].add(index * 4).readS32();
                  if (count < 0 || count > sourceWidth) continue;
                  const x = args[0].add(index * 4).readPointer();
                  const y = args[1].add(index * 4).readPointer();
                  emitPointer(
                    target.name, "enter",
                    "group-" + group.page + "-" + line + "-x",
                    x, count * 4
                  );
                  emitPointer(
                    target.name, "enter",
                    "group-" + group.page + "-" + line + "-y",
                    y, count * 4
                  );
                }
              }
            }
          }
          if (target.name === "PageTransform" && !dumpedPageMesh) {
            dumpedPageMesh = true;
            const sourceWidth = args[0].toInt32();
            const mappedWidth = args[4].toInt32();
            const lineCount = args[11].toInt32();
            send({
              event: "mesh-layout",
              sourceWidth: sourceWidth,
              mappedWidth: mappedWidth,
              lineCount: lineCount,
              centerOffset: args[10].toInt32(),
              splitLine: args[14].toInt32(),
            });
            if (sourceWidth > 0 && sourceWidth <= 8000 &&
                mappedWidth > 0 && mappedWidth <= 8000 &&
                lineCount > 1 && lineCount <= 256) {
              emitPointer(
                target.name, "enter", "column-map", args[3], mappedWidth * 8
              );
              emitPointer(
                target.name, "enter", "row-boundaries", args[8], lineCount * 4
              );
              emitPointer(
                target.name, "enter", "row-pointers", args[9], lineCount * 4
              );
              for (let index = 0; index < lineCount; index++) {
                try {
                  const row = args[9].add(index * Process.pointerSize).readPointer();
                  const xCoordinates = row.readPointer();
                  const yCoordinates = row.add(Process.pointerSize).readPointer();
                  emitPointer(
                    target.name, "enter", "row-" + index + "-object", row, 8
                  );
                  emitPointer(
                    target.name, "enter", "row-" + index + "-x",
                    xCoordinates, sourceWidth * 8
                  );
                  emitPointer(
                    target.name, "enter", "row-" + index + "-y",
                    yCoordinates, sourceWidth * 8
                  );
                } catch (error) {
                  send({
                    event: "error",
                    name: target.name,
                    message: "row " + index + ": " + String(error),
                  });
                }
              }
            }
          }
        },
        onLeave(retval) {
          if (target.objectBytes)
            emitPointer(
              target.name, "leave", "object", this.object, target.objectBytes
            );
          send({
            event: "return",
            name: target.name,
            retval: retval.toString(),
            threadId: Process.getCurrentThreadId(),
          });
        },
      });
    }
    Interceptor.attach(module.base.add(0x631d0), {
      onEnter(args) {
        this.index = lineDetectorCall++;
        this.image = args[0];
        this.width = args[1].toInt32();
        this.height = args[2].toInt32();
        const scaleBits = args[3].toUInt32();
        const scaleBuffer = new ArrayBuffer(4);
        new DataView(scaleBuffer).setUint32(0, scaleBits, true);
        this.scale = new DataView(scaleBuffer).getFloat32(0, true);
        send({
          event: "line-detector",
          phase: "enter",
          index: this.index,
          width: this.width,
          height: this.height,
          scale: this.scale,
          image: this.image.toString(),
        });
        if (!dumpedLineDetectorGlobals) {
          dumpedLineDetectorGlobals = true;
          const offsets = [
            0x16d610, 0x1724c8, 0x1724c4, 0x1724c0,
            0x172430, 0x172418, 0x172410, 0x172338,
            0x172428, 0x1724a8, 0x1724a0, 0x16c2c0,
            0x16d688, 0x16db4c,
          ];
          const values = {};
          for (const offset of offsets) {
            const address = module.base.add(offset);
            values["0x" + offset.toString(16)] = {
              u32: address.readU32(),
              f32: address.readFloat(),
              f64: address.readDouble(),
            };
          }
          send({event: "line-detector-globals", values: values});
        }
        if (this.width > 0 && this.width <= 8000 &&
            this.height > 0 && this.height <= 8000) {
          emitPointer(
            "LineDetector", "enter", "input-" + this.index,
            this.image, this.width * this.height
          );
        }
      },
      onLeave(retval) {
        let count = -1;
        let segments = ptr(0);
        try {
          count = retval.readS32();
          segments = retval.add(4).readPointer();
        } catch (error) {
          send({event: "error", name: "LineDetector", message: String(error)});
        }
        send({
          event: "line-detector",
          phase: "leave",
          index: this.index,
          result: retval.toString(),
          count: count,
          segments: segments.toString(),
        });
        if (count >= 0 && count <= 200000) {
          emitPointer(
            "LineDetector", "leave", "segments-" + this.index,
            segments, count * 20
          );
        }
      },
    });
  },
});

send({event: "agent-ready", architecture: Process.arch});
"""


class Writer:
    def __init__(self, output_dir: pathlib.Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events = (output_dir / "events.jsonl").open(
            "w", encoding="utf-8", buffering=1
        )
        self.sequence = 0
        self.lock = threading.Lock()

    def on_message(self, message, data) -> None:
        with self.lock:
            self.sequence += 1
            payload = message.get("payload", {})
            record = {
                "sequence": self.sequence,
                "time": time.time(),
                "frida": message,
            }
            if data is not None:
                name = payload.get("name", "payload")
                phase = payload.get("phase", "data")
                kind = payload.get("kind", "bin")
                path = self.output_dir / (
                    f"{self.sequence:04d}-{name}-{phase}-{kind}.bin"
                )
                path.write_bytes(bytes(data))
                record["payload"] = path.name
                record["payloadBytes"] = len(data)
            self.events.write(json.dumps(record, ensure_ascii=False) + "\n")
            event = payload.get("event", message.get("type", "message"))
            print(
                f"[{self.sequence:04d}] {event} {payload.get('name', '')}",
                flush=True,
            )

    def close(self) -> None:
        self.events.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=pathlib.Path)
    parser.add_argument("command")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    writer = Writer(args.output_dir.resolve())
    device = frida.get_local_device()
    detached = threading.Event()
    process_id = device.spawn([args.command, *args.arguments], stdio="inherit")
    session = device.attach(process_id)
    session.on("detached", lambda *_args: detached.set())
    script = session.create_script(AGENT_SOURCE)
    script.on("message", writer.on_message)
    script.load()
    device.resume(process_id)
    detached.wait()
    writer.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
