#!/usr/bin/env python3
"""Trace the original SV600 Windows minidriver during one factory scan.

The tracer is read-only: it attaches to the WIA host, records the generic and
device-specific SET WINDOW blocks, and captures the image descriptors passed
to the exact optical-remap kernel in ``SV600u-x64.dll``.  It never patches the
vendor module or changes scanner commands.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import threading
import time

import frida


AGENT = r"""
const hooked = new Set();
const capturePixels = __CAPTURE_PIXELS__;

function safeBytes(pointer, length) {
  try {
    if (pointer.isNull() || length <= 0 || length > 0x10000) return null;
    return pointer.readByteArray(length);
  } catch (_) {
    return null;
  }
}

function safePixelBytes(descriptor) {
  if (!capturePixels) return null;
  try {
    const pixels = descriptor.readPointer();
    const length = descriptor.add(0x1c).readU32();
    if (pixels.isNull() || length <= 0 || length > 0x4000000) return null;
    return pixels.readByteArray(length);
  } catch (_) {
    return null;
  }
}

function emit(event, payload, bytes) {
  send(Object.assign({event: event}, payload || {}), bytes || null);
}

function hookAddress(module, offset, name, callbacks) {
  const key = module.name.toLowerCase() + ":" + offset.toString(16);
  if (hooked.has(key)) return;
  hooked.add(key);
  const address = module.base.add(offset);
  Interceptor.attach(address, callbacks(address));
  emit("hooked", {name: name, address: address.toString()});
}

function imageDescriptor(pointer) {
  const result = {address: pointer.toString()};
  try {
    result.pixels = pointer.readPointer().toString();
    result.width = pointer.add(0x10).readU32();
    result.lines = pointer.add(0x14).readU32();
    result.stride = pointer.add(0x18).readU32();
    result.bytes = pointer.add(0x1c).readU32();
    result.resolutionX = pointer.add(0x20).readU32();
    result.resolutionY = pointer.add(0x24).readU32();
  } catch (error) {
    result.error = String(error);
  }
  return result;
}

function pointerArgs(args, first, last) {
  const result = {};
  for (let index = first; index <= last; index++) {
    try {
      result["arg" + index] = args[index].toString();
    } catch (error) {
      result["arg" + index] = "<unreadable: " + String(error) + ">";
    }
  }
  return result;
}

function hookCorrectionKernel(module, offset, name) {
  hookAddress(module, offset, name, address => ({
    onEnter(args) {
      this.source = args[1];
      this.destination = args[2];
      this.firstLine = args[4].toInt32();
      this.lines = imageDescriptor(this.source).lines;
      emit("correction-kernel-enter", Object.assign({
        name: name,
        address: address.toString(),
        source: imageDescriptor(this.source),
        destination: imageDescriptor(this.destination),
        scale: args[3].toInt32(),
        firstLine: this.firstLine,
        worker: args[5].toInt32(),
        side: args[6].toInt32(),
        trimTop: args[7].toInt32(),
        trimBottom: args[8].toInt32(),
      }, pointerArgs(args, 0, 8)), safeBytes(this.source, 0x80));
      const pixels = safePixelBytes(this.source);
      if (pixels !== null) {
        emit("correction-pixels-before", {
          name: name,
          firstLine: this.firstLine,
          lines: this.lines,
          source: imageDescriptor(this.source),
        }, pixels);
      }
    },
    onLeave(retval) {
      emit("correction-kernel-leave", {
        name: name,
        address: address.toString(),
        retval: retval.toString(),
        source: imageDescriptor(this.source),
        destination: imageDescriptor(this.destination),
      }, safeBytes(this.destination, 0x80));
      const pixels = safePixelBytes(this.destination);
      if (pixels !== null) {
        emit("correction-pixels-after", {
          name: name,
          firstLine: this.firstLine,
          lines: this.lines,
          destination: imageDescriptor(this.destination),
        }, pixels);
      }
    },
  }));
}

function hookMinidriver(module) {
  if (module.name.toLowerCase() !== "sv600u-x64.dll") return;

  // The vendor dispatcher stores the selected correction callback at +0x250.
  hookAddress(module, 0xb89f0, "correction-dispatch", address => ({
    onEnter(args) {
      this.driverContext = args[0];
      emit("correction-dispatch-enter", {
        address: address.toString(),
        context: this.driverContext.toString(),
        side: args[1].toInt32(),
        mode: args[2].toInt32(),
      });
    },
    onLeave() {
      let selected = "<unreadable>";
      try {
        selected = this.driverContext.add(0x250).readPointer().toString();
      } catch (_) {}
      emit("correction-dispatch-leave", {
        address: address.toString(),
        context: this.driverContext.toString(),
        selected: selected,
      });
    },
  }));

  // All callbacks assigned by FUN_1c3b89f0.  Capturing every branch avoids
  // assuming which SIMD/manual path a particular Windows installation uses.
  hookCorrectionKernel(module, 0xac460, "manual-default");
  hookCorrectionKernel(module, 0xac9c0, "manual-mode6-fallback");
  hookCorrectionKernel(module, 0xad560, "manual-mode6");
  hookCorrectionKernel(module, 0xada10, "manual-mode7");
  hookCorrectionKernel(module, 0xb21b0, "ipp-default");

  // Converts the WIA 72-byte descriptor into the Comet device descriptor.
  hookAddress(module, 0x8eb30, "send-window", address => ({
    onEnter(args) {
      this.input = args[1];
      this.length = args[2].toUInt32();
      emit("send-window-enter", {
        address: address.toString(),
        length: this.length,
        side: args[3].toInt32(),
        selector: args[4].toUInt32(),
        divisor: args[5].toUInt32(),
      }, safeBytes(this.input, this.length));
    },
    onLeave(retval) {
      emit("send-window-leave", {retval: retval.toString()});
    },
  }));

  // Transport-command builder called by SendSWDData.  Arguments 5 and 6 are
  // the final vendor payload and its exact byte length under the x64 ABI.
  hookAddress(module, 0x82dc0, "command-builder", address => ({
    onEnter(args) {
      const payload = args[4];
      const length = args[5].toUInt32();
      if (length === 0) return;
      emit("command-builder", {
        address: address.toString(),
        command: args[1].toUInt32(),
        length: length,
      }, safeBytes(payload, length));
    },
  }));
}

Process.attachModuleObserver({onAdded: hookMinidriver});
emit("agent-ready", {architecture: Process.arch, pointerSize: Process.pointerSize});
"""


class Writer:
    def __init__(self, output: pathlib.Path) -> None:
        output.mkdir(parents=True, exist_ok=True)
        self.output = output
        self.events = (output / "events.jsonl").open("a", encoding="utf-8", buffering=1)
        self.lock = threading.Lock()
        self.sequence = 0

    def handler(self, message, data) -> None:
        with self.lock:
            self.sequence += 1
            payload_name = None
            if data is not None:
                payload_name = f"{self.sequence:06d}.bin"
                (self.output / payload_name).write_bytes(bytes(data))
            record = {
                "sequence": self.sequence,
                "time": time.time(),
                "message": message,
            }
            if payload_name:
                record["payload"] = payload_name
                record["payloadBytes"] = len(data)
            self.events.write(json.dumps(record, ensure_ascii=False) + "\n")
            if message.get("type") == "send":
                event = message.get("payload", {})
                print(json.dumps(event, ensure_ascii=False), flush=True)
            else:
                print(json.dumps(message, ensure_ascii=False), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--process", default="wiawow64.exe")
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument(
        "--capture-pixels",
        action="store_true",
        help="capture complete RGB buffers before and after every correction chunk",
    )
    args = parser.parse_args()

    writer = Writer(args.output)
    target: str | int = int(args.process) if args.process.isdecimal() else args.process
    session = frida.attach(target)
    agent = AGENT.replace(
        "__CAPTURE_PIXELS__", "true" if args.capture_pixels else "false"
    )
    script = session.create_script(agent)
    script.on("message", writer.handler)
    script.load()
    print(f"attached to {args.process}; waiting {args.seconds}s", flush=True)
    try:
        time.sleep(args.seconds)
    finally:
        script.unload()
        session.detach()
        writer.events.close()


if __name__ == "__main__":
    main()
