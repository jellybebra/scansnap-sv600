"""Trace the original ScanSnap Home image worker without modifying PFU binaries.

The script attaches to every PfuSshImgProc.exe process, enables the diagnostic
bit mask already implemented by PfuSsImgCtl.dll, records the ScDoImgProc input
structure, and logs calls into the image-processing DLLs.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import threading
import time

import frida


AGENT_SOURCE = r"""
const attached = new Set();

function sendError(where, error) {
  send({event: "error", where: where, message: String(error), stack: error.stack || ""});
}

function readStack(context, byteCount) {
  try {
    return context.sp.add(Process.pointerSize).readByteArray(byteCount);
  } catch (error) {
    sendError("readStack", error);
    return null;
  }
}

function readMemory(address, byteCount) {
  try {
    if (address.isNull()) return null;
    return address.readByteArray(byteCount);
  } catch (error) {
    sendError("readMemory:" + address, error);
    return null;
  }
}

function pointerLayout(exportName) {
  if (exportName === "P2iDigGetPos") {
    return [{index: 0, size: 0x34}, {index: 1, size: 0x20}];
  }
  if (exportName === "P2iDigGetPrm" || exportName === "P2iDigCrop") {
    return [
      {index: 0, size: 0x34},
      {index: 1, size: 0x34},
      {index: 2, size: 0x20},
    ];
  }
  if (exportName.includes("LoadBookParameter")) {
    return [{index: 0, size: 0xd0}];
  }
  if (exportName.includes("AutoBBLINEModelExtraction")) {
    return [
      {index: 6, size: 0x48},
      {index: 7, size: 0x494af8},
      {index: 8, size: 0xd0},
    ];
  }
  if (exportName.includes("ContentModelCorrection")) {
    return [
      {index: 6, size: 0x494af8},
      {index: 8, size: 0x30},
      {index: 9, size: 0xd0},
    ];
  }
  return [];
}

function hookExport(module, exportName) {
  const key = module.name.toLowerCase() + "!" + exportName;
  if (attached.has(key)) return;
  let address;
  try {
    address = module.getExportByName(exportName);
  } catch (_) {
    return;
  }
  attached.add(key);
  Interceptor.attach(address, {
    onEnter(args) {
      this.started = Date.now();
      this.pointerArgs = [];
      send({
        event: "call",
        module: module.name,
        export: exportName,
        address: address.toString(),
        threadId: Process.getCurrentThreadId(),
      }, readStack(this.context, exportName === "ScDoImgProc" ? 0x28c : 0x80));
      const layout = pointerLayout(exportName);
      for (const item of layout) {
        const address = args[item.index];
        this.pointerArgs.push({index: item.index, address: address});
        const data = readMemory(address, item.size);
        if (data !== null) {
          send({
            event: "pointer",
            phase: "enter",
            module: module.name,
            export: exportName,
            argument: item.index,
            address: address.toString(),
            threadId: Process.getCurrentThreadId(),
          }, data);
        }
      }
    },
    onLeave(retval) {
      const layout = pointerLayout(exportName);
      for (let position = 0; position < layout.length; position++) {
        const item = layout[position];
        const saved = this.pointerArgs[position];
        const address = saved.address;
        const data = readMemory(address, item.size);
        if (data !== null) {
          send({
            event: "pointer",
            phase: "leave",
            module: module.name,
            export: exportName,
            argument: saved.index,
            address: address.toString(),
            threadId: Process.getCurrentThreadId(),
          }, data);
        }
      }
      send({
        event: "return",
        module: module.name,
        export: exportName,
        retval: retval.toString(),
        elapsedMs: Date.now() - this.started,
        threadId: Process.getCurrentThreadId(),
      });
    },
  });
}

function hookImageModule(module) {
  const lower = module.name.toLowerCase();
  if (lower === "pfussimgctl.dll") {
    try {
      const levelAddress = module.base.add(0x201084);
      const flagsAddress = module.base.add(0x2018c0);
      const previousLevel = levelAddress.readU32();
      const previousFlags = flagsAddress.readU32();
      levelAddress.writeU32(7);
      flagsAddress.writeU32(0x3f);
      send({
        event: "diagnostics-enabled",
        module: module.name,
        base: module.base.toString(),
        previousLevel: previousLevel,
        previousFlags: previousFlags,
        level: levelAddress.readU32(),
        flags: flagsAddress.readU32(),
      });
    } catch (error) {
      sendError("enable-diagnostics", error);
    }
    hookExport(module, "ScDoImgProc");
    hookExport(module, "SsICGetSsImgCorrection");
    hookExport(module, "SsICGetSingleCropPosAreDir");
    return;
  }

  if (lower === "bookbound.dll") {
    const names = [
      "AutoBBLINEModelExtraction",
      "ContentModelCorrection",
      "LoadBookParameter",
    ];
    for (const item of module.enumerateExports()) {
      if (item.type === "function" && names.some(name => item.name.includes(name))) {
        hookExport(module, item.name);
      }
    }
    return;
  }

  const wanted = [
    /^SsSvcAdjust/i,
    /^_?SsSvcDoUSM/i,
    /^_?SsSvcErase/i,
    /^SsSvcConvRGBToGray/i,
    /^SsSvcRotate/i,
    /^SsSvc.*Skew/i,
    /^P2i.*Crop/i,
    /^P2i.*Get(Pos|DocPos)/i,
    /^P2iDigGetPrm/i,
    /^P2iEraseClrBdr/i,
    /^P2i.*Skew/i,
  ];
  let exports;
  try {
    exports = module.enumerateExports();
  } catch (error) {
    sendError("enumerateExports:" + module.name, error);
    return;
  }
  for (const item of exports) {
    if (item.type !== "function") continue;
    if (wanted.some(pattern => pattern.test(item.name))) {
      hookExport(module, item.name);
    }
  }
}

Process.attachModuleObserver({
  onAdded(module) {
    const lower = module.name.toLowerCase();
    if (lower === "pfussimgctl.dll" ||
        lower === "pfusssvc.dll" ||
        lower === "p2icrppr.dll" ||
        lower === "p2idigcrop.dll" ||
        lower === "bookbound.dll" ||
        lower === "p2ieraseclrbdr.dll" ||
        lower === "p2ibskew.dll") {
      hookImageModule(module);
    }
  },
});

send({event: "agent-ready", architecture: Process.arch, pointerSize: Process.pointerSize});
"""


class TraceWriter:
    def __init__(self, output_dir: pathlib.Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = output_dir / "events.jsonl"
        self.events = self.events_path.open("a", encoding="utf-8", buffering=1)
        self.lock = threading.Lock()
        self.sequence = 0

    def close(self) -> None:
        self.events.close()

    def message_handler(self, pid: int):
        def on_message(message, data) -> None:
            with self.lock:
                self.sequence += 1
                sequence = self.sequence
                record = {
                    "sequence": sequence,
                    "time": time.time(),
                    "pid": pid,
                    "frida": message,
                }
                if data is not None:
                    payload = message.get("payload", {})
                    event = payload.get("event", "payload")
                    export = payload.get("export", "unknown")
                    phase = payload.get("phase", "")
                    argument = payload.get("argument")
                    suffix = "stack"
                    if event == "pointer":
                        safe_export = re.sub(r"[^A-Za-z0-9_.-]+", "_", export).strip("._-")
                        suffix = f"{safe_export[:96]}-arg{argument}-{phase}"
                    payload_path = self.output_dir / f"{sequence:06d}-pid{pid}-{suffix}.bin"
                    payload_path.write_bytes(bytes(data))
                    record["payload"] = payload_path.name
                    record["payloadBytes"] = len(data)
                self.events.write(json.dumps(record, ensure_ascii=False) + "\n")
                self.events.flush()
                payload = message.get("payload", {})
                event = payload.get("event", message.get("type", "message"))
                detail = payload.get("export", payload.get("message", ""))
                print(f"[{sequence:06d}] pid={pid} {event} {detail}", flush=True)

        return on_message


def matching_processes(device) -> dict[int, str]:
    return {
        process.pid: process.name
        for process in device.enumerate_processes()
        if process.name.lower() == "pfusshimgproc.exe"
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=pathlib.Path)
    parser.add_argument("--poll-seconds", type=float, default=0.5)
    args = parser.parse_args()

    writer = TraceWriter(args.output_dir.resolve())
    device = frida.get_local_device()
    sessions: dict[int, tuple[frida.core.Session, frida.core.Script]] = {}
    print(f"Writing trace to {writer.output_dir}", flush=True)
    try:
        while True:
            current = matching_processes(device)
            for pid in sorted(set(sessions) - set(current)):
                sessions.pop(pid, None)
                print(f"Detached from exited pid={pid}", flush=True)
            for pid, name in sorted(current.items()):
                if pid in sessions:
                    continue
                try:
                    session = device.attach(pid)
                    script = session.create_script(AGENT_SOURCE)
                    script.on("message", writer.message_handler(pid))
                    script.load()
                    sessions[pid] = (session, script)
                    print(f"Attached to {name} pid={pid}", flush=True)
                except frida.ProcessNotFoundError:
                    continue
                except Exception as error:
                    print(f"Unable to attach pid={pid}: {error}", file=sys.stderr, flush=True)
            time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        return 0
    finally:
        for session, _script in sessions.values():
            try:
                session.detach()
            except Exception:
                pass
        writer.close()


if __name__ == "__main__":
    raise SystemExit(main())
