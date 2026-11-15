import { readFileSync } from "node:fs";
import { freemem, platform } from "node:os";

// Memory that a new process can use, in bytes. os.freemem() is only the free pages, which is far too low on macOS.
export function availableBytes(): number {
  if (platform() === "linux") {
    const kb = readFileSync("/proc/meminfo", "utf8").match(/MemAvailable:\s+(\d+) kB/)?.[1];
    return Number(kb ?? 0) * 1024;
  }
  const text = Bun.spawnSync(["vm_stat"]).stdout.toString();
  const pageSize = Number(text.match(/page size of (\d+) bytes/)?.[1] ?? 16384);
  const pages = (name: string) => Number(text.match(new RegExp(`Pages ${name}:\\s+(\\d+)`))?.[1] ?? 0);
  return (pages("free") + pages("inactive") + pages("speculative")) * pageSize || freemem();
}
