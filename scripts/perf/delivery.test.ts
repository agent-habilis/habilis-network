import { expect, test } from "bun:test";
import { missingDeliveries, payloadFor, payloadId } from "./delivery.ts";

const line = (kind: string, sender: string, id: string, to?: string[]) => ({
  sender,
  kind,
  receivers: to?.length ?? 0,
  bytes: 200,
  seq: Number(id),
  ts: 0,
  payload_id: id,
  ...(to === undefined ? {} : { to }),
});

test("a payload carries its id, is exactly 200 bytes, and the id reads back", () => {
  const payload = payloadFor("17");
  expect(payload.length).toBe(200);
  expect(payloadId(payload)).toBe("17");
  expect(payloadId("x".repeat(200))).toBeNull(); // the old payload has no id
});

test("a broadcast must reach every other node and a msg its addressee", () => {
  const oracle = [line("broadcast", "a", "1", ["b", "c"]), line("msg", "b", "2", ["c"])];
  const received = new Map([
    ["a", new Set<string>()],
    ["b", new Set(["1"])],
    ["c", new Set(["1", "2"])],
  ]);
  expect(missingDeliveries(oracle, received)).toEqual([]);
});

test("a node that is down misses what was counted for it", () => {
  const oracle = [line("broadcast", "a", "1", ["b", "c"]), line("msg", "b", "2", ["c"])];
  const received = new Map([
    ["a", new Set<string>()],
    ["b", new Set(["1"])],
    ["c", new Set<string>()], // down: it got neither
  ]);
  expect(missingDeliveries(oracle, received)).toEqual(["c missed broadcast 1 from a", "c missed msg 2 from b"]);
});

test("task lines are not checked here: the task exchanges have their own drain", () => {
  const oracle = [line("task_brief", "a", "3", ["b"])];
  expect(missingDeliveries(oracle, new Map([["b", new Set<string>()]]))).toEqual([]);
});
