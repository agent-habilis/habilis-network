// The delivery proof of the workload: every broadcast and every msg that the runner counts in the oracle must
// reach the nodes that the oracle names. A node that is down, or that lost the payload, fails the run.

export const PAYLOAD_BYTES = 200;

export type OracleLine = {
  sender: string;
  kind: string;
  receivers: number;
  bytes: number;
  seq: number;
  ts: number;
  to?: string[];
  payload_id?: string;
};

// The payload of one send: its id, a colon, and padding up to PAYLOAD_BYTES, so that the receiver can name it.
export function payloadFor(id: string): string {
  return `${id}:`.padEnd(PAYLOAD_BYTES, "x");
}

// The id of a payload, or null for a body that has none.
export function payloadId(body: string): string | null {
  return body.match(/^(\d+):x*$/)?.[1] ?? null;
}

const CHAT_KINDS = new Set(["broadcast", "msg"]);

// What the oracle counted for a node and the node did not receive, one line each, in oracle order.
export function missingDeliveries(oracle: OracleLine[], received: Map<string, Set<string>>): string[] {
  const missing: string[] = [];
  for (const entry of oracle) {
    if (!CHAT_KINDS.has(entry.kind) || entry.payload_id === undefined) continue;
    for (const node of entry.to ?? []) {
      if (!received.get(node)?.has(entry.payload_id)) {
        missing.push(`${node} missed ${entry.kind} ${entry.payload_id} from ${entry.sender}`);
      }
    }
  }
  return missing;
}
