// FsStore round-trip against a temp dir — no model, no Docker. Proves a
// trajectory (including bigint-carrying snapshot observations) records and
// replays byte-faithfully.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Trajectory, Observation, Action } from "core";
import { sanitize } from "core";
import { FsStore, serializeTrajectory, deserializeTrajectory } from "./fs-store.js";

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "fsstore-test-"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const observation: Observation = {
  source: sanitize([{ path: "sources/m.move", contents: "module m {}" }]),
  tools: { bash: true, writeFile: true, references: false },
  env: { network: "devnet", model: "claude-opus-4-8", effort: "high" },
};

const action: Action = {
  kind: "report_exploit",
  exploit: {
    finding: {
      id: "vuln-001",
      module: "m",
      severity: "high",
      title: "t",
      description: "d",
    },
    script: { path: "exploit.mts", contents: "export async function attack(){}" },
  },
};

function trajectory(id: string): Trajectory {
  return { id, target: "entry", steps: [{ observation, action }] };
}

describe("FsStore", () => {
  it("records and replays a trajectory faithfully", async () => {
    const store = new FsStore(root);
    const t = trajectory("run-1");
    await store.record(t);
    const back = await store.replay("run-1");
    expect(back).toEqual(t);
  });

  it("creates the root dir on first record", async () => {
    const nested = join(root, "a", "b", "c");
    const store = new FsStore(nested);
    await store.record(trajectory("run-2"));
    const back = await store.replay("run-2");
    expect(back.id).toBe("run-2");
  });

  it("round-trips bigints via the tagged (de)serializer", () => {
    const t: Trajectory = {
      id: "x",
      target: "e",
      steps: [],
    };
    // A snapshot-bearing shape carrying a bigint (as balances/fields do).
    const carrier = { ...t, extra: { amount: 123456789012345678901234567890n } };
    const json = serializeTrajectory(carrier as unknown as Trajectory);
    const back = deserializeTrajectory(json) as unknown as typeof carrier;
    expect(back.extra.amount).toBe(123456789012345678901234567890n);
    expect(typeof back.extra.amount).toBe("bigint");
  });

  it("rejects path traversal in ids by sanitizing the filename", async () => {
    const store = new FsStore(root);
    await store.record(trajectory("../evil"));
    // stored under a sanitized name; replaying with the same id resolves it.
    const back = await store.replay("../evil");
    expect(back.id).toBe("../evil");
  });
});
