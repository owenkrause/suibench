// `FsStore` — the real `Store`. Persists a run's `Trajectory` to JSON for offline
// deterministic replay (no model, no Docker). Thin fs I/O; the one wrinkle is
// that trajectories carry `bigint`s (balances/fields), so the JSON is bigint-aware.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import type { Store, Trajectory } from "core";

/** Marker wrapping a bigint so JSON round-trips it losslessly. */
const BIGINT_TAG = "$bigint";

function replacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? { [BIGINT_TAG]: value.toString() } : value;
}

function reviver(_key: string, value: unknown): unknown {
  if (
    value &&
    typeof value === "object" &&
    typeof (value as Record<string, unknown>)[BIGINT_TAG] === "string"
  ) {
    return BigInt((value as Record<string, string>)[BIGINT_TAG]);
  }
  return value;
}

export function serializeTrajectory(t: Trajectory): string {
  return JSON.stringify(t, replacer, 2);
}

export function deserializeTrajectory(json: string): Trajectory {
  return JSON.parse(json, reviver) as Trajectory;
}

export class FsStore implements Store {
  constructor(private readonly root: string) {}

  private pathFor(id: string): string {
    // guard against path traversal (ids come from model output).
    const safe = id.replace(/[^A-Za-z0-9._-]/g, "_");
    return join(resolve(this.root), `${safe}.json`);
  }

  async record(t: Trajectory): Promise<void> {
    await mkdir(resolve(this.root), { recursive: true });
    await writeFile(this.pathFor(t.id), serializeTrajectory(t), "utf-8");
  }

  async replay(id: string): Promise<Trajectory> {
    const raw = await readFile(this.pathFor(id), "utf-8");
    return deserializeTrajectory(raw);
  }
}
