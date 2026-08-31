import { execFileSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import type { DatasetEntry } from "./entry.js";
import { loadEntry } from "./entry.js";

/** The published snapshot id: the git tree SHA of the dataset subtree at HEAD.
 *  Changes only when the dataset changes. Throws if not in a git tree. */
export function datasetVersion(repoRoot: string, datasetRelPath: string): string {
  return execFileSync("git", ["-C", repoRoot, "rev-parse", `HEAD:${datasetRelPath}`], { encoding: "utf-8" }).trim();
}

export function buildEntryRegistry(entries: DatasetEntry[]): Map<string, DatasetEntry> {
  const m = new Map<string, DatasetEntry>();
  for (const e of entries) {
    if (m.has(e.id)) throw new Error(`duplicate entry id "${e.id}"`);
    m.set(e.id, e);
  }
  return m;
}

/** Every confirmed-tier entry directly under `datasetDir` — the web-facing
 *  bench surface. Skips `-patched` twins (negative-control siblings, not
 *  independent corpus entries) and any subdir with no `entry.json`. */
export function discoverConfirmedEntries(datasetDir: string): DatasetEntry[] {
  if (!existsSync(datasetDir)) throw new Error(`dataset dir not found: ${datasetDir}`);
  const out: DatasetEntry[] = [];
  for (const name of readdirSync(datasetDir, { withFileTypes: true })) {
    if (!name.isDirectory() || name.name.endsWith("-patched")) continue;
    const dir = resolve(datasetDir, name.name);
    if (!existsSync(resolve(dir, "entry.json"))) continue;
    const entry = loadEntry(dir);
    if (entry.tier === "confirmed") out.push(entry);
  }
  return out;
}
