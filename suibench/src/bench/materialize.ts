// I/O boundary between the pure perturbation engine and the dataset entry
// format: reads an entry dir into EntryFiles, derives a deterministic twin
// seed, and writes a TwinResult back out as a loadEntry-able entry dir. Lives
// in bench/ (not perturbation/) because it imports parseManifest as a VALUE
// from ../dataset — perturbation/'s self-containment invariant (version.ts,
// version.test.ts) forbids that.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync, mkdirSync, statSync, existsSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import type { EntryFiles, TwinResult } from "../perturbation/types.js";
import { parseManifest } from "../dataset/manifest.js";

export function twinSeed(target: string, index: number): string {
  return createHash("sha256").update(`${target}#${index}`).digest("hex");
}

const INCLUDE = (rel: string) =>
  rel === "Move.toml" || rel === "entry.json" || rel === "check.ts" || rel === "functional.ts" ||
  rel.startsWith("sources/") || rel.startsWith("exploits/") || rel.startsWith("patches/") ||
  rel === "harness/setup.ts" || rel === "harness/victim.ts";

function walk(root: string, dir: string, out: Record<string, string>): void {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(root, full, out);
    else { const rel = relative(root, full); if (INCLUDE(rel)) out[rel] = readFileSync(full, "utf-8"); }
  }
}

export function readEntryFiles(entryDir: string): EntryFiles {
  const files: Record<string, string> = {};
  walk(entryDir, entryDir, files);
  if (!files["entry.json"]) throw new Error(`perturbation: ${entryDir} has no entry.json`);
  return { files, entry: parseManifest(files["entry.json"], `${entryDir}/entry.json`) };
}

export function writeTwinDir(dir: string, twin: TwinResult): void {
  for (const f of twin.files) {
    const dest = join(dir, f.relPath);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.content);
  }
}
