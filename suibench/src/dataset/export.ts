// The redistribution-safe artifact: exactly loadSource's files (Move.toml + sources/),
// sorted, plus a content digest over them. Reuse of loadSource IS the decontamination
// guarantee — never tar the raw entry dir.
import { createHash } from "node:crypto";
import type { DatasetEntry } from "./entry.js";
import { loadSource } from "./entry.js";
import type { MoveFile } from "core";

export function exportEntry(entry: DatasetEntry): MoveFile[] {
  return [...loadSource(entry).files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

export function sourceDigest(entry: DatasetEntry): string {
  const h = createHash("sha256");
  for (const f of exportEntry(entry)) h.update(f.path).update("\0").update(f.contents).update("\0");
  return h.digest("hex");
}
