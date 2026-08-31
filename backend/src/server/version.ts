// Published dataset version + confirmed-tier entry registry, resolved once at
// import time. The registry only ever contains confirmed-tier entries (a
// snapshot-pure check.ts is what makes an entry gradeable on the web surface).
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import {
  buildEntryRegistry,
  discoverConfirmedEntries,
  sourceDigest,
  type DatasetEntry,
} from "suibench/dataset";

// suibench is bundled/inlined into the Astro web build, so this module's own
// import.meta.url is unusable here: the built chunk lands under
// dist/server/chunks/, one level deeper than the source tree, and a
// walk-up calibrated for the source path silently mis-resolves in the
// build. Instead, resolve "suibench/dataset" through Node's own module
// resolution (a pnpm symlink to the real package in dev, and a real
// dependency in a deployed build) and derive both directories from that.
const require = createRequire(import.meta.url);
// suibench/dataset resolves to <suibench>/dist/dataset/index.js; the actual
// data files live in the sibling <suibench>/dataset directory.
const DATASET_DIR = resolve(dirname(require.resolve("suibench/dataset")), "../../dataset");

const entries: DatasetEntry[] = discoverConfirmedEntries(DATASET_DIR);
const reg = buildEntryRegistry(entries);

// A content digest over the same per-entry sourceDigests the manifest ships
// (each hashing that entry's exported loadSource bytes: Move.toml + sources/).
// This is a fingerprint of exactly the challenge sources served/graded here —
// no git, no env var, so it can't drift from the bytes a submitter downloads.
export const PUBLISHED_VERSION: string = createHash("sha256")
  .update(entries.map((e) => `${e.id}:${sourceDigest(e)}`).sort().join("\n"))
  .digest("hex");

export function registry(): Map<string, DatasetEntry> {
  return reg;
}

export interface ManifestEntrySummary {
  id: string;
  sourceDigest: string;
}

export interface DatasetManifest {
  datasetVersion: string;
  entries: ManifestEntrySummary[];
}

export function manifest(): DatasetManifest {
  return {
    datasetVersion: PUBLISHED_VERSION,
    entries: entries.map((e) => ({ id: e.id, sourceDigest: sourceDigest(e) })),
  };
}
