// Generate negative-control twins. For each entry that ships >= 1 gold patch,
// materialize its FULLY-PATCHED, decontaminated build as a sibling
// `<entry>-patched` negative (entry.json `vulns: []`). Assuming the gold patches
// fully fix their bugs, the patched build is a genuinely clean contract that is
// structurally identical to its positive — so it can't be separated from the
// positives by shape, and it measures the model's false-positive rate on
// realistic bug-shaped-but-fixed code.
//
// These twins are DERIVED artifacts: never hand-edit them; regenerate after any
// sources/patch change. `--check` regenerates in memory and asserts the on-disk
// twins are identical (an idempotency guard for CI: a patch edited without
// regenerating fails the check).
//
// Usage:
//   tsx scripts/generate-negatives.ts [entry...]     # write twins (all, or named)
//   tsx scripts/generate-negatives.ts --check [...]  # verify twins are up to date
import {
  readdirSync,
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { resolve, dirname, join, basename } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { loadEntry, loadSource, loadPatchFiles } from "../src/dataset/index.js";
import { CHAL_ID_RE } from "../src/dataset/manifest.js";
import type { MoveFile } from "core";

// 3-way merge of two patched versions of one file over a common base. Both gold
// patches replace the whole .move file, each carrying only its own fix; a
// multi-label entry that patches the SAME file needs the fixes combined, not the
// last one to win. Non-overlapping hunks merge cleanly; a real conflict throws.
function mergeAll(base: string, versions: string[]): string {
  let cur = versions[0];
  const dir = mkdtempSync(join(tmpdir(), "neg-"));
  try {
    const b = join(dir, "base");
    writeFileSync(b, base);
    for (let i = 1; i < versions.length; i++) {
      const o = join(dir, "cur");
      const t = join(dir, "other");
      writeFileSync(o, cur);
      writeFileSync(t, versions[i]);
      try {
        cur = execFileSync("git", ["merge-file", "-p", o, b, t], { encoding: "utf-8" });
      } catch (e: any) {
        if (typeof e.stdout === "string" && e.status > 0)
          throw new Error(`conflicting patches on the same file (status ${e.status})`);
        throw e;
      }
    }
    return cur;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const DATASET = resolve(import.meta.dirname, "../dataset");
const SUFFIX = "-patched";
const MARK = "AUTO-GENERATED negative twin — do not edit; regenerate via scripts/generate-negatives.ts";

// Every id already committed anywhere in the corpus (twins included), so a
// freshly-minted twin id can never collide with a sibling entry's.
const usedIds = new Set<string>();
for (const d of readdirSync(DATASET, { withFileTypes: true })) {
  if (!d.isDirectory()) continue;
  const p = resolve(DATASET, d.name, "entry.json");
  if (!existsSync(p)) continue;
  try {
    const id = JSON.parse(readFileSync(p, "utf-8")).id;
    if (typeof id === "string" && CHAL_ID_RE.test(id)) usedIds.add(id);
  } catch {
    // malformed entry.json elsewhere isn't this script's concern.
  }
}
const mintId = (): string => {
  let s: string;
  do s = "chal_" + randomBytes(4).toString("hex");
  while (usedIds.has(s));
  usedIds.add(s);
  return s;
};

// A twin's id is stable across regenerations: read the one it already has on
// disk (so `--check` doesn't see churn), and only mint a fresh one the first
// time a twin is materialized. Never reuse the un-suffixed sibling's id —
// each `-patched` twin is its own corpus entry and needs its own unique id.
function twinId(name: string): string {
  const p = resolve(DATASET, name + SUFFIX, "entry.json");
  if (existsSync(p)) {
    try {
      const id = JSON.parse(readFileSync(p, "utf-8")).id;
      if (typeof id === "string" && CHAL_ID_RE.test(id)) return id;
    } catch {
      // fall through to mint a new one.
    }
  }
  return mintId();
}

// Strip fix-revealing comments (our gold patches mark the fix with "FIX"), so the
// materialized clean build carries no pointer to what was changed. Benign comments
// are kept, so the twin's comment profile still matches the positives.
function scrub(contents: string): string {
  return contents
    .split("\n")
    .filter((l) => !(l.trim().startsWith("//") && /\bFIX\b/i.test(l)))
    .map((l) => l.replace(/[ \t]*\/\/.*\bFIX\b.*$/i, ""))
    .join("\n");
}

/** The materialized twin as a path->contents map (deterministic). */
function buildTwin(name: string): Record<string, string> | null {
  const entry = loadEntry(resolve(DATASET, name));
  const labels = Object.keys(entry.patches).sort();
  if (labels.length === 0) return null; // no patch => no clean twin to derive

  const base = loadSource(entry).files;
  // patch versions of each source file, keyed by basename, across all labels.
  const patched = new Map<string, string[]>();
  for (const id of labels)
    for (const pf of loadPatchFiles(entry, id)) {
      const key = basename(pf.path);
      (patched.get(key) ?? patched.set(key, []).get(key)!).push(pf.contents);
    }

  const files: Record<string, string> = {};
  for (const f of base as MoveFile[]) {
    const versions = patched.get(basename(f.path));
    let contents = f.contents;
    if (versions && versions.length === 1) contents = versions[0];
    else if (versions) contents = mergeAll(f.contents, versions); // same file, multiple fixes
    files[f.path] = f.path.endsWith(".move") ? scrub(contents) : contents;
  }
  files["entry.json"] = JSON.stringify({ id: twinId(name), version: 1, vulns: [] }, null, 2) + "\n";
  files["SOURCE.md"] =
    `# ${name}${SUFFIX} — negative control\n\n` +
    `<!-- ${MARK} -->\n\n` +
    `The fully-patched build of \`${name}\`: the same contract with every gold ` +
    `patch applied, so it is structurally identical to the positive but has no ` +
    `reachable bug. A negative control (\`vulns: []\`) — any finding a model ` +
    `reports here is a false positive.\n`;
  return files;
}

function writeTwin(name: string, files: Record<string, string>): void {
  const dir = resolve(DATASET, name + SUFFIX);
  rmSync(dir, { recursive: true, force: true });
  for (const [rel, contents] of Object.entries(files)) {
    const p = resolve(dir, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, contents);
  }
}

function readTwin(name: string, files: Record<string, string>): string[] {
  const dir = resolve(DATASET, name + SUFFIX);
  const diffs: string[] = [];
  for (const [rel, want] of Object.entries(files)) {
    const p = resolve(dir, rel);
    if (!existsSync(p)) diffs.push(`missing ${name}${SUFFIX}/${rel}`);
    else if (readFileSync(p, "utf-8") !== want) diffs.push(`stale ${name}${SUFFIX}/${rel}`);
  }
  return diffs;
}

// The twins that already exist on disk ARE the registry — the curated negative
// set. `--check` and a no-arg regenerate operate on exactly those, so removing a
// twin is `rm -rf`, and adding one is `generate <name>` once. Named args
// bootstrap new twins (or refresh specific ones).
const args = process.argv.slice(2);
const check = args.includes("--check");
const named = args.filter((a) => a !== "--check");
const existing = readdirSync(DATASET, { withFileTypes: true })
  .filter((d) => d.isDirectory() && d.name.endsWith(SUFFIX))
  .map((d) => d.name.slice(0, -SUFFIX.length));
const candidates = (named.length ? named : existing.sort()).filter(
  (name) => buildTwin(name) !== null,
);

let stale = 0;
for (const name of candidates) {
  const files = buildTwin(name)!;
  if (check) {
    const diffs = readTwin(name, files);
    if (diffs.length) {
      stale++;
      for (const d of diffs) console.error(`  ${d}`);
    }
  } else {
    writeTwin(name, files);
    console.log(`  wrote ${name}${SUFFIX} (${Object.keys(files).length} files)`);
  }
}

if (check) {
  console.log(stale ? `\n${stale} twin(s) out of date — run without --check` : `\n${candidates.length} twins up to date`);
  process.exit(stale ? 1 : 0);
} else {
  console.log(`\ngenerated ${candidates.length} negative twins`);
}
