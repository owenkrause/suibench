// The dataset loader: read one entry directory into a typed, validated record.
//
// Layout (all extensions unified to `.ts`):
//   entry.json          manifest — labels + provenance (parseManifest)
//   SOURCE.md           provenance / description
//   sources/            the vulnerable Move package (verbatim)
//   harness/setup.ts    optional seed phase (run in-container)
//   harness/victim.ts   optional availability victim op (run in-container)
//   check.ts            snapshot-pure Check per confirmed vuln (imported at grade time)
//   functional.ts       patch-mode: the legit flow still works
//   exploits/<id>.ts    reference exploit, keyed by a manifest id
//   patches/<id>/       per-vuln fix, keyed by a manifest id
//
// Detect-tier entries carry only `entry.json` (+ SOURCE.md/sources); a missing
// `check.ts`/`exploits`/`patches` is not an error — it's the tier boundary.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, basename, relative, join } from "node:path";
import { pathToFileURL } from "node:url";
import type {
  Check,
  GroundTruth,
  VulnLabel,
  MoveFile,
  SanitizedSource,
  Severity,
  Harm,
} from "core";
import { sanitize } from "core";
import { parseManifest, type Manifest, type ManifestVuln } from "./manifest.js";
import type { ConfirmerHarness } from "../adapters/confirmer.js";

/** A loaded, validated dataset entry. `check` is imported lazily (a Check is TS,
 *  loaded via `loadCheck()` only when grading a confirmed-tier entry). */
export interface DatasetEntry {
  /** Neutral, stable corpus id — the correlation key. */
  id: string;
  /** Directory basename — the entry's target name. */
  target: string;
  dir: string;
  manifest: Manifest;
  /** Manifest projected to the kernel scorer's label shape. */
  groundtruth: GroundTruth;
  /** setup/victim phase scripts (both optional), read verbatim for the container. */
  harness: ConfirmerHarness;
  /** Confirmed-tier iff a snapshot-pure `check.ts` is present. */
  tier: "detect" | "confirmed";
  /** Absolute path to `check.ts`, or null for detect-tier. */
  checkPath: string | null;
  /** vuln id -> absolute path to its reference exploit (`exploits/<id>.ts`). */
  exploits: Record<string, string>;
  /** vuln id -> absolute path to its patch dir (`patches/<id>/`). */
  patches: Record<string, string>;
  /** Absolute path to `functional.ts` (patch mode), or null. */
  functionalPath: string | null;
}

function manifestToGroundTruth(target: string, m: Manifest): GroundTruth {
  const vulns: VulnLabel[] = m.vulns.map((v: ManifestVuln) => {
    const label: VulnLabel = {
      id: v.id,
      module: v.module,
      title: v.title,
      severity: v.severity as Severity,
      root_cause: v.root_cause,
    };
    if (v.harm) label.harm = v.harm as Harm;
    return label;
  });
  return { target, vulns };
}

/** Read a phase script verbatim into an in-container `MoveFile`. */
function readScript(path: string, containerName: string): MoveFile {
  return { path: containerName, contents: readFileSync(path, "utf-8") };
}

/** id -> path for every immediate child of `dir` matching `childOf(name) -> id`. */
function keyedChildren(
  dir: string,
  pick: (name: string) => { id: string; isDir: boolean } | null,
): Record<string, string> {
  if (!existsSync(dir)) return {};
  const out: Record<string, string> = {};
  for (const name of readdirSync(dir)) {
    const hit = pick(name);
    if (!hit) continue;
    const full = resolve(dir, name);
    if (statSync(full).isDirectory() !== hit.isDir) continue;
    out[hit.id] = full;
  }
  return out;
}

/**
 * Load + validate one entry directory. Throws on any structural violation:
 * manifest shape (parseManifest), and — the loader's own contract — every
 * `exploits/<id>.ts` and `patches/<id>/` must map to a real manifest id.
 */
export function loadEntry(entryDir: string): DatasetEntry {
  const dir = resolve(entryDir);
  const target = basename(dir);

  const manifestPath = resolve(dir, "entry.json");
  if (!existsSync(manifestPath))
    throw new Error(`${target}: missing entry.json`);
  const manifest = parseManifest(
    readFileSync(manifestPath, "utf-8"),
    `${target}/entry.json`,
  );

  const ids = new Set(manifest.vulns.map((v) => v.id));

  const harnessDir = resolve(dir, "harness");
  const harness: ConfirmerHarness = {};
  const setupPath = resolve(harnessDir, "setup.ts");
  if (existsSync(setupPath)) harness.setup = readScript(setupPath, "setup.mts");
  const victimPath = resolve(harnessDir, "victim.ts");
  if (existsSync(victimPath))
    harness.victim = readScript(victimPath, "victim.mts");

  const checkPathCandidate = resolve(dir, "check.ts");
  const checkPath = existsSync(checkPathCandidate) ? checkPathCandidate : null;

  const functionalCandidate = resolve(dir, "functional.ts");
  const functionalPath = existsSync(functionalCandidate)
    ? functionalCandidate
    : null;

  const exploits = keyedChildren(resolve(dir, "exploits"), (name) =>
    name.endsWith(".ts") ? { id: name.slice(0, -3), isDir: false } : null,
  );
  const patches = keyedChildren(resolve(dir, "patches"), (name) => ({
    id: name,
    isDir: true,
  }));

  validateMapping(target, ids, "exploits", exploits);
  validateMapping(target, ids, "patches", patches);

  const tier = checkPath ? "confirmed" : "detect";

  return {
    id: manifest.id,
    target,
    dir,
    manifest,
    groundtruth: manifestToGroundTruth(target, manifest),
    harness,
    tier,
    checkPath,
    exploits,
    patches,
    functionalPath,
  };
}

function validateMapping(
  target: string,
  ids: Set<string>,
  kind: string,
  mapping: Record<string, string>,
): void {
  for (const id of Object.keys(mapping)) {
    if (!ids.has(id))
      throw new Error(
        `${target}/${kind}: "${id}" maps to no manifest vuln id`,
      );
  }
}

/** Recursively collect files under `dir`, each carrying its path RELATIVE to
 *  `root` (so a mount reads `sources/x.move`, `Move.toml`). */
function collectFiles(root: string, dir: string, out: MoveFile[]): void {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) collectFiles(root, full, out);
    else out.push({ path: relative(root, full), contents: readFileSync(full, "utf-8") });
  }
}

/**
 * The decontaminated, model-facing mount for an entry: ONLY the Move package
 * (`Move.toml` + `sources/`). This is the least-privilege boundary — the
 * groundtruth (`entry.json`), the `check.ts`, the reference `exploits/`, and the
 * `patches/` NEVER enter here, so nothing the sandbox/policy can reach carries
 * the answer. Minting a `SanitizedSource` is the only way these files become a
 * `Mount` (`Sandbox`/`Grader` accept nothing else).
 */
export function loadSource(entry: DatasetEntry): SanitizedSource {
  const files: MoveFile[] = [];
  const toml = resolve(entry.dir, "Move.toml");
  if (existsSync(toml))
    files.push({ path: "Move.toml", contents: readFileSync(toml, "utf-8") });
  collectFiles(entry.dir, resolve(entry.dir, "sources"), files);
  return sanitize(files);
}

/** A label's patch as overlay files (in-package paths). Empty if the entry ships
 *  no `patches/<id>/` for that label (detect-tier / unpatched). A patch dir
 *  mirrors the package layout but may drop the `sources/` segment (a bare
 *  `*.move`); re-root it so it overlays the mount's `sources/`. */
export function loadPatchFiles(entry: DatasetEntry, labelId: string): MoveFile[] {
  const patchDir = entry.patches[labelId];
  if (!patchDir) return [];
  const files: MoveFile[] = [];
  collectFiles(patchDir, patchDir, files);
  return files.map((f) => ({
    path:
      f.path.startsWith("sources/") || f.path === "Move.toml"
        ? f.path
        : f.path.endsWith(".move")
          ? `sources/${f.path}`
          : f.path,
    contents: f.contents,
  }));
}

/** Dynamically import an entry's snapshot-pure `Check`. The module must default-
 *  or named-export `check`. Confirmed-tier only. Imported via a `file://` URL
 *  (not the bare path) so any special character in the entry dir path (e.g. a
 *  `#`) isn't mis-parsed by the module loader. */
export async function loadCheck(entry: DatasetEntry): Promise<Check> {
  if (!entry.checkPath)
    throw new Error(`${entry.target}: no check.ts (detect-tier entry)`);
  const mod = (await import(pathToFileURL(entry.checkPath).href)) as {
    check?: Check;
    default?: Check;
  };
  const check = mod.check ?? mod.default;
  if (typeof check !== "function")
    throw new Error(`${entry.target}/check.ts: must export \`check\``);
  return check;
}
