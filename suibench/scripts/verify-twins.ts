// Offline admissibility gate: for each confirmed-tier entry and each derived seed,
// regenerate the twin, replay the entry's reference exploit through the REAL grader
// on BOTH original and twin, and assert identical PERFECT attribution — proving the
// twin grades the same as its original (design §4.4). Also: rename-closure.
import { resolve, join } from "node:path";
import { existsSync, statSync, readdirSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import type { RunScore, RunEnv } from "core";
import { loadEntry, type DatasetEntry } from "../src/dataset/index.js";
import { benchEntry, type BenchDeps, type RunConfig } from "../src/bench/driver.js";
import { scriptedPolicyFactory } from "../src/bench/policies.js";
import { Confirmer } from "../src/adapters/confirmer.js";
import { SandboxManager } from "../src/adapters/sandbox.js";
import { boundedMap } from "../src/util/bounded.js";
import { readEntryFiles, writeTwinDir, twinSeed } from "../src/bench/materialize.js";
import { generateTwin } from "../src/perturbation/transform.js";
import { buildReferenceActions } from "./verify-graders.js"; // reuse the exact ref-exploit builder

const K = Number(process.env.SUIBENCH_TWINS ?? "3");

// Twins must be materialized IN-TREE, not under the OS tmpdir: a twin's check.ts
// bare-imports "core", and Node resolves bare specifiers by walking node_modules
// UP from the importing file — from an OS tmpdir that never reaches the
// workspace's node_modules, so loadCheck's dynamic import throws. Same hazard
// perturb-driver.ts already handles by dumping under `.suibench/` (gitignored).
const SCRATCH_ROOT = resolve(import.meta.dirname, "../.suibench");

export function evaluateTwinGate(o: RunScore, t: RunScore): { pass: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const both = (pred: (m: RunScore["metrics"]) => boolean, msg: string) => { if (!(pred(o.metrics) && pred(t.metrics))) reasons.push(msg); };
  both((m) => m.labels_total > 0 && m.labels_hit === m.labels_total, "not every label HIT on both sides");
  both((m) => m.findings_total > 0 && m.true_positives === m.findings_total && m.false_positives === 0, "not perfectly confirmed on both sides");
  // Cardinality must be identical: a twin only renames symbols, so its label/finding
  // counts must match the original. A drift here means the twin transform altered the
  // graded shape — exactly what this gate exists to catch.
  if (o.metrics.labels_total !== t.metrics.labels_total || o.metrics.findings_total !== t.metrics.findings_total)
    reasons.push("original and twin have different label/finding counts (twin cardinality drift)");
  if (o.metrics.labels_hit !== t.metrics.labels_hit) reasons.push("original and twin hit different label counts");
  return { pass: reasons.length === 0, reasons };
}

async function scoreEntry(entry: DatasetEntry, manager: SandboxManager, env: RunEnv): Promise<RunScore> {
  const config: RunConfig = { harness: "harnessed", axis: "exploitation", env, k: 1 };
  const deps: BenchDeps = {
    policyFor: scriptedPolicyFactory({ [entry.target]: buildReferenceActions(entry) }),
    graderFor: (e) => new Confirmer(manager, e.harness),
  };
  return (await benchEntry(entry, config, deps)).run;
}

async function verifyEntry(dir: string, manager: SandboxManager, env: RunEnv): Promise<{ target: string; pass: boolean; reasons: string[] }> {
  const entry = loadEntry(dir);
  const original = await scoreEntry(entry, manager, env);
  const files = readEntryFiles(dir);
  const reasons: string[] = [];
  for (let i = 0; i < K; i++) {
    const twin = await generateTwin(files, twinSeed(entry.target, i));
    mkdirSync(SCRATCH_ROOT, { recursive: true });
    const out = mkdtempSync(join(SCRATCH_ROOT, `twin-${entry.target}-${i}-`));
    try {
      writeTwinDir(out, twin);
      const twinScore = await scoreEntry(loadEntry(out), manager, env);
      const g = evaluateTwinGate(original, twinScore);
      if (!g.pass) reasons.push(`seed ${i}: ${g.reasons.join("; ")}`);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }
  return { target: entry.target, pass: reasons.length === 0, reasons };
}

function confirmedTierDirs(datasetDir: string): string[] {
  return readdirSync(datasetDir).map((n) => join(datasetDir, n))
    .filter((d) => statSync(d).isDirectory() && existsSync(join(d, "check.ts")));
}

export async function main(): Promise<number> {
  const dirs = confirmedTierDirs(resolve(import.meta.dirname, "../dataset"));
  if (dirs.length === 0) { console.error("verify:twins — no confirmed-tier entries"); return 1; }
  const manager = new SandboxManager();
  const env: RunEnv = { network: "devnet", model: "none", effort: "low" };
  try {
    const results = await boundedMap(dirs, 3, (d) => verifyEntry(d, manager, env));
    let failed = 0;
    for (const r of results) { if (r.pass) console.log(`PASS  ${r.target}`); else { failed++; console.error(`FAIL  ${r.target} — ${r.reasons.join(" | ")}`); } }
    console.log(`\n${results.length - failed}/${results.length} entries verified (K=${K})`);
    return failed === 0 ? 0 : 1;
  } finally { await manager.teardownAll(); }
}

if (import.meta.url === `file://${process.argv[1]}`) main().then((c) => process.exit(c)).catch((e) => { console.error(e); process.exit(1); });
