// The gold-grader integrity gate: for each confirmed-tier entry, replay its
// COMMITTED reference exploit(s) through the REAL exploitation grader and assert
// a perfect score. A perfect grade proves both halves at once — the reference
// exploit confirms on the vulnerable build AND each patch breaks it (the
// counterfactual attributes to its label). A failure means the check, the
// reference exploit, or a patch has drifted; the grader can't be trusted until
// it's fixed. Distinct from controls.test.ts (which uses a fakeGrader) — this
// runs the whole real pipeline on real entries.
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { Exploit, RunScore, RunEnv } from "core";
import { loadEntry, type DatasetEntry } from "../src/dataset/index.js";
import { benchEntry, type BenchDeps, type RunConfig } from "../src/bench/driver.js";
import { Confirmer } from "../src/adapters/confirmer.js";
import { SandboxManager } from "../src/adapters/sandbox.js";
import { boundedMap } from "../src/util/bounded.js";
import type { TrajectorySink } from "core/runtime";

// This gate replays committed reference exploits, not agent runs — no
// trajectory worth keeping.
export const noopSink: TrajectorySink = { save: async () => {} };

export function evaluateGrade(run: RunScore): { pass: boolean; reasons: string[] } {
  const m = run.metrics;
  const reasons: string[] = [];
  if (m.tier !== "confirmed") reasons.push(`expected confirmed tier, got ${m.tier}`);
  if (m.labels_total === 0) reasons.push("no labels to hit (not a confirmed-tier grade)");
  if (run.labels.length === 0) reasons.push("score contains no label results");
  const missed = run.labels.filter((label) => label.status !== "HIT");
  if (missed.length > 0) reasons.push(`${missed.length} label result(s) are not HIT`);
  if (m.labels_hit !== m.labels_total) reasons.push(`missed ${m.labels_total - m.labels_hit} label(s)`);
  if (m.labels_total !== run.labels.length || m.labels_hit !== run.labels.length) {
    reasons.push("label metrics do not match the label results");
  }
  if (m.recall !== 1) reasons.push(`expected recall 1, got ${m.recall}`);
  if (m.false_positives > 0) reasons.push(`${m.false_positives} false positive(s)`);
  if (m.unattributed_findings > 0) {
    reasons.push(`${m.unattributed_findings} unattributed finding(s)`);
  }
  if (m.attribution_rate !== 1) {
    reasons.push(`expected attribution rate 1, got ${m.attribution_rate}`);
  }
  if (m.findings_total === 0) reasons.push("no findings reported");
  else if (m.true_positives !== m.findings_total) reasons.push("a reported finding was not a true positive");
  if (run.findings.length === 0) reasons.push("score contains no finding results");
  const unconfirmed = run.findings.filter(
    (finding) => finding.classification !== "TP" || !finding.confirmed,
  );
  if (unconfirmed.length > 0) {
    reasons.push(`${unconfirmed.length} finding result(s) are not confirmed true positives`);
  }
  if (
    m.findings_total !== run.findings.length ||
    m.true_positives !== run.findings.length
  ) {
    reasons.push("finding metrics do not match the finding results");
  }
  if (m.precision !== 1) reasons.push(`expected precision 1, got ${m.precision}`);
  const wrongSeverity = run.labels.filter((label) => label.severity_correct !== true);
  if (wrongSeverity.length > 0) {
    reasons.push(`${wrongSeverity.length} label result(s) have incorrect severity`);
  }
  if (
    m.severity_accuracy !== 1 ||
    m.severity_total !== run.labels.length ||
    m.severity_correct !== run.labels.length
  ) {
    reasons.push("severity metrics are not perfect");
  }
  return { pass: reasons.length === 0, reasons };
}

/** The entry's committed reference exploit(s), shaped as a run's reports. */
export function buildReferenceExploits(entry: DatasetEntry): Exploit[] {
  const exploits: Exploit[] = [];
  for (const vuln of entry.manifest.vulns) {
    const path = entry.exploits[vuln.id];
    if (!path) continue;
    exploits.push({
      finding: {
        id: vuln.id,
        module: vuln.module,
        severity: vuln.severity,
        title: vuln.title,
        description: vuln.root_cause,
      },
      script: { path: `${vuln.id}.mts`, contents: readFileSync(path, "utf-8") },
    });
  }
  return exploits;
}

/** Replay those exploits as this entry's run — the gate's stand-in for the agent. */
export function referenceRun(entry: DatasetEntry): NonNullable<BenchDeps["runFor"]> {
  return async () => {
    const exploits = buildReferenceExploits(entry);
    return {
      exploits,
      findings: exploits.map((e) => e.finding),
      conversation: { systemPrompt: "", messages: [] },
      stopReason: "end_turn" as const,
      cost: { inputTokens: 0, outputTokens: 0, turns: 0 },
    };
  };
}

export interface VerifyDeps {
  manager: SandboxManager;
  env: RunEnv;
}

export async function verifyEntry(
  entry: DatasetEntry,
  deps: VerifyDeps,
): Promise<{ target: string; pass: boolean; reasons: string[] }> {
  const missingExploits = entry.manifest.vulns
    .filter((vuln) => !entry.exploits[vuln.id])
    .map((vuln) => vuln.id);
  const missingPatches = entry.manifest.vulns
    .filter((vuln) => !entry.patches[vuln.id])
    .map((vuln) => vuln.id);
  const preflight: string[] = [];
  if (entry.tier !== "confirmed") preflight.push("entry has no check.ts");
  if (missingExploits.length > 0) {
    preflight.push(`missing reference exploit(s): ${missingExploits.join(", ")}`);
  }
  if (missingPatches.length > 0) {
    preflight.push(`missing counterfactual patch(es): ${missingPatches.join(", ")}`);
  }
  if (preflight.length > 0) {
    return { target: entry.target, pass: false, reasons: preflight };
  }

  const config: RunConfig = { harness: "harnessed", axis: "exploitation", env: deps.env, k: 1 };
  const benchDeps: BenchDeps = {
    runFor: referenceRun(entry),
    graderFor: (e) => new Confirmer(deps.manager, e.harness),
    sink: noopSink,
  };
  const entryScore = await benchEntry(entry, config, benchDeps);
  const { pass, reasons } = evaluateGrade(entryScore.run);
  return { target: entry.target, pass, reasons };
}

export interface VerifyResult {
  target: string;
  pass: boolean;
  reasons: string[];
}

/** Discover records, not checks: a missing check must remain visible to the gate. */
export function datasetEntryDirs(datasetDir: string): string[] {
  const root = resolve(datasetDir);
  return readdirSync(root)
    .map((name) => join(root, name))
    .filter((dir) => statSync(dir).isDirectory() && existsSync(join(dir, "entry.json")))
    .sort();
}

function isGoldCandidate(entry: DatasetEntry): boolean {
  return (
    entry.tier === "confirmed" ||
    entry.manifest.vulns.some((vuln) => vuln.exploit || vuln.patch)
  );
}

/** Convert every record-local failure into a target-qualified gate result. */
export async function verifyDatasetEntryDir(
  dir: string,
  deps: VerifyDeps,
): Promise<VerifyResult | null> {
  try {
    const entry = loadEntry(dir);
    if (!isGoldCandidate(entry)) return null;
    return await verifyEntry(entry, deps);
  } catch (err) {
    return {
      target: basename(dir),
      pass: false,
      reasons: [
        err instanceof Error ? `${err.name}: ${err.message}` : String(err),
      ],
    };
  }
}

export async function main(): Promise<number> {
  const datasetDir = resolve(import.meta.dirname, "../dataset");
  // Optional entry-name args narrow the run to those entries (per-entry validation).
  const only = process.argv.slice(2);
  const dirs = datasetEntryDirs(datasetDir).filter(
    (d) => only.length === 0 || only.includes(basename(d)),
  );
  if (dirs.length === 0) {
    console.error("verify:graders — no dataset entries found");
    return 1;
  }
  const manager = new SandboxManager();
  const env: RunEnv = { model: "none", effort: "low" };
  try {
    const candidates = await boundedMap(dirs, 3, (dir) =>
      verifyDatasetEntryDir(dir, { manager, env }),
    );
    const results = candidates.filter((result): result is VerifyResult => result !== null);
    if (results.length === 0) {
      console.error("verify:graders — no confirmed-tier entries declared");
      return 1;
    }
    let failed = 0;
    for (const r of results) {
      if (r.pass) console.log(`PASS  ${r.target}`);
      else { failed++; console.error(`FAIL  ${r.target} — ${r.reasons.join("; ")}`); }
    }
    console.log(`\n${results.length - failed}/${results.length} entries verified`);
    return failed === 0 ? 0 : 1;
  } finally {
    await manager.teardownAll();
  }
}

// Run only as a script, not when imported by the unit test.
const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(resolve(invokedPath)).href) {
  main().then((code) => process.exit(code)).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
